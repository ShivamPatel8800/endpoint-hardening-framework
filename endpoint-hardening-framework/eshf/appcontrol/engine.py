"""Application control: policy model, first-match decision engine, directory
scanning (PE/ELF/Mach-O aware), enforcement-status detection (AppLocker /
fapolicyd / SIP+Gatekeeper), and AppLocker/fapolicyd draft export."""
import base64
import fnmatch
import json
import os
import platform
import re
from dataclasses import dataclass
from xml.sax.saxutils import escape

from ..utils.helpers import IS_WINDOWS, IS_LINUX, IS_MACOS, run_command, sha256_file

if IS_WINDOWS:
    import winreg

VALID_MATCH = {"path", "name", "extension", "hash"}

EXECUTABLE_EXTS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".bat", ".cmd",
    ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
    ".msi", ".mst", ".jar",
}

_MACHO_MAGICS = {
    b"\xcf\xfa\xed\xfe",  # MH_MAGIC_64 little-endian — every native Apple Silicon binary
    b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64 big-endian byte order
    b"\xce\xfa\xed\xfe",  # MH_MAGIC (32-bit) LE
    b"\xfe\xed\xfa\xce",  # MH_MAGIC (32-bit) BE
    b"\xca\xfe\xba\xbe",  # Fat/universal binary (overlaps Java class magic — harmless here)
}


class PolicyError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    action: str          # allow | deny
    match: str           # path | name | extension | hash
    values: list
    description: str = ""


@dataclass
class Decision:
    path: str
    action: str          # allow | deny
    matched_rule: str    # rule id, or "default"
    reason: str = ""


# ------------------------------------------------------------ policy I/O
def validate_policy(data, source="<policy>"):
    if not isinstance(data, dict):
        raise PolicyError(f"{source}: policy must be a JSON object")
    if data.get("default_action") not in ("allow", "deny"):
        raise PolicyError(f"{source}: default_action must be 'allow' or 'deny'")
    for i, r in enumerate(data.get("rules", [])):
        rid = r.get("id", f"rules[{i}]")
        if r.get("action") not in ("allow", "deny"):
            raise PolicyError(f"{source}: {rid}: action must be allow|deny")
        if r.get("match") not in VALID_MATCH:
            raise PolicyError(f"{source}: {rid}: match must be one of {sorted(VALID_MATCH)}")
        if not r.get("values"):
            raise PolicyError(f"{source}: {rid}: 'values' must be non-empty")


def load_policy(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    validate_policy(data, source=path)
    return data


def save_policy(policy, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(policy, fh, indent=2)
        fh.write("\n")


def add_rule(policy, rule):
    values = rule["values"] if isinstance(rule["values"], list) else [rule["values"]]
    clean = {"id": str(rule["id"]), "action": rule["action"].lower(),
             "match": rule["match"].lower(), "values": [str(v) for v in values],
             "description": str(rule.get("description", ""))}
    if any(r.get("id") == clean["id"] for r in policy.get("rules", [])):
        raise PolicyError(f"rule id {clean['id']!r} already exists")
    validate_policy({"default_action": policy["default_action"],
                     "rules": [clean]})
    policy.setdefault("rules", []).append(clean)
    policy["version"] = int(policy.get("version", 0)) + 1


def remove_rule(policy, rule_id):
    before = len(policy.get("rules", []))
    policy["rules"] = [r for r in policy.get("rules", []) if r.get("id") != rule_id]
    if len(policy["rules"]) == before:
        raise PolicyError(f"rule id {rule_id!r} not found")
    policy["version"] = int(policy.get("version", 0)) + 1


# ---------------------------------------------------------- decision engine
class AppControlEngine:
    """Rules are evaluated in listed order; the FIRST match wins, otherwise
    the policy default_action applies. Order your allow/deny rules carefully."""

    def __init__(self, policy):
        self.default_action = policy.get("default_action", "allow")
        self.rules = []
        for r in policy.get("rules", []):
            values = r["values"] if isinstance(r["values"], list) else [r["values"]]
            self.rules.append(Rule(str(r["id"]), r["action"].lower(),
                                   r["match"].lower(), [str(v) for v in values],
                                   str(r.get("description", ""))))

    def decide(self, path):
        ap = os.path.abspath(path)
        for rule in self.rules:
            if self._matches(rule, ap):
                return Decision(ap, rule.action, rule.id, rule.description)
        return Decision(ap, self.default_action, "default",
                        "no rule matched — default action")

    def _matches(self, rule, ap):
        low = ap.lower()
        if rule.match == "path":
            pats = [v.replace("/", "\\").lower() if IS_WINDOWS else v.lower()
                    for v in rule.values]
            return any(fnmatch.fnmatch(low, p) for p in pats)
        if rule.match == "name":
            return any(fnmatch.fnmatch(os.path.basename(low), v.lower())
                       for v in rule.values)
        if rule.match == "extension":
            return os.path.splitext(low)[1] in {v.lower() for v in rule.values}
        if rule.match == "hash":
            try:
                return sha256_file(ap) in {v.lower() for v in rule.values}
            except OSError:
                return False
        return False


def looks_executable(path):
    if IS_WINDOWS:
        return os.path.splitext(path)[1].lower() in EXECUTABLE_EXTS
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    if head.startswith(b"#!"):
        return True
    if IS_MACOS:
        return head in _MACHO_MAGICS
    return head == b"\x7fELF"


def scan_path(engine, path, recursive=False):
    if os.path.isfile(path):
        return [engine.decide(path)]
    decisions = []
    for root, _dirs, files in os.walk(path):
        for name in files:
            fp = os.path.join(root, name)
            if looks_executable(fp):
                decisions.append(engine.decide(fp))
        if not recursive:
            break
    return decisions


# ----------------------------------------------------- enforcement status
def enforcement_status():
    if IS_WINDOWS:
        policy_present = False
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe",
                                0, winreg.KEY_READ):
                policy_present = True
        except OSError:
            pass
        _rc, out, _ = run_command(["sc", "query", "AppIDSvc"])
        svc = "running" if "RUNNING" in out else "stopped" if "STOPPED" in out else "unknown"
        return {"platform": "windows", "mechanism": "AppLocker (SrpV2)",
                "policy_present": policy_present, "appidsvc": svc,
                "active": policy_present and svc == "running"}

    if IS_MACOS:
        _rc, sip_out, _ = run_command(["csrutil", "status"])
        sip = "enabled" in sip_out.lower()
        _rc, sp_out, _ = run_command(["spctl", "--status"])
        gk = "assessments enabled" in sp_out.lower()
        _rc, fw_out, _ = run_command(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        fw = "state = 1" in fw_out.lower()
        return {"platform": "macos", "mechanism": "SIP + Gatekeeper",
                "sip": sip, "gatekeeper": gk, "app_firewall": fw,
                "active": sip and gk,
                "detail": "per-app enforcement on macOS needs configuration "
                          "profiles/MDM — ESHF verification is advisory here"}

    if IS_LINUX:
        _rc, out, _ = run_command(["systemctl", "is-active", "fapolicyd"])
        state = out.strip()
        return {"platform": "linux", "mechanism": "fapolicyd",
                "active": state == "active", "detail": state}

    return {"platform": platform.system(), "mechanism": None, "active": False,
            "detail": "no supported application-control mechanism detected"}


# --------------------------------------------------------------- exporters
def _is_windows_path(v):
    return "\\" in v or re.match(r"^[A-Za-z]:", v) is not None


def export_applocker(policy, out_path):
    """Generate a DRAFT AppLocker EXE policy XML. Test in Audit mode first."""
    engine = AppControlEngine(policy)
    out = ['<?xml version="1.0" encoding="utf-8"?>',
           '<RuleCollection Type="Exe" EnforcementMode="NotConfigured">',
           '  <!-- DRAFT generated by ESHF. Review, test in Audit mode, then:',
           '       Set-AppLockerPolicy -XmlPolicy this_file.xml -->']
    for rule in engine.rules:
        name = escape(f"{rule.id}: {rule.description}".strip(": "))
        for v in rule.values:
            if rule.match == "hash":
                try:
                    data = base64.b64encode(bytes.fromhex(v)).decode()
                except ValueError:
                    out.append(f'  <!-- rule {rule.id}: {v} is not valid hex sha256 -->')
                    continue
                out += [
                    f'  <FileHashRule Action="{rule.action.capitalize()}" '
                    f'UserOrGroupSid="S-1-1-0" Name="{name}" Description="ESHF draft">',
                    '    <Conditions>',
                    f'      <FileHashCondition><FileHash Type="SHA256" Data="{data}" '
                    f'SourceFileName="*" SourceFileLength="0"/></FileHashCondition>',
                    '    </Conditions>',
                    '  </FileHashRule>']
            else:
                if rule.match == "path" and not _is_windows_path(v):
                    out.append(f'  <!-- rule {rule.id}: skipped non-Windows path {escape(v)} -->')
                    continue
                if rule.match == "path":
                    cond = v
                elif rule.match == "name":
                    cond = v if v.startswith("*") else "*" + v
                else:  # extension
                    cond = "*" + (v if v.startswith(".") else "." + v)
                out += [
                    f'  <FilePathRule Action="{rule.action.capitalize()}" '
                    f'UserOrGroupSid="S-1-1-0" Name="{name}" Description="ESHF draft">',
                    '    <Conditions>',
                    f'      <FilePathCondition Path="{escape(cond)}"/>',
                    '    </Conditions>',
                    '  </FilePathRule>']
    out.append('</RuleCollection>')
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")
    return out_path


def export_fapolicyd(policy, out_path):
    """Generate a DRAFT fapolicyd rules file (path rules mapped; others noted)."""
    engine = AppControlEngine(policy)
    lines = ["# DRAFT fapolicyd rules generated by ESHF — review before deploying.",
             "# Install: cp <file> /etc/fapolicyd/rules.d/10-eshf.rules && "
             "systemctl restart fapolicyd"]
    for rule in engine.rules:
        for v in rule.values:
            if rule.match == "path" and "\\" not in v:
                d = v.replace("\\", "/").strip("*")
                if not d.endswith("/"):
                    d += "/"
                if not d.startswith("/"):
                    d = "/" + d
                lines.append(f"# {rule.id}: {rule.description}")
                lines.append(f"{rule.action} perm=any all : dir={d}")
            else:
                lines.append(f"# rule {rule.id} ({rule.match}={v}) -> {rule.action}: "
                             f"map manually — {rule.description}")
    lines.append(("allow" if engine.default_action == "allow" else "deny")
                 + " perm=any all : all")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return out_path
