"""Safe, explicit remediation. Dry-run by default; each check may define one
`remediation` block: registry | sysctl | chmod | file_line | command | manual."""
import os
import re

from ..utils.helpers import IS_WINDOWS, is_admin, run_command

if IS_WINDOWS:
    import winreg

_HIVES = {
    "HKLM": winreg.HKEY_LOCAL_MACHINE if IS_WINDOWS else None,
    "HKCU": winreg.HKEY_CURRENT_USER if IS_WINDOWS else None,
}


class Remediator:
    def __init__(self, dry_run=True, allow_commands=False):
        self.dry_run = dry_run
        self.allow_commands = allow_commands

    def apply(self, check):
        rem = check.get("remediation")
        if not rem:
            return "no automated remediation defined"
        if rem.get("type") in ("manual", "note"):
            return rem.get("description") or "manual remediation required"
        handler = {
            "registry": self._registry, "sysctl": self._sysctl,
            "chmod": self._chmod, "file_line": self._file_line,
            "command": self._command,
        }.get(rem.get("type"))
        if handler is None:
            return f"unsupported remediation type {rem.get('type')!r}"
        try:
            return handler(rem)
        except PermissionError:
            return "permission denied — run elevated (sudo)"
        except Exception as exc:
            return f"remediation failed: {type(exc).__name__}: {exc}"

    # -- Windows registry ---------------------------------------------------
    def _registry(self, rem):
        if not IS_WINDOWS:
            return "registry remediation is Windows-only"
        hive_name, _, subkey = rem["path"].replace("/", "\\").partition("\\")
        hive = _HIVES.get(hive_name.upper())
        if hive is None:
            return f"unknown hive {hive_name!r}"
        rtype, data = rem.get("reg_type", "string").lower(), rem["data"]
        desc = f"{rem['path']}\\{rem['value']} = {data!r} ({rtype})"
        if self.dry_run:
            return f"would set {desc}"
        if not is_admin():
            return "needs Administrator privileges"
        with winreg.CreateKeyEx(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
            if rtype == "dword":
                winreg.SetValueEx(key, rem["value"], 0, winreg.REG_DWORD, int(data))
            elif rtype == "qword":
                winreg.SetValueEx(key, rem["value"], 0, winreg.REG_QWORD, int(data))
            else:
                winreg.SetValueEx(key, rem["value"], 0, winreg.REG_SZ, str(data))
        return f"set {desc}"

    # -- Linux sysctl (runtime + persisted) ---------------------------------
    def _sysctl(self, rem):
        if IS_WINDOWS:
            return "sysctl remediation is Linux-only"
        key, value = rem["key"], str(rem["value"])
        if self.dry_run:
            return f"would set {key}={value} (runtime + /etc/sysctl.d/99-eshf-hardening.conf)"
        if not is_admin():
            return "needs root privileges"
        with open("/proc/sys/" + key.replace(".", "/"), "w") as fh:
            fh.write(value + "\n")
        persist = "/etc/sysctl.d/99-eshf-hardening.conf"
        existing = ""
        if os.path.exists(persist):
            with open(persist) as fh:
                existing = fh.read()
        entry = f"{key} = {value}\n"
        if entry not in existing:
            with open(persist, "a") as fh:
                fh.write(entry)
        return f"set {key}={value}"

    # -- POSIX chmod ---------------------------------------------------------
    def _chmod(self, rem):
        path, mode = rem["path"], int(str(rem["mode"]), 8)
        if self.dry_run:
            return f"would chmod {format(mode, '04o')} {path}"
        os.chmod(path, mode)
        return f"chmod {format(mode, '04o')} {path}"

    # -- ensure a config line exists (append-only) ---------------------------
    def _file_line(self, rem):
        path, line, pat = rem["path"], rem["line"], rem.get("pattern")
        text = ""
        if os.path.exists(path):
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        if pat and re.search(pat, text, re.MULTILINE):
            return f"{path}: directive already present — manual review required"
        if self.dry_run:
            return f"would append {line!r} to {path}"
        with open(path, "a", encoding="utf-8") as fh:
            prefix = "\n" if text and not text.endswith("\n") else ""
            fh.write(prefix + line.rstrip("\n") + "\n")
        return f"appended {line!r} to {path}"

    # -- arbitrary command (opt-in) ------------------------------------------
    def _command(self, rem):
        cmd = rem["cmd"]
        if not self.allow_commands:
            return "skipped (command remediations need --allow-commands)"
        if self.dry_run:
            return f"would run: {cmd}"
        if not is_admin():
            return "needs elevated privileges (sudo)"
        rc, out, _err = run_command(cmd)
        return f"ran: {cmd} (rc={rc})" + (f" {out[:80]}" if out else "")
