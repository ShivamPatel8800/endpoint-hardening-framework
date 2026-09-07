"""Built-in check executors: registry, services (SCM/systemd/launchd), file
permissions/content, sysctl (Linux /proc + macOS CLI), packages (dpkg/rpm/
Homebrew), commands, and application-control enforcement status."""
import os
import platform
import re

from ..utils.helpers import IS_WINDOWS, IS_LINUX, IS_MACOS, run_command
from .base import CheckResult, Status, compare

if IS_WINDOWS:
    import winreg

_HIVES = {
    "HKLM": winreg.HKEY_LOCAL_MACHINE if IS_WINDOWS else None,
    "HKCU": winreg.HKEY_CURRENT_USER if IS_WINDOWS else None,
    "HKCR": winreg.HKEY_CLASSES_ROOT if IS_WINDOWS else None,
    "HKU": winreg.HKEY_USERS if IS_WINDOWS else None,
}


def _result(check, status, actual="", message=""):
    rem = check.get("remediation") or {}
    return CheckResult(
        check_id=check["id"],
        title=check.get("title", ""),
        category=check.get("category", "general"),
        severity=check.get("severity", "medium"),
        status=status,
        actual=str(actual),
        message=message,
        remediation=rem.get("description", "") if rem else "",
    )


# ----------------------------------------------------------------- registry
def _check_registry(check):
    p = check["params"]
    hive_name, _, subkey = p["path"].replace("/", "\\").partition("\\")
    value_name, op, expected = p.get("value"), p.get("operator", "eq"), p.get("expected")
    hive = _HIVES.get(hive_name.upper())
    if hive is None:
        return _result(check, Status.ERROR, message=f"unknown hive {hive_name!r}")

    actual = None
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            actual, _regtype = winreg.QueryValueEx(key, value_name)
    except FileNotFoundError:
        pass
    except PermissionError:
        return _result(check, Status.SKIP, message="access denied — rerun as Administrator")
    except OSError as exc:
        return _result(check, Status.SKIP, message=f"registry read error: {exc}")

    full = f"{p['path']}\\{value_name}"
    if op == "absent":
        ok = actual is None
        return _result(check, Status.PASS if ok else Status.FAIL,
                       actual=f"{full}: {'absent' if ok else 'present'}")
    if actual is None:
        return _result(check, Status.FAIL, actual=f"{full}: value is not set")
    ok, detail = compare(actual, op, expected)
    return _result(check, Status.PASS if ok else Status.FAIL, actual=detail)


# ----------------------------------------------------------------- services
def _check_service_windows(check):
    p = check["params"]
    name, want_state, want_startup = p["name"], p.get("state"), p.get("startup")
    rc, out, err = run_command(["sc", "query", name])
    state = "running" if "RUNNING" in out else "stopped" if "STOPPED" in out else None
    if state is None:
        return _result(check, Status.ERROR, message=f"cannot query {name!r}: {err[:120]}")

    parts, problems = [f"state={state}"], []
    if want_state and state != want_state:
        problems.append(f"state is {state}, expected {want_state}")

    if want_startup:
        _rc, out2, _ = run_command(["sc", "qc", name])
        m = re.search(r"START_TYPE\s*:\s*\d+\s+(\w+)", out2)
        startup = {"AUTO_START": "auto", "DEMAND_START": "manual",
                   "DISABLED": "disabled"}.get(m.group(1)) if m else None
        if startup is None:
            return _result(check, Status.WARN, actual=", ".join(parts),
                           message="could not parse START_TYPE (localized output?)")
        parts.append(f"startup={startup}")
        if startup != want_startup:
            problems.append(f"startup is {startup}, expected {want_startup}")

    return _result(check, Status.FAIL if problems else Status.PASS,
                   actual=", ".join(parts), message="; ".join(problems))


def _check_service_linux(check):
    import shutil
    if not shutil.which("systemctl"):
        return _result(check, Status.SKIP, message="systemctl not available (no systemd?)")
    p = check["params"]
    name, want_state, want_startup = p["name"], p.get("state"), p.get("startup")
    if not want_state and not want_startup:
        return _result(check, Status.ERROR, message="no expected state/startup given")

    parts, problems = [], []
    if want_state:
        _rc, out, _ = run_command(["systemctl", "is-active", name])
        state = out.strip() or "unknown"
        parts.append(f"state={state}")
        if state != want_state:
            problems.append(f"state is {state}, expected {want_state}")
    if want_startup:
        _rc, out, _ = run_command(["systemctl", "is-enabled", name])
        enabled = out.strip() or "unknown"
        parts.append(f"startup={enabled}")
        if enabled != want_startup:
            problems.append(f"startup is {enabled}, expected {want_startup}")

    return _result(check, Status.FAIL if problems else Status.PASS,
                   actual=", ".join(parts), message="; ".join(problems))


def _check_service_macos(check):
    """launchd via launchctl. 'state' accepts running|loaded|not loaded.
    'startup' accepts enabled|disabled (checked in the *system* domain —
    run the scan with sudo for reliable system-domain visibility)."""
    import shutil
    if not shutil.which("launchctl"):
        return _result(check, Status.SKIP, message="launchctl not available")
    p = check["params"]
    name, want_state, want_startup = p["name"], p.get("state"), p.get("startup")
    if not want_state and not want_startup:
        return _result(check, Status.ERROR, message="no expected state/startup given")

    rc, out, _ = run_command(["launchctl", "list", name])
    loaded = rc == 0 and bool(out)
    running = loaded and out.split()[0] != "-"
    state = "running" if running else ("loaded" if loaded else "not loaded")
    parts, problems = [f"state={state}"], []
    if want_state and state != want_state:
        problems.append(f"state is {state}, expected {want_state}")

    if want_startup:
        _rc, out2, _ = run_command(["launchctl", "print-disabled", "system"])
        disabled = f'"{name}" => true' in out2
        parts.append(f"startup={'disabled' if disabled else 'enabled (system domain)'}")
        if disabled != (want_startup == "disabled"):
            problems.append(f"startup is {'disabled' if disabled else 'enabled'}, "
                            f"expected {want_startup}")

    return _result(check, Status.FAIL if problems else Status.PASS,
                   actual=", ".join(parts), message="; ".join(problems))


# --------------------------------------------------- posix file permissions
def _check_file_permission(check):
    p = check["params"]
    path, expected, op = p["path"], p.get("expected", "0644"), p.get("operator", "in")
    if not os.path.exists(path):
        return _result(check, Status.FAIL, actual="missing", message=f"{path} does not exist")
    mode = os.stat(path).st_mode & 0o7777
    values = expected if isinstance(expected, list) else str(expected).split("|")
    nums = [int(str(v).strip(), 8) for v in values]
    ok = {"eq": mode == nums[0], "in": mode in nums, "not_in": mode not in nums}.get(op)
    if ok is None:
        return _result(check, Status.ERROR, message=f"operator {op!r} not supported here")
    return _result(check, Status.PASS if ok else Status.FAIL,
                   actual=f"mode={format(mode, '04o')} expected={expected}")


# ------------------------------------------------------------- file content
def _check_file_content(check):
    p = check["params"]
    path, pattern, op = p["path"], p["pattern"], p.get("operator", "present")
    if not os.path.exists(path):
        if check.get("optional"):
            return _result(check, Status.SKIP, message=f"{path} not found (optional check)")
        return _result(check, Status.FAIL, actual="missing", message=f"{path} not found")
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    m = re.search(pattern, text, re.MULTILINE)

    if op == "present":
        ok = m is not None
        return _result(check, Status.PASS if ok else Status.FAIL,
                       actual=f"pattern {'matched' if ok else 'not found'}: {pattern}")
    if op == "absent":
        ok = m is None
        return _result(check, Status.PASS if ok else Status.FAIL,
                       actual=f"pattern {'unexpectedly present' if not ok else 'absent'}: {pattern}")
    if m is None:
        return _result(check, Status.FAIL, actual="pattern not found",
                       message=f"{pattern!r} not found in {path}")
    grp = p.get("group", 1)
    actual = m.group(grp) if m.groups() else m.group(0)
    ok, detail = compare(actual, op, p.get("expected"))
    return _result(check, Status.PASS if ok else Status.FAIL, actual=detail)


# ------------------------------------------------------------------- sysctl
def _check_sysctl(check):
    p = check["params"]
    key = p["key"]
    if IS_MACOS:
        rc, out, err = run_command(["sysctl", "-n", key])
        if rc != 0:
            return _result(check, Status.FAIL, actual="missing",
                           message=f"sysctl {key}: {err[:100]}")
        ok, detail = compare(out, p.get("operator", "eq"), p.get("expected"))
        return _result(check, Status.PASS if ok else Status.FAIL, actual=detail)
    # Linux
    path = "/proc/sys/" + key.replace(".", "/")
    if not os.path.exists(path):
        return _result(check, Status.FAIL, actual="missing", message=f"sysctl {key} unavailable")
    with open(path) as fh:
        actual = fh.read().strip()
    ok, detail = compare(actual, p.get("operator", "eq"), p.get("expected"))
    return _result(check, Status.PASS if ok else Status.FAIL, actual=detail)


# ------------------------------------------------------------------ package
def _check_package(check):
    import shutil
    name = check["params"]["name"]
    want = str(check["params"].get("expected", "absent")).lower()
    if IS_MACOS:
        if not shutil.which("brew"):
            return _result(check, Status.SKIP, message="Homebrew not installed")
        rc, _out, _err = run_command(["brew", "list", name])
        installed = rc == 0
    elif shutil.which("dpkg-query"):
        rc, out, _ = run_command(["dpkg-query", "-W", "-f=${Status}", name])
        installed = rc == 0 and "install ok installed" in out
    elif shutil.which("rpm"):
        rc, _, _ = run_command(["rpm", "-q", name])
        installed = rc == 0
    else:
        return _result(check, Status.SKIP, message="no brew/dpkg/rpm package manager found")
    ok = installed if want == "installed" else not installed
    return _result(check, Status.PASS if ok else Status.FAIL,
                   actual=f"{name} {'installed' if installed else 'not installed'} (want {want})")


# ------------------------------------------------------------------ command
def _check_command(check):
    p = check["params"]
    rc, out, err = run_command(p["cmd"], timeout=int(p.get("timeout", 60)))
    text = out or err
    pattern = p.get("pattern")
    if pattern:
        m = re.search(pattern, text, re.MULTILINE)
        if not m:
            return _result(check, Status.FAIL, actual=text[:160],
                           message=f"pattern {pattern!r} not matched in command output")
        grp = p.get("group", 1)
        actual = m.group(grp) if m.groups() else m.group(0)
    else:
        actual = text
    ok, detail = compare(actual, p.get("operator", "eq"), p.get("expected"))
    return _result(check, Status.PASS if ok else Status.FAIL, actual=detail)


# --------------------------------------------------- app-control enforcement
def _check_app_control_status(check):
    from ..appcontrol.engine import enforcement_status
    st = enforcement_status()
    detail = "; ".join(f"{k}={v}" for k, v in st.items() if k != "platform")
    return _result(check, Status.PASS if st.get("active") else Status.FAIL, actual=detail)


# ----------------------------------------------------------------- dispatch
def run_check(check):
    """Route a check dict to its handler. A failing check never aborts a scan."""
    ctype, sysname = check.get("type"), platform.system()

    if ctype == "registry":
        if sysname != "Windows":
            return _result(check, Status.SKIP, message="requires Windows")
        handler = _check_registry
    elif ctype == "service":
        if sysname == "Windows":
            handler = _check_service_windows
        elif sysname == "Linux":
            handler = _check_service_linux
        elif sysname == "Darwin":
            handler = _check_service_macos
        else:
            return _result(check, Status.SKIP, message="unsupported platform")
    elif ctype == "file_permission":
        if sysname == "Windows":
            return _result(check, Status.SKIP, message="POSIX permissions not applicable")
        handler = _check_file_permission          # works on macOS and Linux
    elif ctype == "file_content":
        handler = _check_file_content
    elif ctype == "sysctl":
        if sysname not in ("Linux", "Darwin"):
            return _result(check, Status.SKIP, message="requires Linux or macOS")
        handler = _check_sysctl
    elif ctype == "package":
        handler = _check_package
    elif ctype == "command":
        handler = _check_command
    elif ctype == "app_control_status":
        if sysname not in ("Windows", "Linux", "Darwin"):
            return _result(check, Status.SKIP, message="unsupported platform")
        handler = _check_app_control_status
    else:
        return _result(check, Status.ERROR, message=f"unsupported check type {ctype!r}")

    try:
        return handler(check)
    except Exception as exc:  # defensive: one bad check must not kill the scan
        return _result(check, Status.ERROR, message=f"{type(exc).__name__}: {exc}")
