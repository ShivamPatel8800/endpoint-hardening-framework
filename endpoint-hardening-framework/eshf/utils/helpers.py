"""Small shared utilities: colors, subprocess wrapper, hashing, privilege check."""
import ctypes
import hashlib
import os
import platform
import subprocess
import sys

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"      # macOS, incl. Apple Silicon

RESET, BOLD = "\033[0m", "\033[1m"
RED, GREEN, YELLOW, BLUE, CYAN, GREY = (
    "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[96m", "\033[90m",
)

_COLOR_ENABLED = sys.stdout.isatty()
if IS_WINDOWS and _COLOR_ENABLED:
    os.system("")  # enable ANSI VT processing on Windows 10+

def colorize(text, *codes):
    if not _COLOR_ENABLED:
        return str(text)
    return "".join(codes) + str(text) + RESET

def run_command(cmd, timeout=60):
    """Run a command (str -> shell, list -> argv). Returns (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            shell=isinstance(cmd, str),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except OSError as exc:
        return 1, "", str(exc)

def sha256_file(path, chunk=1 << 16):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()

def is_admin():
    if IS_WINDOWS:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0
