import hashlib
import json

import pytest

from eshf.appcontrol.engine import AppControlEngine, looks_executable
from eshf.checks.base import compare
from eshf.core.baseline import BaselineError, load_baseline_file
from eshf.core.remediation import Remediator
from eshf.utils.helpers import IS_MACOS


def test_compare_operators():
    assert compare("1", "eq", True)[0] is True          # bool truthiness
    assert compare("10", "ge", 8)[0] is True
    assert compare("0644", "in", "0640|0644")[0] is True
    assert compare("abc", "regex", r"^a")[0] is True
    assert compare(None, "absent", None)[0] is True
    assert compare("x", "not_contains", "y")[0] is True


def test_appcontrol_first_match_wins(tmp_path):
    denied_dir = tmp_path / "sketchy"
    denied_dir.mkdir()
    eng = AppControlEngine({"default_action": "allow", "rules": [
        {"id": "R1", "action": "deny", "match": "path",
         "values": [str(denied_dir / "*")]},
        {"id": "R2", "action": "deny", "match": "extension", "values": [".jar"]},
    ]})
    assert eng.decide(str(denied_dir / "evil.sh")).matched_rule == "R1"
    jar = tmp_path / "tool.jar"
    jar.write_bytes(b"x")
    assert eng.decide(str(jar)).matched_rule == "R2"
    ok = tmp_path / "ok.bin"
    ok.write_bytes(b"x")
    assert eng.decide(str(ok)).action == "allow"


def test_appcontrol_hash_rule(tmp_path):
    payload = b"malware-bytes"
    f = tmp_path / "sample.bin"
    f.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    eng = AppControlEngine({"default_action": "allow", "rules": [
        {"id": "H1", "action": "deny", "match": "hash", "values": [digest]},
    ]})
    assert eng.decide(str(f)).action == "deny"


def test_baseline_validation_rejects_bad_type(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"metadata": {}, "checks": [
        {"id": "X1", "type": "nope", "params": {}}]}))
    with pytest.raises(BaselineError):
        load_baseline_file(str(p))


def test_baseline_rejects_duplicate_ids(tmp_path):
    p = tmp_path / "b.json"
    chk = {"id": "D1", "type": "command", "params": {"cmd": "echo hi"}}
    p.write_text(json.dumps({"metadata": {}, "checks": [chk, chk]}))
    with pytest.raises(BaselineError):
        load_baseline_file(str(p))


def test_remediation_dry_run_chmod(tmp_path):
    f = tmp_path / "f.conf"
    f.write_text("x")
    r = Remediator(dry_run=True)
    msg = r.apply({"remediation": {"type": "chmod", "path": str(f), "mode": "600"}})
    assert msg.startswith("would chmod")


def test_remediation_manual_type():
    r = Remediator(dry_run=True)
    msg = r.apply({"remediation": {"type": "manual",
                                   "description": "Enable FileVault in System Settings"}})
    assert "FileVault" in msg


def test_shebang_detection(tmp_path):
    f = tmp_path / "script.sh"
    f.write_text("#!/bin/sh\necho hi\n")
    assert looks_executable(str(f)) is True


@pytest.mark.skipif(not IS_MACOS, reason="Mach-O magic only relevant on macOS")
def test_macho_detection(tmp_path):
    f = tmp_path / "native"
    f.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 16)   # MH_MAGIC_64 LE (Apple Silicon)
    assert looks_executable(str(f)) is True
    g = tmp_path / "fat"
    g.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 16)   # universal binary
    assert looks_executable(str(g)) is True
    h = tmp_path / "text.bin"
    h.write_bytes(b"just some text" + b"\x00" * 8)
    assert looks_executable(str(h)) is False
