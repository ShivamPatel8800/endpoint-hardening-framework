<p align="center">
  <h1 align="center">ESHF</h1>
  <p align="center"><b>Endpoint Security Hardening Framework</b><br>
  Configuration reviews · Application control · Automated remediation</p>
</p>

[![CI](https://github.com/YOUR-USERNAME/endpoint-hardening-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR-USERNAME/endpoint-hardening-framework/actions/workflows/ci.yml)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

ESHF is a zero-dependency Python framework that audits endpoints against
CIS-inspired hardening baselines, manages allow/deny application-control
policies, and remediates failed checks — safely, with dry-run by default.

It ships with three production-ready baselines:

| Baseline | Checks | Highlights |
|---|---|---|
| **macOS** (Apple Silicon) | 21 | SIP, Gatekeeper, FileVault, application firewall, software-update policy, loginwindow hardening, sysctl, sshd |
| **Linux** | 15 | sshd, sysctl, file permissions, password policy, package hygiene, auditd |
| **Windows** | 13 | UAC, LSA protection, SMBv1, RDP/NLA, firewall, AutoRun, account policy |

Cross-platform scans simply `SKIP` inapplicable checks, so one merged scan
works everywhere and the severity-weighted score is never distorted.

---

## Why ESHF

- **Nothing to install** — pure Python 3.8+ standard library. Clone and run.
- **Declarative baselines** — checks are plain JSON; add your own without
  touching code.
- **Application control everywhere** — a single policy model (path / name /
  extension / SHA-256) evaluated by a first-match-wins engine, with
  Mach-O, ELF, PE, and shebang-aware binary detection. Enforcement status is
  read from AppLocker (Windows), fapolicyd (Linux), and SIP + Gatekeeper (macOS).
- **Safe by design** — every remediation runs in dry-run mode unless you pass
  `--apply`; actions that only Recovery, System Settings, or MDM can perform
  are surfaced as guided `manual` steps instead of failing.
- **CI-ready** — `--strict` mode exits non-zero on failures, and reports emit
  as console, JSON, CSV, or self-contained HTML.

---

## Quick start

```bash
git clone https://github.com/YOUR-USERNAME/endpoint-hardening-framework.git
cd endpoint-hardening-framework
python3 -m eshf scan
```

That's it — the baseline is auto-selected for your OS
(`macos_baseline.json` on macOS, `linux_baseline.json` on Linux,
`windows_baseline.json` on Windows).

Optional setup:

```bash
python3 -m venv .venv && source .venv/bin/activate   # isolated env (optional)
pip install -e .                                     # installs the `eshf` CLI globally
pip install pytest                                   # dev-only, for the test suite
```

---

## Usage

### Scan

```bash
python3 -m eshf scan                              # auto-picked platform baseline
python3 -m eshf scan -f html -o report.html       # self-contained HTML report
python3 -m eshf scan -f json -o report.json       # machine-readable (SI ingestion)
python3 -m eshf scan -b config/baselines          # merge every baseline
python3 -m eshf scan --min-severity high --strict # CI: exit 1 on high+ failures
python3 -m eshf scan --category ssh,network       # filter by category
python3 -m eshf baselines                         # inventory available baselines
```

Sample console output:

```
════════════════════════════════════════════════════════════════════════════
 ESHF — Endpoint Security Hardening Framework
 Baseline : ESHF macOS (Apple Silicon) Baseline
 Host     : macbook (Darwin 24.4.0, arm64)
 Date     : 2025-06-01 12:04:33    Checks: 21    Duration: 2.31s
════════════════════════════════════════════════════════════════════════════

 SYSTEM-INTEGRITY
 PASS  ESHF-MAC-0001  System Integrity Protection (SIP) is enabled
 ENCRYPTION
 FAIL  ESHF-MAC-0003  FileVault full-disk encryption is on
        ↳ actual='Off' eq expected='On'
 NETWORK
 PASS  ESHF-MAC-0004  Application firewall is enabled
 SSH
 SKIP  ESHF-MAC-0014  SSH: root login disabled (if Remote Login is used)
        ↳ /etc/ssh/sshd_config not found (optional check)

────────────────────────────────────────────────────────────────────────────
 PASS 15 | FAIL 4 | WARN 0 | ERROR 0 | SKIP 2
 Score    : 81/100   Grade: B
 Suggested fixes:
  - ESHF-MAC-0003: System Settings → Privacy & Security → FileVault → Turn On
════════════════════════════════════════════════════════════════════════════
```

Scoring is severity-weighted (critical ×10, high ×6, medium ×3, low ×1) and
computed only over PASS/FAIL checks, so skipped items are free.

### Remediate

```bash
python3 -m eshf remediate            # dry-run plan — shows exactly what would change
sudo python3 -m eshf remediate --apply --allow-commands   # apply (needs elevation)
python3 -m eshf remediate --only ESHF-MAC-0020            # target specific checks
```

Remediation action types: `registry` (Windows), `sysctl` (Linux, runtime +
persistent), `chmod`, `file_line` (ensure a config directive), `command`
(opt-in via `--allow-commands`), and `manual` (guided instructions for SIP /
FileVault / per-user settings that should never be automated blindly).

### Application control

```bash
python3 -m eshf appcontrol status                # SIP/Gatekeeper · AppLocker · fapolicyd
python3 -m eshf appcontrol verify /usr/bin/ls    # → ALLOW [R001]
python3 -m eshf appcontrol verify /tmp -r        # recursive directory verdicts
python3 -m eshf appcontrol add-rule --id R100 --action deny \
    --match name --value 'crack*' --description 'block cracking tools'
python3 -m eshf appcontrol remove-rule --id R100
python3 -m eshf appcontrol show
python3 -m eshf appcontrol export --target applocker -o draft.xml   # AppLocker XML draft
python3 -m eshf appcontrol export --target fapolicyd -o 10-eshf.rules
```

Rules are evaluated in listed order — **first match wins**, then the policy
`default_action`. The EICAR test file is pre-seeded in the default policy as a
safe way to demonstrate hash blocking:

```bash
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
python3 -m eshf appcontrol verify /tmp/eicar.txt     # → DENY [R004] EICAR test file
```

---

## Writing your own baselines

Checks are JSON objects. Drop a file into `config/baselines/` and it merges
automatically in directory scans:

```json
{
  "id": "ESHF-MAC-0030",
  "title": "Firewall blocks all incoming connections",
  "category": "network",
  "severity": "high",
  "type": "command",
  "params": {
    "cmd": "/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall",
    "pattern": "(?i)Mode:\\s*(\\d)",
    "group": 1, "operator": "eq", "expected": "1"
  },
  "remediation": {
    "type": "manual",
    "description": "System Settings → Network → Firewall → Options → Block all incoming"
  }
}
```

### Check types

| Type | Platforms | Reads |
|---|---|---|
| `command` | all | any command's output, with regex capture + comparison |
| `file_content` | all | file text against a regex (`"optional": true` → SKIP if absent) |
| `file_permission` | macOS, Linux | octal mode (`in`, `eq`, `not_in`) |
| `sysctl` | macOS, Linux | kernel tunables (`/proc/sys` or the `sysctl` CLI) |
| `service` | all | SCM / systemd / launchd state and startup type |
| `package` | all | dpkg / rpm / Homebrew presence |
| `registry` | Windows | hive value by path |
| `app_control_status` | all | OS-level application-control enforcement |

### Operators

`eq` · `ne` · `gt` · `ge` · `lt` · `le` · `contains` · `not_contains` ·
`regex` · `in` · `not_in` · `present` · `absent`

Booleans accept `1/true/yes/on/enabled` so integer and boolean expectations
interchange freely.

---

## Application-control policy format

```json
{
  "name": "eshf-default-policy",
  "version": 3,
  "default_action": "allow",
  "rules": [
    { "id": "R001", "action": "allow", "match": "path",
      "values": ["/usr/bin/*", "C:\\Windows\\*"],
      "description": "Trusted OS directories" },
    { "id": "R002", "action": "deny", "match": "path",
      "values": ["*/tmp/*", "*\\Downloads\\*"],
      "description": "Block execution from user-writable locations" },
    { "id": "R003", "action": "deny", "match": "extension",
      "values": [".scr", ".jar", ".hta"] },
    { "id": "R004", "action": "deny", "match": "hash",
      "values": ["<sha256 hex>"] }
  ]
}
```

Match types: `path` (glob), `name` (glob on basename), `extension`, `hash`
(SHA-256, computed on demand). On macOS, enforcement is advisory — the verify
engine reports what your policy *would* decide; OS-level per-app blocking
requires Gatekeeper configuration profiles or MDM.

---

## Project structure

```
eshf/
├── cli.py              # argument parsing and command dispatch
├── checks/
│   ├── base.py         # result model + operator/comparison engine
│   └── builtin.py      # registry / service / sysctl / package / file / command handlers
├── core/
│   ├── baseline.py     # loading, validation, filtering
│   ├── scanner.py      # orchestration, severity-weighted scoring
│   ├── report.py       # console / JSON / CSV / HTML renderers
│   └── remediation.py  # dry-run-first fix engine
├── appcontrol/
│   └── engine.py       # policy model, decision engine, exporters, status
└── utils/
    └── helpers.py      # subprocess wrapper, colors, hashing, privilege checks
config/
├── baselines/          # macos / linux / windows JSON baselines
└── app_control_policy.json
tests/                  # pytest suite (runs on all 3 OSes in CI)
```

## Testing

```bash
python3 -m pytest tests/ -v
```

CI runs the suite across **Ubuntu, macOS, and Windows** on Python 3.10 and
3.12, including platform-conditional tests (Mach-O detection only asserts on
Darwin runners).

## Safety notes

- `remediate` is a **dry-run planner by default**; nothing changes until you
  pass `--apply`, and command-type fixes additionally require
  `--allow-commands`.
- System-level checks and fixes need elevation (`sudo` / Administrator);
  per-user settings are deliberately typed `manual` so they are never applied
  under the wrong privilege context.
- Always validate a new baseline and remediation set on a scratch VM or a
  non-production endpoint before fleet rollout.
- AppLocker / fapolicyd exports are **drafts** — review them and test in
  audit mode before enforcement.

## Roadmap

- [ ] `.mobileconfig` Gatekeeper profile exporter (macOS)
- [ ] launchd plist generator for persistent macOS sysctl/`defaults` fixes
- [ ] Scan diffing between runs (`--diff previous.json`)
- [ ] SUID/SGID audit check type
- [ ] Scheduled-scan mode with trend scoring

## Contributing

Issues and pull requests are welcome. For new check types, add the handler in
`eshf/checks/builtin.py`, register it in `run_check`, extend
`VALID_TYPES` in `eshf/core/baseline.py`, and include tests plus a sample
baseline entry. Run `pytest` locally before submitting.

## License

MIT — see [LICENSE](LICENSE).
