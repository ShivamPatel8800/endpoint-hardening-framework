ESHF — Endpoint Security Hardening Framework
Zero-dependency Python framework (3.8+, stdlib only) for:

Configuration reviews — scan endpoints against JSON hardening baselines(macOS: SIP/Gatekeeper/FileVault/firewall/updates/sysctl; Linux: sshd/sysctl/perms; Windows: registry/services) with severity-weighted scoring andconsole/JSON/CSV/HTML reports.
Application control — allow/deny policies by path, name, extension, orSHA-256; Mach-O/ELF/PE/shebang-aware directory scanning; enforcement-statusdetection (SIP + Gatekeeper / AppLocker / fapolicyd).
Automated remediation — dry-run by default; explicit --apply opt-in;manual type surfaces guided instructions for things only Recovery/SystemSettings can change (SIP, FileVault).
Setup (MacBook, Apple Silicon)
xcode-select --install                 # one-time: provides python3 + cccd endpoint-hardening-frameworkpython3 -m venv .venv && source .venv/bin/activate   # optional but tidypip install pytest                     # dev-only, for the test suite
Install as a global CLI (optional): pip install -e . → use eshf … anywhere.

Daily use
python3 -m pytest tests/ -v                   # all tests passpython3 -m eshf scan                          # auto-picks the macOS baselinepython3 -m eshf scan -f html -o mac-report.htmlpython3 -m eshf scan --min-severity high --strict     # CI mode (exit 1 on FAIL)python3 -m eshf baselines                     # list all baselines (marks this platform)python3 -m eshf scan -b config/baselines      # merge every baseline (others SKIP)python3 -m eshf remediate                     # dry-run plan (safe, no sudo needed to plan)sudo python3 -m eshf remediate --apply --allow-commands   # apply system-wide fixespython3 -m eshf appcontrol status             # SIP / Gatekeeper / app-firewall statepython3 -m eshf appcontrol verify /tmp -rprintf 'int main(){return 0;}' > /tmp/t.c && cc -o /tmp/t /tmp/t.cpython3 -m eshf appcontrol verify /tmp/t      # → DENY  [R002] user-writable locationpython3 -m eshf appcontrol verify /usr/bin/ls # → ALLOW [R001]python3 -m eshf appcontrol add-rule --id R100 --action deny \    --match name --value 'crack*' --description 'block crack tools'python3 -m eshf appcontrol showpython3 -m eshf appcontrol export --target applocker -o draft.xml  # cross-platform drafting
Baseline check schema
{ "id": "ESHF-MAC-0003", "title": "...", "category": "encryption", "severity": "high",  "type": "command",  "params": { "cmd": "fdesetup status",              "pattern": "FileVault is (On|Off)", "group": 1,              "operator": "eq", "expected": "On" },  "remediation": { "type": "manual", "description": "System Settings → FileVault → Turn On" } }
Types: command (any OS), file_content (+ "optional": true → SKIP if thefile is absent), file_permission (POSIX), sysctl (Linux /proc + macOS CLI),service (SCM / systemd / launchd), package (dpkg / rpm / Homebrew),registry (Windows), app_control_status (all OSes).Operators: eq, ne, gt, ge, lt, le, contains, not_contains, regex, in, not_in,present, absent. Cross-platform scans simply SKIP non-applicable checks and thescore ignores them.

macOS notes & safety
Run the scan as yourself; use sudo only for system-wide visibility/fixes(launchd system domain, /Library/Preferences defaults, firewall, sysctl).
Per-user settings (defaults -currentHost, screensaver) are checked/remediatedas your user — their remediation is manual so it is never run under sudo.
SIP and FileVault can only change from Recovery / System Settings — shown asmanual steps; the dry-run planner lists them under "Suggested fixes".
Application control is advisory on macOS: real per-app enforcement needsGatekeeper configuration profiles or MDM. The verify engine shows what yourpolicy would say; it does not block execution.
macOS ignores /etc/sysctl.conf on modern releases — persist sysctl fixes viaa LaunchDaemon if needed.
SSH checks are optional: they SKIP if Remote Login was never enabled, andlegitimately FAIL if sshd runs with Apple's unhardened defaults.
Licensed under the MIT License.
