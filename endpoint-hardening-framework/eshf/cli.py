"""ESHF command-line interface. The default baseline auto-selects by OS:
macos_baseline.json on your Mac, linux_baseline.json on Linux servers,
windows_baseline.json on Windows — override anytime with -b."""
import argparse
import glob
import os
import platform
import sys
from collections import Counter

from . import __version__
from .appcontrol import engine as ac
from .checks.base import Status
from .core.baseline import (SEVERITIES, BaselineError, filter_checks,
                            load_baseline_file, load_baselines)
from .core.remediation import Remediator
from .core.report import to_console, to_csv, to_html, to_json, write as write_report
from .core.scanner import run_scan
from .utils.helpers import BOLD, GREEN, RED, YELLOW, colorize

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_BASELINES = os.path.join(ROOT, "config", "baselines")
DEFAULT_POLICY = os.path.join(ROOT, "config", "app_control_policy.json")

_PLATFORM_FILE = {"Darwin": "macos", "Linux": "linux", "Windows": "windows"}


def _default_baseline():
    """Pick the platform-native baseline if it exists, else the merged dir."""
    key = _PLATFORM_FILE.get(platform.system())
    if key:
        p = os.path.join(DEFAULT_BASELINES, f"{key}_baseline.json")
        if os.path.exists(p):
            return p
    return DEFAULT_BASELINES


# ------------------------------------------------------------------ scan
def cmd_scan(args):
    bl = load_baselines(args.baseline)
    checks = filter_checks(bl["checks"], min_severity=args.min_severity,
                           categories=args.category.split(",") if args.category else None)
    if not checks:
        print("No checks match the given filters.")
        return 0
    rep = run_scan(checks, bl["metadata"])

    if args.output:
        if args.format == "console":
            print("Use -f json|html|csv together with -o, or omit -o for console output.")
            return 2
        write_report(rep, args.format, args.output)
        s = rep.summary
        print(colorize(f"Report written to {args.output} — "
                       f"PASS {s['passed']} / FAIL {s['failed']} / "
                       f"score {s['score']} ({s['grade']})", BOLD))
    elif args.format == "console":
        print(to_console(rep))
    elif args.format == "json":
        print(to_json(rep))
    elif args.format == "csv":
        print(to_csv(rep))
    else:
        print(to_html(rep))
    return 1 if (args.strict and rep.summary["failed"]) else 0


# -------------------------------------------------------------- baselines
def cmd_baselines(args):
    path = args.path or DEFAULT_BASELINES
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "*.json")))
    else:
        files = [path]
    for f in files:
        try:
            bl = load_baseline_file(f)
        except (BaselineError, OSError) as e:
            print(colorize(f" [!] {f}: {e}", RED))
            continue
        counts = Counter(c["severity"] for c in bl["checks"])
        breakdown = ", ".join(f"{s}:{counts[s]}" for s in SEVERITIES if counts.get(s))
        marker = "  ← this platform" if f == _default_baseline() else ""
        print(f"{bl['metadata'].get('name', '?')} "
              f"v{bl['metadata'].get('version', '?')}  ({f}){marker}")
        print(f"   checks: {len(bl['checks'])} — {breakdown}")
    return 0


# -------------------------------------------------------------- remediate
def cmd_remediate(args):
    bl = load_baselines(args.baseline)
    rep = run_scan(bl["checks"], bl["metadata"])
    s = rep.summary
    print(f"Scan: PASS {s['passed']} / FAIL {s['failed']} / "
          f"ERROR {s['errors']} / SKIP {s['skipped']}")

    by_id = {c["id"]: c for c in bl["checks"]}
    only = {x.upper() for x in args.only} if args.only else None
    targets = []
    for r in rep.results:
        if r.status != Status.FAIL:
            continue
        c = by_id.get(r.check_id)
        if not c or not c.get("remediation"):
            continue
        if only and c["id"].upper() not in only:
            continue
        targets.append(c)

    if not targets:
        print("Nothing to remediate (no failed checks define automated remediation).")
        return 0

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(colorize(f"Remediator [{mode}]: {len(targets)} action(s)", BOLD))
    rem = Remediator(dry_run=not args.apply, allow_commands=args.allow_commands)
    for c in targets:
        msg = rem.apply(c)
        tag = colorize("PLAN", YELLOW) if not args.apply else colorize("DONE", GREEN)
        print(f" [{tag}] {c['id']}: {msg}")
    if not args.apply:
        print(colorize("\nDry-run only. Re-run with --apply to make changes "
                       "(use sudo for system-wide fixes).", BOLD))
    return 0


# ------------------------------------------------------------- appcontrol
def cmd_ac_verify(args):
    policy = ac.load_policy(args.policy)
    eng = ac.AppControlEngine(policy)
    if not os.path.exists(args.path):
        print(colorize(f"Path not found: {args.path}", RED))
        return 2
    decisions = (ac.scan_path(eng, args.path, recursive=args.recursive)
                 if os.path.isdir(args.path) else [eng.decide(args.path)])
    if not decisions:
        print("No executable files found (scripts with shebangs and Mach-O/ELF/PE "
              "binaries are counted).")
        return 0
    denied = 0
    for d in decisions:
        color = RED if d.action == "deny" else GREEN
        tag = colorize(f"{d.action.upper():<5}", color)
        print(f" {tag}  {d.path}   [{d.matched_rule}] {d.reason or '-'}")
        denied += d.action == "deny"
    print(colorize(f"\n{len(decisions)} file(s): "
                   f"{len(decisions) - denied} allowed, {denied} denied", BOLD))
    return 1 if denied else 0


def cmd_ac_show(args):
    policy = ac.load_policy(args.policy)
    print(f"Policy   : {policy.get('name', '?')} (v{policy.get('version', '?')})")
    print(f"Default  : {policy['default_action']}")
    for i, r in enumerate(policy.get("rules", []), 1):
        print(f" {i:2}. [{r['id']}] {r['action'].upper():4} {r['match']:9} "
              f"{r['values']}  # {r.get('description', '')}")
    return 0


def cmd_ac_add(args):
    policy = ac.load_policy(args.policy)
    try:
        ac.add_rule(policy, {"id": args.id, "action": args.action, "match": args.match,
                             "values": args.value, "description": args.description or ""})
    except ac.PolicyError as e:
        print(colorize(str(e), RED))
        return 2
    ac.save_policy(policy, args.policy)
    print(f"Rule {args.id} added to {args.policy}")
    return 0


def cmd_ac_remove(args):
    policy = ac.load_policy(args.policy)
    try:
        ac.remove_rule(policy, args.id)
    except ac.PolicyError as e:
        print(colorize(str(e), RED))
        return 2
    ac.save_policy(policy, args.policy)
    print(f"Rule {args.id} removed from {args.policy}")
    return 0


def cmd_ac_export(args):
    policy = ac.load_policy(args.policy)
    if args.target == "applocker":
        ac.export_applocker(policy, args.output)
    else:
        ac.export_fapolicyd(policy, args.output)
    print(f"Draft {args.target} policy written to {args.output} — review before deploying.")
    return 0


def cmd_ac_status(args):
    st = ac.enforcement_status()
    for k, v in st.items():
        print(f" {k:16}: {v}")
    return 0


# ------------------------------------------------------------------ parser
def build_parser():
    p = argparse.ArgumentParser(
        prog="eshf",
        description="ESHF — Endpoint Security Hardening Framework "
                    "(configuration reviews, application control, remediation)")
    p.add_argument("--version", action="version", version=f"eshf {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    default_bl = _default_baseline()

    scan = sub.add_parser("scan", help="run baseline checks against this endpoint")
    scan.add_argument("-b", "--baseline", default=default_bl,
                      help="baseline file or directory (default: auto-picked for this OS)")
    scan.add_argument("-f", "--format", choices=["console", "json", "csv", "html"],
                      default="console")
    scan.add_argument("-o", "--output", help="write report to file (with -f)")
    scan.add_argument("--min-severity", choices=SEVERITIES)
    scan.add_argument("--category", help="comma-separated category filter")
    scan.add_argument("--strict", action="store_true",
                      help="exit 1 if any check fails (CI-friendly)")
    scan.set_defaults(func=cmd_scan)

    bl = sub.add_parser("baselines", help="list available baselines")
    bl.add_argument("--path", default=None)
    bl.set_defaults(func=cmd_baselines)

    rem = sub.add_parser("remediate", help="auto-remediate failed checks (dry-run by default)")
    rem.add_argument("-b", "--baseline", default=default_bl)
    rem.add_argument("--apply", action="store_true", help="actually apply changes")
    rem.add_argument("--allow-commands", action="store_true",
                     help="permit command-type remediations")
    rem.add_argument("--only", nargs="*", help="limit to these check ids")
    rem.set_defaults(func=cmd_remediate)

    app = sub.add_parser("appcontrol", help="application control policy tools")
    appsub = app.add_subparsers(dest="acmd", required=True)

    v = appsub.add_parser("verify", help="verify a file or directory against the policy")
    v.add_argument("path")
    v.add_argument("--policy", default=DEFAULT_POLICY)
    v.add_argument("-r", "--recursive", action="store_true")
    v.set_defaults(func=cmd_ac_verify)

    s = appsub.add_parser("status", help="show OS-level application-control enforcement")
    s.set_defaults(func=cmd_ac_status)

    sh = appsub.add_parser("show", help="print the policy")
    sh.add_argument("--policy", default=DEFAULT_POLICY)
    sh.set_defaults(func=cmd_ac_show)

    a = appsub.add_parser("add-rule", help="add a rule to the policy")
    a.add_argument("--id", required=True)
    a.add_argument("--action", choices=["allow", "deny"], required=True)
    a.add_argument("--match", choices=sorted(ac.VALID_MATCH), required=True)
    a.add_argument("--value", action="append", required=True)
    a.add_argument("--description", default="")
    a.add_argument("--policy", default=DEFAULT_POLICY)
    a.set_defaults(func=cmd_ac_add)

    d = appsub.add_parser("remove-rule", help="remove a rule by id")
    d.add_argument("--id", required=True)
    d.add_argument("--policy", default=DEFAULT_POLICY)
    d.set_defaults(func=cmd_ac_remove)

    e = appsub.add_parser("export", help="export policy as AppLocker XML or fapolicyd rules")
    e.add_argument("--target", choices=["applocker", "fapolicyd"], required=True)
    e.add_argument("-o", "--output", required=True)
    e.add_argument("--policy", default=DEFAULT_POLICY)
    e.set_defaults(func=cmd_ac_export)

    return p


def main():
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except BaselineError as e:
        print(colorize(f"baseline error: {e}", RED), file=sys.stderr)
        return 2
    except ac.PolicyError as e:
        print(colorize(f"policy error: {e}", RED), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
