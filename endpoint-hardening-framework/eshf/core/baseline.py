"""Baseline loading, validation, and filtering."""
import glob
import json
import os

SEVERITIES = ("info", "low", "medium", "high", "critical")   # ascending
RANK = {s: i for i, s in enumerate(SEVERITIES)}
VALID_TYPES = {"registry", "service", "file_permission", "file_content",
               "sysctl", "package", "command", "app_control_status"}


class BaselineError(ValueError):
    pass


def load_baseline_file(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or not isinstance(data.get("checks"), list):
        raise BaselineError(f"{path}: expected object with a 'checks' list")

    meta = data.get("metadata", {})
    checks, seen = [], set()
    for i, raw in enumerate(data["checks"]):
        c = dict(raw)
        cid = str(c.get("id") or f"CHECK-{i + 1:04d}")
        if cid in seen:
            raise BaselineError(f"{path}: duplicate check id {cid!r}")
        seen.add(cid)
        if c.get("type") not in VALID_TYPES:
            raise BaselineError(f"{path}: {cid}: unknown type {c.get('type')!r}")
        if not isinstance(c.get("params"), dict):
            raise BaselineError(f"{path}: {cid}: 'params' must be an object")
        sev = str(c.get("severity", "medium")).lower()
        if sev not in SEVERITIES:
            raise BaselineError(f"{path}: {cid}: invalid severity {sev!r}")
        c["id"], c["severity"] = cid, sev
        checks.append(c)

    return {"metadata": meta, "checks": checks, "source": path}


def load_baselines(path):
    """Load one baseline file or every *.json in a directory (merged, deduped)."""
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "*.json")))
        if not files:
            raise BaselineError(f"no *.json baselines found in {path}")
    elif os.path.isfile(path):
        files = [path]
    else:
        raise BaselineError(f"baseline not found: {path}")

    checks, names, versions, sources, seen = [], [], [], [], set()
    for f in files:
        bl = load_baseline_file(f)
        names.append(bl["metadata"].get("name", os.path.basename(f)))
        versions.append(str(bl["metadata"].get("version", "?")))
        sources.append(f)
        for c in bl["checks"]:
            if c["id"] in seen:
                raise BaselineError(f"duplicate check id across baselines: {c['id']}")
            seen.add(c["id"])
            checks.append(c)

    meta = {"name": " + ".join(names), "version": versions[0], "sources": sources}
    return {"metadata": meta, "checks": checks}


def filter_checks(checks, min_severity=None, categories=None):
    out = checks
    if min_severity:
        out = [c for c in out if RANK[c["severity"]] >= RANK[min_severity]]
    if categories:
        cats = [x.strip().lower() for x in categories if x.strip()]
        out = [c for c in out if c.get("category", "").lower() in cats]
    return out
