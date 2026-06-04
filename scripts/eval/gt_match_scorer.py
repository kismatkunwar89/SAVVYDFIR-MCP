#!/usr/bin/env python3
"""Agnostic ground-truth match scorer (PART A, review 2026-06-04).

Computes recall / hallucination / eval-target coverage for a finalized
SAVVYDFIR run against a ground-truth answer-key YAML, using ANCHORED semantic
matching (methodology §2). It is case-agnostic: anchors are derived from each
GT record's own fields - nothing about ROCBA (or any case) is hardcoded.

WHY THIS EXISTS
---------------
The prior scratch matcher counted a GT finding as a TP on a single GENERIC
token overlap (e.g. GT "Natasha Romanoff" matched a report finding on the word
"correlation"). That inflated recall to a meaningless ~100%. This scorer rejects
generic-only matches: a TP requires at least one DISTINCTIVE anchor in common
(email / domain / filename / registry-key identifier / proper-noun / code-name /
EID / ATT&CK technique), never a common DFIR/English word.

MATCH RULE (§2.1, semantic not exact-string)
---------------------------------------------
A GT finding is a TP when some report finding:
  * has evidence_kind / status in {OBSERVATION, INFERENCE}
    (HYPOTHESIS / REJECTED do not count), AND
  * shares >= 1 DISTINCTIVE anchor with the GT finding.
Recall = TP / (TP + FN) over GT `findings`.
Hallucination = report findings sharing a distinctive anchor with a
`known_negatives` entry.
Precision is reported only when the GT declares `exhaustive: true`; otherwise
"N/A - GT non-exhaustive" (courseware GTs are thin; naive FP is meaningless).

Deterministic: same (GT, findings) -> same score.

USAGE
-----
    python scripts/eval/gt_match_scorer.py <gt.yaml> <state_or_report.json> [--json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except Exception as exc:  # pragma: no cover
    print(json.dumps({"status": "error", "error": f"pyyaml required: {exc}"}))
    sys.exit(2)


# Common DFIR / English words that must NEVER, alone, establish a match.
# Case-agnostic: these are domain-generic, not case-specific.
GENERIC = frozenset("""
the a an and or of to in on at for with from is are was were be been being this that these those
by as it its also into per within not no any all more most some such than then over under
user users account accounts activity evidence finding findings file files folder folders path paths
drive google microsoft windows system data download downloads history browser registry key keys value
values execution executed run runs running process processes network connection artifact artifacts
correlation defense evasion exfiltration exfil persistence lateral movement credential access discovery
collection impact reconnaissance command control project content research labs lab company organization
victim subject attacker actor named name person interest additional confirmed observed inference
observation timestamp time date local cache metadata document documents cloud storage client tool
location locations distinct different source sources entry entries record records detected detection
suspicious malicious benign legitimate present absent yields parsed includes including across multiple
extraction extracted known added confirms confirm inside opened open lists list deletion deleted
uninstalled uninstall installed install received receive header headers based appears appear large
tied hosts host hosted ties total counts count files-only image-only filled answer answers blank
default profile profiles local-profile workstation laptop desktop server machine host evidencing
navigation explorer-folder shellbag shellbags lastwrite last-write modified created accessed
""".split())

# Ubiquitous app / tool / domain names that are NOT case-distinctive: a match on
# these alone must not establish a TP or a hallucination.
UBIQUITOUS = frozenset("""
firefox edge chrome chromium outlook gmail yahoo hotmail live iphone ipad icloud onedrive
sharepoint explorer prefetch amcache shimcache srum sysinternals defender powershell sqlite
outlook.com gmail.com yahoo.com google.com microsoft.com live.com hotmail.com office.com
windows.db ntuser.dat usrclass.dat history default
appdata roaming local localwow currentversion software microsoft windows recent users programdata
system32 syswow64 temp tmp automaticdestinations customdestinations winx startmenu programs
shellbags userassist comdlg32 explorer-folder bagmru-root currentcontrolset
""".split())

# Filename stems too generic to anchor on (kept only as full filename).
GENERIC_STEM = frozenset("history default ntuser usrclass index thumbcache desktop user".split())

PROPER_RE = re.compile(r"\b[A-Z][a-zA-Z]{3,}\b")  # Title/Camel-led proper nouns in original case

EMAIL_RE = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", re.I)
DOMAIN_RE = re.compile(r"\b[a-z0-9\-]+(?:\.[a-z0-9\-]+)+\.(?:com|net|org|lan|local|io|gov|edu|info|biz)\b", re.I)
FILE_RE = re.compile(r"\b([a-z0-9_\-.%]+\.(?:exe|dll|pst|docx?|xlsx?|dat|pf|db|hve|lnk|ps1|sys|zip|rar|7z|vhdx?|e01|raw))\b", re.I)
CAMEL_RE = re.compile(r"\b([A-Za-z][a-z0-9]*(?:[A-Z][a-z0-9]+){1,}[A-Za-z0-9]*)\b")  # OpenSavePidlMRU, DropboxUninstaller, BagMRU, TypedPaths, UsrClass, DriveFS, RecentDocs
EID_RE = re.compile(r"\b(?:eid|event id|event_id)\s*[:#]?\s*(\d{3,5})\b", re.I)
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
HOSTY_RE = re.compile(r"\b[a-z][a-z0-9]*(?:-[a-z0-9]+){1,}\b", re.I)  # base-rd-08, freds-laptop, shieldbase.lan
WORD_RE = re.compile(r"[a-z][a-z0-9]{4,}", re.I)  # long-ish lexical tokens (filtered by GENERIC)


def _norm(t: str) -> str:
    return t.strip().strip("._-/:\\").lower()


def distinctive_anchors(text: str) -> set[str]:
    """Extract case-agnostic DISTINCTIVE anchors from free text.

    Distinctive = emails / domains / filenames (+stems) / CamelCase identifiers /
    EIDs / ATT&CK techniques / hyphenated host-ish tokens / long lexical tokens
    that are NOT in GENERIC. Common DFIR/English words are dropped, so a match on
    them alone cannot occur.
    """
    s = str(text or "")
    if not s:
        return set()
    anchors: set[str] = set()
    for m in EMAIL_RE.findall(s):
        m = m.lower()
        anchors.add(m)
        local, _, dom = m.partition("@")
        anchors.update({local, dom})
    for m in DOMAIN_RE.findall(s):
        anchors.add(m.lower())
    for m in FILE_RE.findall(s):
        m = m.lower()
        anchors.add(m)
        stem = re.sub(r"\.[^.]+$", "", m)
        if stem not in GENERIC_STEM:  # drop generic stems (history/default/...)
            anchors.add(stem)
    for m in CAMEL_RE.findall(s):
        anchors.add(m.lower())
    for m in EID_RE.findall(s):
        anchors.add(f"eid{m}")
    for m in TECH_RE.findall(s):
        anchors.add(m.upper())
    for m in HOSTY_RE.findall(s):
        anchors.add(m.lower())
    # dotted code-names: P.E.G.A.S.U.S -> PEGASUS (only when initials collapse to a word)
    for m in re.findall(r"\b(?:[A-Za-z]\.){3,}[A-Za-z]?\b", s):
        collapsed = m.replace(".", "").lower()
        if len(collapsed) >= 4:
            anchors.add(collapsed)
    # proper nouns ONLY (Title/Camel-case in original text) - NOT arbitrary
    # lowercase words. This is what stops the "matched on 'extraction'" failure:
    # generic forensic verbs are lowercase mid-sentence and never harvested here.
    for m in PROPER_RE.findall(s):
        anchors.add(m.lower())
    # filter generics / ubiquitous / too-short
    out = set()
    for a in anchors:
        a = _norm(a)
        if not a or a in GENERIC or a in UBIQUITOUS:
            continue
        if "@" in a or "." in a or "-" in a or len(a) >= 4:
            out.add(a)
    return out


def gt_anchor_text(rec: dict[str, Any]) -> str:
    """Join the GT fields that carry distinctive identity for a finding."""
    parts: list[str] = []
    for k in ("value", "location_key", "artifact_source", "description"):
        if rec.get(k):
            parts.append(str(rec[k]))
    for k in ("registry_paths", "paths_to_verify", "corroborates_with"):
        v = rec.get(k)
        if isinstance(v, list):
            parts.extend(str(x) for x in v)
    return " ".join(parts)


def finding_text(f: dict[str, Any]) -> str:
    parts = [
        str(f.get("description", "")),
        str(f.get("artifact_path", "")),
        str(f.get("artifact_subtype", "")),
        str(f.get("location_key", "")),
        str(f.get("mitre_technique", "")),
    ]
    si = f.get("supporting_indicators") or []
    if isinstance(si, list):
        parts.extend(str(x) for x in si)
    return " ".join(parts)


def load_findings(path: Path) -> list[dict[str, Any]]:
    d = json.loads(path.read_text(encoding="utf-8"))
    for key in ("findings", "all_findings", "top_findings"):
        v = d.get(key)
        if isinstance(v, list) and v:
            return v
    return []


def is_scoreable_status(f: dict[str, Any]) -> bool:
    ek = str(f.get("evidence_kind") or "").upper()
    st = str(f.get("finding_status") or f.get("status") or "").upper()
    # OBSERVATION/INFERENCE evidence kinds; exclude HYPOTHESIS/REJECTED.
    if ek in ("OBSERVATION", "INFERENCE"):
        return True
    if ek in ("HYPOTHESIS", "REJECTED"):
        return False
    # fall back to status when evidence_kind absent
    return st in ("ACTIVE", "CONFIRMED")


def score(gt: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    scoreable = [f for f in findings if is_scoreable_status(f)]
    f_anchors = [(f.get("finding_id"), distinctive_anchors(finding_text(f))) for f in scoreable]

    gt_rows = gt.get("findings", []) or []
    per_gt = []
    tp = fn = 0
    for g in gt_rows:
        ga = distinctive_anchors(gt_anchor_text(g))
        best = None
        for fid, fa in f_anchors:
            shared = ga & fa
            if shared and (best is None or len(shared) > len(best[1])):
                best = (fid, shared)
        if best:
            tp += 1
            per_gt.append({
                "gt_id": g.get("id"), "finding_type": g.get("finding_type"),
                "verdict": "TP", "matched_finding": best[0],
                "match_explanation": sorted(best[1])[:8],
            })
        else:
            fn += 1
            per_gt.append({
                "gt_id": g.get("id"), "finding_type": g.get("finding_type"),
                "verdict": "FN", "matched_finding": None,
                "reject_reason": (
                    "no report finding shared a distinctive anchor with this GT "
                    f"(GT anchors: {sorted(ga)[:8]})"
                ),
            })

    # hallucination: scoreable finding sharing a distinctive anchor with a known-negative
    halluc = []
    for kn in gt.get("known_negatives", []) or []:
        kna = distinctive_anchors(" ".join(
            str(kn.get(k, "")) for k in ("value", "claim", "description", "note")
        ))
        if not kna:
            continue
        for fid, fa in f_anchors:
            shared = kna & fa
            if shared:
                halluc.append({"known_negative": kn.get("value", "")[:60],
                               "finding": fid, "shared_anchor": sorted(shared)[:5]})

    # eval-target coverage (best-effort: anchor presence in any scoreable finding)
    et_cov = []
    all_f_anchors: set[str] = set()
    for _, fa in f_anchors:
        all_f_anchors |= fa
    for et in gt.get("eval_targets", []) or []:
        eta = distinctive_anchors(" ".join(
            str(et.get(k, "")) for k in ("account", "partial_ground_truth", "filter_date", "question")
        ))
        covered = bool(eta & all_f_anchors)
        et_cov.append({"id": et.get("id"), "covered": covered,
                       "anchors": sorted(eta)[:6]})

    recall = tp / (tp + fn) if (tp + fn) else 0.0
    exhaustive = bool(gt.get("exhaustive"))
    return {
        "status": "ok",
        "case_id": gt.get("case_id"),
        "gt_findings": tp + fn,
        "tp": tp,
        "fn": fn,
        "recall": round(recall, 4),
        "hallucinations": halluc,
        "hallucination_count": len(halluc),
        "precision": "N/A - GT non-exhaustive" if not exhaustive else None,
        "eval_target_coverage": {
            "covered": sum(1 for e in et_cov if e["covered"]),
            "total": len(et_cov),
            "detail": et_cov,
        },
        "scoreable_findings": len(scoreable),
        "total_findings": len(findings),
        "per_gt": per_gt,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Agnostic GT-match scorer (recall/hallucination).")
    ap.add_argument("gt_yaml")
    ap.add_argument("findings_json", help="state.json (findings[]) or report.json")
    ap.add_argument("--json", action="store_true", help="emit full JSON")
    args = ap.parse_args()

    gt = yaml.safe_load(Path(args.gt_yaml).read_text(encoding="utf-8"))
    findings = load_findings(Path(args.findings_json))
    result = score(gt, findings)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    print(f"case: {result['case_id']}")
    print(f"{'GT':8} {'type':18} {'verdict':4}  match / reason")
    for r in result["per_gt"]:
        if r["verdict"] == "TP":
            print(f"{r['gt_id']:8} {str(r['finding_type'])[:18]:18} TP    {r['matched_finding']} via {r['match_explanation']}")
        else:
            print(f"{r['gt_id']:8} {str(r['finding_type'])[:18]:18} FN    {r['reject_reason']}")
    print("\n=== SCORE ===")
    print(f"recall: {result['recall']:.1%}  (TP={result['tp']} FN={result['fn']} / {result['gt_findings']} GT)")
    print(f"hallucinations: {result['hallucination_count']} {result['hallucinations'] or ''}")
    print(f"precision: {result['precision']}")
    et = result["eval_target_coverage"]
    print(f"eval_target_coverage: {et['covered']}/{et['total']}")
    print(f"scoreable findings: {result['scoreable_findings']}/{result['total_findings']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
