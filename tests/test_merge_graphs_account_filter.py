"""Regression tests for scripts/merge_graphs.py cross-host IOC extraction.

Locks the fixes from the SRL-2018 capstone post-run review:
  - registry/path fragments must NOT become shared_account IOCs (the 1992-edge flood)
  - accounts come ONLY from account-prefixed supporting_indicators (allowlist)
  - hashes/IPs are still scraped from all text (unambiguous)
  - _host_from_case must not collapse distinct hosts that share a suffix
    (CRIMSON-OSPREY-WKSTN-01 vs CRIMSON-OSPREY-RD-01 -> both 'host:01' before fix)
Pure-stdlib, offline.
"""
import importlib.util
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("merge_graphs", _REPO / "scripts" / "merge_graphs.py")
mg = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(mg)


def _finding(**details):
    return {"details": details}


# ---- account noise filter ----
def test_registry_and_path_fragments_are_not_accounts():
    f = _finding(supporting_indicators=[
        "value_data: HKLM\\SYSTEM\\ControlSet001\\Services\\AeLookupSvc",
        "path: C:\\Windows\\System32\\drivers\\etc",
        "executable: C:\\Users\\Administrator\\x.exe",
    ], description="loaded from windows\\system32 and hklm\\system",
       embedding_text="controlset001\\services tcpip\\parameters")
    iocs = mg._finding_iocs(f)
    accts = [i for i in iocs if i.startswith("account:")]
    assert accts == [], f"registry/path fragments leaked as accounts: {accts}"


def test_real_account_from_prefix_kept():
    f = _finding(supporting_indicators=["account: CORP\\svc_backup"])
    iocs = mg._finding_iocs(f)
    assert "account:corp\\svc_backup" in iocs


def test_benign_account_filtered_even_with_prefix():
    f = _finding(supporting_indicators=["account: NT AUTHORITY\\SYSTEM"])
    assert not [i for i in mg._finding_iocs(f) if i.startswith("account:")]


def test_hashes_and_ips_still_scraped_from_free_text():
    sha1 = "2013247c1481bb44bbebbb927a153b42e73b499f"
    f = _finding(supporting_indicators=[], description=f"dropped {sha1} talking to 10.0.0.50")
    iocs = mg._finding_iocs(f)
    assert f"sha1:{sha1}" in iocs
    assert "ip:10.0.0.50" in iocs


def test_account_not_scraped_from_free_text():
    f = _finding(description="ran as CORP\\jdoe via path C:\\Users\\jdoe")
    # accounts only come from prefixed indicators, never description
    assert not [i for i in mg._finding_iocs(f) if i.startswith("account:")]


# ---- host collision fix ----
def test_host_from_case_no_collision_on_shared_suffix():
    a = mg.UnifiedGraphBuilder._host_from_case("CRIMSON-OSPREY-WKSTN-01")
    b = mg.UnifiedGraphBuilder._host_from_case("CRIMSON-OSPREY-RD-01")
    assert a != b, f"distinct hosts collapsed to the same id: {a!r} == {b!r}"
    assert a == "CRIMSON-OSPREY-WKSTN-01" and b == "CRIMSON-OSPREY-RD-01"


def test_is_noise_account_matrix():
    for benign in ["hklm\\system", "controlset001\\services", "windows\\system32",
                   "users\\administrator", "NT AUTHORITY\\SYSTEM", "tcpip\\parameters"]:
        assert mg._is_noise_account(benign) is True, benign
    for real in ["CORP\\jdoe", "SHIELDBASE\\rsydow-a", "ACME\\svc_sql"]:
        assert mg._is_noise_account(real) is False, real


# ---- registry-noise collapse (_condense_bulk_observations) ----
def _builder_with(nodes, edges):
    b = mg.UnifiedGraphBuilder()
    b.nodes = nodes
    b.edges = edges
    b._node_ids = {n["id"] for n in nodes}
    b._edge_keys = {(e["source"], e["target"], e["type"]) for e in edges}
    return b


def _obs(i, case="C-A", sub="registry", **extra):
    d = {"case_id": case, "artifact_subtype": sub, "evidence_kind": "OBSERVATION",
         "finding_status": "ACTIVE"}
    d.update(extra)
    return {"id": f"F-{i}", "type": "finding", "label": f"F-{i}", "details": d}


def test_condense_collapses_bulk_observations():
    nodes = [{"id": "host:C-A", "type": "host", "label": "C-A"}]
    nodes += [_obs(i) for i in range(30)]  # 30 > threshold(20)
    edges = [{"source": "host:C-A", "target": f"F-{i}", "type": "produced"} for i in range(30)]
    b = _builder_with(nodes, edges)
    b._condense_bulk_observations(threshold=20)
    groups = [n for n in b.nodes if str(n["id"]).startswith("group:")]
    assert len(groups) == 1
    assert groups[0]["details"]["support_count"] == 30
    assert len(groups[0]["details"]["member_ids"]) == 30  # data preserved
    assert not [n for n in b.nodes if n["id"].startswith("F-")]  # members removed


def test_condense_keeps_below_threshold():
    nodes = [{"id": "host:C-A", "type": "host", "label": "C-A"}] + [_obs(i) for i in range(10)]
    edges = [{"source": "host:C-A", "target": f"F-{i}", "type": "produced"} for i in range(10)]
    b = _builder_with(nodes, edges)
    b._condense_bulk_observations(threshold=20)
    assert not [n for n in b.nodes if str(n["id"]).startswith("group:")]


def test_condense_protects_confirmed_corroborated_and_related():
    nodes = [{"id": "host:C-A", "type": "host", "label": "C-A"}, {"id": "ioc:ip:10.0.0.5", "type": "ioc"}]
    nodes += [_obs(i) for i in range(28)]
    nodes += [_obs(100, finding_status="CONFIRMED"),
              _obs(101, corroborated_by=["F-1"]),
              _obs(102)]  # F-102 will get a cross-host edge below
    edges = [{"source": "host:C-A", "target": n["id"], "type": "produced"} for n in nodes if n["id"].startswith("F-")]
    edges.append({"source": "F-102", "target": "ioc:ip:10.0.0.5", "type": "shared_ioc"})
    b = _builder_with(nodes, edges)
    b._condense_bulk_observations(threshold=20)
    surviving = {n["id"] for n in b.nodes if n["id"].startswith("F-")}
    assert {"F-100", "F-101", "F-102"} <= surviving  # protected, not collapsed
