# Multi-Host Lead-Driven Pivot Methodology

**How SAVVYDFIR-MCP investigates an enterprise intrusion across multiple hosts.**

This is the real-IR way: investigate one host, extract its IOCs, then *hunt those specific IOCs*
on the next host to follow the attacker across the network - instead of investigating every host
blindly and merging at the end. It implements the SANS DFIR **Incident Response Detection &
Intelligence Loop**: *detect → triage host → extract IOCs → sweep the next host → repeat.*

> **Execution is strictly sequential** (one host at a time - RAM-bound). This is not a limitation:
> a pivot is inherently sequential because each host's hunt is *seeded by* the previous host's output.

---

## What is automated vs. analyst tradecraft

| Layer | Provided by the framework | Performed by the analyst (agent) |
|---|---|---|
| Per-host isolation | `SAVVYDFIR_ANALYSIS_DIR` → separate state/findings/audit per host | choose host order |
| IOC capture | findings carry **prefixed** `supporting_indicators` | emit correct prefixes (or the graph is empty) |
| Hypothesis seeding | `record_hypotheses(initial_pivot=...)` | read Host A's report, seed Host B's hunt |
| Cross-host graph | `merge_host_graphs` draws `lateral_movement` / `shared_ioc` / `shared_account` edges | confirm each hop before claiming movement |

**The pivot itself - reading Host A's IOCs and hunting them on Host B - is the agent's job between
sessions. The framework validates and visualizes it afterward; it does not perform the pivot.**

---

## Host order (SRL-2018 "CRIMSON OSPREY", 5 hosts)

**Recommended: kill-chain-forward with a per-host detection gate.**

```
DMZ-FTP (disk only) → WKSTN-01 → RD-01 (pivot hub) → FILE → DC (crown jewel)
```

At the **start of each host**, run a cheap detection gate (`summarize_evtx` + `sigma_hunt`) *before*
deep mining. This gives detection-driven triage without a wasteful separate 5-host pre-sweep - each
host's sigma gate feeds both that host's deep-dive and its carry package.

- **DMZ-FTP first** = internet-facing perimeter / likely initial access + cleanest chronological
  narrative. It is disk-only (no memory) - record `data_gaps: ["no_memory_capture"]`; "no C2 in memory"
  is *not observable*, not *absent*.
- If DMZ-FTP triage is thin, treat **WKSTN-01** as the patient-zero candidate.
- Alternative (if perimeter is empty): anchor on **RD-01** (pivot hub, strongest lateral signal) and
  pivot backward ("how did they get here") + outward ("blast radius").

---

## Highest-value pivot IOCs (ranked, Windows AD)

1. **Accounts** - `domain\user`, service accounts, newly created / "sleeper" accounts. Strongest cross-host tie.
2. **Auth pairs** - 4624/4648, Kerberos 4769 (RC4 downgrade `0x17`), NTLM 4776, with source IP + logon type.
3. **Tool hashes / names** - Amcache SHA-1, dropped-binary paths (survive hostname changes).
4. **Service / scheduled-task names** - `PSEXESVC`, randomized 7-10-char service names, persistence that travels.
5. **Named pipes** - Cobalt Strike `\Device\NamedPipe\MSSE-####-server`, WinRM/WMI markers.
6. **C2 IPs / domains** - useful but **over-shared**; never pivot on an IP alone.
7. **Timestamps** - bounding windows for sweeping concurrent activity, not standalone IOCs.

---

## Proving a pivot edge (paired artifacts + aligned timestamps)

A shared IOC is a **lead**, not proof. Confirm movement with ≥2 independent artifacts showing
**mechanism + direction + same time window**:

| Technique | Originating host | Target host |
|---|---|---|
| Explicit-credential hop | **EID 4648** (records the destination host/IP) | **4624 Type 3** + **5140** (share access) |
| RDP hop | **TerminalServices-RDPClient 1024/1102** (destination) | **4624 Type 10** / **4778/4779** |
| SMB file copy | source file's M-time | target file **M-time < B-time** + **4624 Type 3** in window |
| Remote service exec | - | **7045** service install + **4688/Sysmon 1** in window |

Shared account alone → `shared_account` edge. Upgrade to `lateral_movement` (finding_type TA0008)
only with the paired evidence above on *both* hosts.

---

## Per-host loop

1. `start_investigation` (isolated analysis dir for this host).
2. `record_hypotheses(initial_pivot=<prior-host IOCs>, status=ACTIVE)` - cite the prior host's F-IDs.
   **Before** mining, so the chain is auditable, not hindsight.
3. **Detection gate:** `summarize_evtx` + `sigma_hunt`.
4. **Full mandatory stack:** memory suite (where memory exists) + disk baseline + `detect_injection`
   + `compare_disk_and_memory`. Run these *regardless of the carry list* - anti-tunnel-vision.
5. **Hunt budget - 80 / 20:** 80% of `run_analysis` queries hunt the carried IOCs; 20% reserved for
   host-local outliers (loudest sigma hits, SRUM volume spikes, injection flags not in the carry list).
6. **Confirm hops** with paired-artifact mechanism evidence → `submit_finding` with prefixed
   `supporting_indicators` (account:/ip:/hash:/executable:/path:/owner_process:/timestamp:/value_data:)
   and `corroborated_by=[upstream F-IDs]`.
7. **Resolve hypotheses:** flip each to CONFIRMED / REFUTED / SUSPENDED. Record carried IOCs that were
   **hunted but not found** - a clean miss is evidence and may redirect the chain.
8. `generate_report` + `generate_graph`. Delete the host's memory `.raw` (and E01) to reclaim space.
9. Carry the new IOC package forward → next host.

After all 5: `merge_host_graphs` + `build_reports_index` - the cross-host graph validates the chain
and catches any link the sequential pass missed (the finish-line photo, not the investigation).

---

## Pitfalls & guards

| Pitfall | Guard |
|---|---|
| **Tunnel vision** (only hunting carried IOCs) | 80/20 query budget; always run `detect_injection` + `compare_disk_and_memory`; DFIR temporal-proximity + least-frequency stacking for host-local discovery |
| **Confirmation bias** (shared account = movement) | require mechanism + direction (4648/4624+5140 etc.), not a name match |
| **Clock skew** | normalize UTC; check System EID 1 boot time per host; ±5 min cross-host windows, not ±10 s; document skew |
| **Shared IOC ≠ lateral movement** | `shared_ioc` edge unless paired-artifact corroboration on both hosts |
| **Jump-host noise (RD-01)** | filter to carried account + source IP + time window first, then expand |
| **Disk-only blind spot (DMZ-FTP)** | record `data_gaps`; conclude "not observable", never "absent" |
| **Hindsight pivot** | `record_hypotheses(status=ACTIVE)` before mining; flip after |

---

*Sources: SANS DFIR (IR Detection & Intelligence Loop) + independent IR review. Methodology is
executable with existing framework tools - no gate changes required.*
