# Third-Party Tools, Code & Data — Attribution

SAVVYDFIR-MCP is an orchestration layer. It does **not** reimplement forensic
parsers; it drives best-in-class open-source DFIR tools and adds cross-artifact
correlation, an evidence-provenance gate, and reporting on top. All third-party
work below is the property of its respective authors under its own license. This
project (MIT) claims no ownership over any of it.

## Bundled / vendored in this repo

| File | Upstream source | License | Notes |
|------|-----------------|---------|-------|
| `rules/chainsaw-sigma-mapping.yml` | [WithSecureLabs/chainsaw](https://github.com/WithSecureLabs/chainsaw) — `mappings/sigma-event-logs-all.yml` | **GPL-3.0** | Verbatim copy of Chainsaw's official Sigma→EVTX field mapping, used so `sigma_hunt` matches correctly. Credited here + in the file header. (Alternative: fetch at install time instead of vendoring — see `install.sh`.) |

## Detection / forensic engines invoked at runtime (not bundled)

| Tool | Author / project | License |
|------|------------------|---------|
| Sigma detection rules | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | Detection Rule License (DRL) 1.1 |
| Chainsaw (Sigma over EVTX) | [WithSecureLabs/chainsaw](https://github.com/WithSecureLabs/chainsaw) | GPL-3.0 |
| Hayabusa (Sigma over EVTX) | [Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa) | GPL-3.0 |
| EZ Tools (MFTECmd, PECmd, AmcacheParser, AppCompatCacheParser, EvtxECmd, SBECmd, LECmd, JLECmd, RECmd, SrumECmd, rla.exe) | Eric Zimmerman — [EricZimmerman/...](https://github.com/EricZimmerman) | MIT |
| Volatility 3 | [Volatility Foundation](https://github.com/volatilityfoundation/volatility3) | Volatility Software License (VSL) |
| Plaso / log2timeline | [log2timeline/plaso](https://github.com/log2timeline/plaso) | Apache-2.0 |
| The Sleuth Kit (fls, mmls, icat) | [sleuthkit/sleuthkit](https://github.com/sleuthkit/sleuthkit) | IBM-PL / CPL / GPL (per component) |
| YARA | [VirusTotal/yara](https://github.com/VirusTotal/yara) | BSD-3-Clause |
| libewf (ewfmount), libesedb (esedbexport), libvshadow | Joachim Metz — [libyal](https://github.com/libyal) | LGPL-3.0 |

These ship with the SANS SIFT Workstation; SAVVYDFIR-MCP invokes them as
subprocesses and parses their output. See the SIFT Workstation for its own
licensing/attribution.

## Python dependencies (`requirements.txt`)

`fastmcp` (Apache-2.0), `pydantic` (MIT), `pandas` (BSD-3-Clause),
`tabulate` (MIT), `mitreattack-python` (Apache-2.0/MITRE), `asteval` (MIT),
`pyyaml` (MIT), `claude-code-log` (MIT) — each under its own upstream license.

## Test fixtures / detection validation data

| Use | Source | License |
|-----|--------|---------|
| Known-malicious EVTX for the Sigma positive-control (`scripts/eval/sigma_positive_control.sh`) — **downloaded at test time, not committed** | [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | per upstream |

## Evaluation datasets (public DFIR cases)

Used only to measure accuracy; evidence images are **not** committed (ground-truth
answer keys are gitignored).

| Case | Source |
|------|--------|
| NIST CFReDS — Data Leakage | [cfreds.nist.gov](https://cfreds.nist.gov) (NIST, U.S. Gov — public domain) |
| NIST CFReDS — Hacking Case ("Mr. Evil") | [cfreds-archive.nist.gov/Hacking_Case.html](https://cfreds-archive.nist.gov/Hacking_Case.html) (NIST — public domain) |
| Ali Hadi — Web Server Case (DFIR Challenge #1) | [ashemery.com/dfir.html](https://www.ashemery.com/dfir.html) |
| SANS Realistic Lab (SRL-2018), ROCBA, LONEWOLF | SANS Institute course material (used per course terms; synthetic data) |

ATT&CK® is a registered trademark of The MITRE Corporation.

---
If any attribution here is incomplete or incorrect, please open an issue — it
will be corrected promptly.
