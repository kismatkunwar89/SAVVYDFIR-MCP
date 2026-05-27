# Research Sources

Last updated: 2026-04-03

This file captures the external sources used to shape the FIND EVIL! submission plan for this repository.

## 1. FIND EVIL! Hackathon Overview

- URL: https://findevil.devpost.com/
- Why it matters:
  Defines the challenge mission, timeline, supported approaches, submission requirements, judging criteria, and prizes.
- Key takeaways used in planning:
  - The event runs from April 15, 2026 to June 15, 2026.
  - The mission is to build autonomous AI defenders on SIFT inspired by Protocol SIFT.
  - The project should teach the agent to sequence work, detect when something is wrong, and self-correct.
  - The custom MCP server pattern is explicitly called out as the strongest architecture in evaluation.
  - The submission must include all eight required components.
  - Judging prioritizes autonomous execution quality, IR accuracy, constraints, audit trail quality, and usability.
- Relevant sections:
  - Mission and challenge framing: lines 138-159 on the Devpost overview page
  - Supported approaches and starter ideas: lines 179-200 on the Devpost overview page
  - Submission requirements: lines 203-216 on the Devpost overview page
  - Judging criteria: lines 268-280 on the Devpost overview page

## 2. SANS SIFT Workstation Download Link

- URL: https://www.sans.org/tools/sift-workstation
- Why it matters:
  This is the official SIFT workstation reference linked from the hackathon overview as the target platform for local reproduction and judge setup.
- Key takeaway used in planning:
  - Try-it-out instructions should assume judges may run the project against the downloadable SIFT workstation environment.

## 3. Protocol SIFT Install Reference Mentioned by the Hackathon

- URL: https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh
- Why it matters:
  The hackathon overview explicitly points participants to this installer as the starter path for demonstrating automated analysis on SIFT.
- Key takeaway used in planning:
  - The project should be positioned as a focused improvement on top of the Protocol SIFT direction rather than a disconnected standalone concept.
- Note:
  - I was able to confirm the link is referenced from the official Devpost page, but I was not able to retrieve and inspect the installer contents directly in this session.

## 4. teamdfir/sift GitHub Repository

- URL: https://github.com/teamdfir/sift
- Why it matters:
  This is the public TeamDFIR SIFT repository and is useful as the public code and community reference point around SIFT packaging and related ecosystem context.
- Key takeaway used in planning:
  - Keep project setup and instructions aligned with the SIFT ecosystem instead of assuming a generic Linux environment.

## 5. SANS Whitepaper Referencing SIFT Workflow Value

- URL: https://www.sans.org/white-papers/35512/
- Why it matters:
  This whitepaper describes the SIFT workstation as a powerful but labor-intensive artisan toolkit and argues for automation of repetitive investigative tasks.
- Key takeaway used in planning:
  - The strongest project framing is not “replace analysts,” but “automate repetitive investigative steps so analysts can work faster and more consistently.”

## Planning Inference Notes

The following recommendations in `PLAN.md` are inferences based on the sources above plus the current repo contents:

- Narrowing scope to memory triage is a strategy recommendation, not an explicit hackathon requirement.
- Prioritizing structured logs before frontend polish is a scoring-driven recommendation based on the judging criteria.
- Treating the graph UI as secondary to traceability is an inference from the judging categories, which emphasize autonomous execution, accuracy, constraints, and audit trail quality over presentation.
- Building around typed, read-only MCP tools is directly aligned with the challenge’s custom MCP server description, but the exact tool list in `PLAN.md` is my proposed implementation, not a quoted requirement.
