# D.2 Hardcoded IOC Audit Report

**Date**: 2026-05-17  
**Scope**: `sift_mcp/tools/*.py` (all forensic tool modules)  
**Objective**: Verify case-agnostic detection patterns; identify any hardcoded IOCs

## Audit Methodology

Searched for:
- IP addresses (regex: `[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`)
- Hardcoded usernames (admin, administrator, root, guest)
- Suspicious filenames (mimikatz, psexec, specific .exe names)
- Hardcoded hashes (SHA-1, MD5, SHA-256)
- Drive letters and user paths (C:\Users\, D:\, E:\)
- Registry key comparisons (HKEY_*)
- Domain/hostname comparisons
- Port number hardcoding

## Findings

### ✅ PASS: No Environment-Specific IOCs Found

The codebase correctly uses **behavioral patterns** instead of hardcoded IOCs:

1. **Interpreter Detection** (`disk.py:1758-1767`)
   - `_INTERPRETER_BASENAMES` = frozenset of cmd.exe, powershell.exe, rundll32.exe, etc.
   - **Verdict**: Legitimate behavioral detection list (not case-specific)
   - **Rationale**: These are Windows system binaries present across all environments

2. **Localhost Filtering** (`memory.py:1290`)
   - Filters `127.0.0.1` and `::1` from network scan results
   - **Verdict**: Standard practice (not an IOC)
   - **Rationale**: Loopback connections are expected and non-suspicious

3. **Port Classification** (`memory.py:136-148`)
   - Uses RFC port ranges (1-1023, 1024-49151, 49152-65535)
   - **Verdict**: Structural grouping, not hardcoded services
   - **Rationale**: Classifies by well-known/registered/ephemeral buckets

4. **System Path Patterns** (`disk.py:1751-1756`)
   - `_SYSTEM_PREFIXES` = (\windows\system32\, \program files\, etc.)
   - **Verdict**: Universal Windows patterns (not case-specific)
   - **Rationale**: Standard OS directories for clean binary filtering

### References Found (Non-IOC)

- "attacker" in comments/descriptions (9 occurrences) - narrative text only
- "evil.exe" in example comment (`disk.py:3147`) - documentation only
- No actual comparison logic uses these strings

## Recommendations

### ✅ Already Implemented
- Behavioral detection via process parent/child relationships
- Path-based filtering using system directory patterns
- Port classification by RFC ranges
- No environment-specific comparisons

### No Action Required
The codebase is **already case-agnostic** per CLAUDE.md requirements:
> "Case-agnostic: no hardcoded IPs, usernames, or filenames - universal patterns only"

## Conclusion

**Status**: PASS  
**Action**: Document findings (no code changes needed)  
**Commit Message**: "D.2: Hardcoded IOC audit complete - no environment-specific IOCs found"

All detection logic uses behavioral patterns (parent process, logon type, path regex) instead of hardcoded indicators. The framework correctly supports universal investigation workflows across arbitrary environments.
