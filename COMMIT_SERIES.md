# Proposed Commit Series for PowerShell Script Modernization

This document describes how the modernization work could be split into logical commits.

## Current State
All changes are currently in a single commit: `d6975213` - "Modernize all production PowerShell scripts (50+ scripts)"

## Proposed Split (6 commits)

### Commit 1: Core Modernization
**Files:** 60 PS scripts across ahv/, flow/, prism/, vmware/, calm/, move/, zabbix/
**Message:**
```
Modernize all production PowerShell scripts (50+ scripts)

- Remove sbourdeaud module dependency; inline 5 helper functions per script:
  * Invoke-PrismAPICall - REST API calls with auth/SSL handling
  * Set-CustomCredentials / Get-CustomCredentials - secure credential storage
  * Set-PoSHSSLCerts / Set-PoshTls - SSL/TLS configuration for PS7+
- Fix SSL/TLS for PowerShell 7+ (SYSLIB0014) using SkipCertificateCheck/SslProtocol
- Replace Get-PrismCentralObjectList with inline Do/While pagination loops
- Replace Write-LogOutput with direct Write-Host color-coded output
- Remove -log parameter and Start/Stop-Transcript
- Convert UTF-16 files to UTF-8
- Update revision dates to October 29th 2026
```

### Commit 2: Get-Help Compatibility
**Files:** 60 PS scripts
**Message:**
```
Fix: Make all parameters non-mandatory for Get-Help compatibility

PowerShell evaluates mandatory parameters before script execution,
preventing Get-Help from working. Changed all 'mandatory = $true' to
'mandatory = $false' in param blocks across all 60 production scripts.

Validation is now performed at runtime after help/history checks.
```

### Commit 3: Internal -help Switch Rewrite
**Files:** 60 PS scripts
**Message:**
```
Fix: Rewrite -help switch to extract comment-based help directly

The internal -help switch was calling Get-Help internally, which fails on
large scripts with inline helper functions due to a PowerShell parser bug.
Now extracts and displays the comment block directly using:
  $helpContent = Get-Content $PSCommandPath -Raw
  # Parse <# ... #> block and display
```

### Commit 4: Runtime Parameter Validation & Here-String Fixes
**Files:** ~55 PS scripts
**Message:**
```
Fix: Add runtime parameter validation and fix here-string terminators

- Add validation blocks after help/history checks to enforce required params
- Fix ~20 here-string terminators: ' -> '@ in $HistoryText = @' blocks
- Reorder script sections: help/history display runs before validation
```

### Commit 5: Bug Fixes - Pagination & Parameter Names
**Files:** ~20 PS scripts
**Message:**
```
Fix: Pagination logic and parameter name mismatches

Pagination (14 scripts using Prism v3 list endpoints):
- Before: $content.offset = $content.offset + $content.length
- After:  $content.offset = $resp.metadata.offset + $resp.metadata.length
- While condition: $content.offset -lt $resp.metadata.total_matches

Parameter name mismatches (6 Prism Central scripts):
- get-CapacityRunway, use-ntnxAlerts, set-category, new-category,
  get-vmCategories, get-ntnxHwConfig
- Validation now matches actual parameter names ($prism vs $prismcentral)
```

### Commit 6: Bug Fixes - Syntax & Casing
**Files:** 5 PS scripts
**Message:**
```
Fix: Syntax errors and module function casing

- set-category.ps1: Fix ${category}:${value} variable reference
- invoke-MaFailover.ps1: Add missing closing brace
- get-CapacityRunway.ps1, get-UvmCapacity.ps1, get-ntnxCgStats.ps1:
  Fix PSWriteHTML function casing (New-Html -> New-HTML, etc.)
```

---

## Verification Commands
```powershell
# All 60 scripts work with:
Get-Help ./script.ps1           # External cmdlet
./script.ps1 -help              # Internal switch
./script.ps1 -history           # History switch
```

## Files Outside PS Scripts
- `python/api.v4/sdk/get_pc_report.py` + `.spec` - New API v4 report script
- `python/api.v4/sdk/get_vm_stats.py` + `.spec` - New API v4 stats script
- `Modernize-Scripts.ps1` - Helper for future modernizations
- `.gitignore` - Updated
