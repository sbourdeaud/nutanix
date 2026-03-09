#Requires -Version 7.0
<#
.SYNOPSIS
    Exports all AHV VMs and their categories to a CSV with one column per unique category key.
.DESCRIPTION
    Lists VMs via Nutanix VMM v4 API and resolves category extIds to key/value via Prism
    Categories API. Output CSV columns: VmName, VmExtId, then one column per category key
    (no duplicates). Read-only; no cluster state is modified.
.EXAMPLE
    .\Get-NtnxVmCategoriesExport.ps1 -PrismCentral 'myprism.domain.local' -OutputPath '.\vm-categories.csv'
.EXAMPLE
    .\Get-NtnxVmCategoriesExport.ps1 -PrismCentral 'myprism.domain.local' -OutputPath '.\vm-categories.csv' -Username 'admin'
    Prompts securely for password only.
.EXAMPLE
    .\Get-NtnxVmCategoriesExport.ps1 -PrismCentral 'myprism.domain.local' -OutputPath '.\out.csv' -DryRun
#>
param(
    [Parameter(Mandatory)]
    [string]$PrismCentral,
    [string]$OutputPath,
    [string]$Username,
    [PSCredential]$Credential,
    [int]$TimeoutSec = 60,
    [switch]$DryRun
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:DEFAULT_TIMEOUT_SEC = 60
$script:MAX_RETRIES = 3
$script:PAGE_LIMIT = 100

function Write-NtnxLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Severity,
        [Parameter(Mandatory)]
        [string]$Message,
        [string]$Target = '',
        [string]$RequestId = ''
    )
    $timestamp = [DateTime]::UtcNow.ToString('o')
    $targetStr = if ($Target) { " Target=$Target" } else { '' }
    $requestStr = if ($RequestId) { " RequestId=$RequestId" } else { '' }
    $line = "[$timestamp] [$Severity] $Message$targetStr$requestStr"
    Write-Verbose $line
    if ($Severity -eq 'ERROR') { Write-Error $Message -ErrorAction Continue }
}

function Invoke-NtnxRestWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$InvokeParams,
        [int]$MaxRetries = $script:MAX_RETRIES,
        [string]$RequestId = (New-Guid).ToString()
    )
    $attempt = 0
    $delayMs = 1000
    while ($true) {
        try {
            $response = Invoke-RestMethod @InvokeParams
            return $response
        }
        catch {
            $statusCode = $null
            if ($_.Exception -is [System.Net.WebException] -and $_.Exception.Response) {
                try { $statusCode = [int][System.Net.HttpStatusCode]$_.Exception.Response.StatusCode } catch { $statusCode = $null }
            }
            if (($statusCode -in 429, 503) -and ($attempt -lt $MaxRetries)) {
                $attempt++
                Write-NtnxLog -Severity WARN -Message "Transient error (HTTP $statusCode), retry $attempt/$MaxRetries in ${delayMs}ms" -RequestId $RequestId
                Start-Sleep -Milliseconds $delayMs
                $delayMs = [Math]::Min($delayMs * 2, 30000)
                continue
            }
            Write-NtnxLog -Severity ERROR -Message "API call failed: $($_.Exception.Message)" -RequestId $RequestId
            throw
        }
    }
}

function Get-NtnxVmCategoriesExport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PrismCentral,
        [string]$OutputPath,
        [string]$Username,
        [PSCredential]$Credential,
        [int]$TimeoutSec = $script:DEFAULT_TIMEOUT_SEC,
        [switch]$DryRun
    )

    $hostPart = $PrismCentral.Trim() -replace '^https?://', ''
    $baseUri = "https://${hostPart}:9440/api"

    if (-not $OutputPath) {
        $outDir = Join-Path -Path (Get-Location) -ChildPath '.output'
        if (-not (Test-Path -LiteralPath $outDir -PathType Container)) {
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        }
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $pcSafe = $hostPart -replace '[.:/\\]', '_'
        $scriptName = 'Get-NtnxVmCategoriesExport'
        $OutputPath = Join-Path -Path $outDir -ChildPath "${scriptName}_${pcSafe}_${timestamp}.csv"
    }

    if (-not $Credential) {
        if ($Username) {
            $Credential = Get-Credential -UserName $Username -Message 'Prism Central password (read-only for VMM and Categories)'
        } else {
            $Credential = Get-Credential -Message 'Prism Central credentials (read-only for VMM and Categories)'
        }
    }
    $pair = "$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($pair)
    $base64 = [Convert]::ToBase64String($bytes)
    $headers = @{
        'Content-Type' = 'application/json'
        'Accept'       = 'application/json'
        'Authorization' = "Basic $base64"
    }

    # 1) Fetch all categories (Prism) and build extId -> key/value lookup
    $categoryByExtId = @{}
    $page = 0
    $totalCategories = $null
    do {
        $categoriesUri = "${baseUri}/prism/v4.0/config/categories?`$page=$page&`$limit=$script:PAGE_LIMIT"
        Write-NtnxLog -Severity INFO -Message "Fetching categories page $page" -Target 'categories'
        $invokeParams = @{
            Uri         = $categoriesUri
            Method      = 'GET'
            Headers     = $headers
            TimeoutSec  = $TimeoutSec
        }
        $catResponse = Invoke-NtnxRestWithRetry -InvokeParams $invokeParams
        if ($null -eq $catResponse.metadata.totalAvailableResults) {
            $totalCategories = 0
        } else {
            $totalCategories = $catResponse.metadata.totalAvailableResults
        }
        $data = $catResponse.data
        if ($data -and $data.Count -gt 0) {
            foreach ($c in $data) {
                if ($c.extId -and $null -ne $c.key -and $null -ne $c.value) {
                    $categoryByExtId[$c.extId] = @{ key = $c.key; value = $c.value }
                }
            }
        }
        $page++
    } while ($data -and $data.Count -eq $script:PAGE_LIMIT -and ($categoryByExtId.Count -lt $totalCategories))

    Write-NtnxLog -Severity INFO -Message "Fetched $($categoryByExtId.Count) categories" -Target 'categories'

    # 2) Fetch all AHV VMs (VMM) with extId, name, categories
    $allVms = [System.Collections.Generic.List[object]]::new()
    $page = 0
    $select = [uri]::EscapeDataString('extId,name,categories')
    do {
        $vmsUri = "${baseUri}/vmm/v4.0/ahv/config/vms?`$page=$page&`$limit=$script:PAGE_LIMIT&`$select=$select"
        Write-NtnxLog -Severity INFO -Message "Fetching VMs page $page" -Target 'vms'
        $invokeParams = @{
            Uri        = $vmsUri
            Method     = 'GET'
            Headers    = $headers
            TimeoutSec = $TimeoutSec
        }
        $vmResponse = Invoke-NtnxRestWithRetry -InvokeParams $invokeParams
        $data = $vmResponse.data
        if ($data -and $data.Count -gt 0) {
            foreach ($vm in $data) { $allVms.Add($vm) }
        }
        $page++
    } while ($data -and $data.Count -eq $script:PAGE_LIMIT)

    Write-NtnxLog -Severity INFO -Message "Fetched $($allVms.Count) VMs" -Target 'vms'

    # 3) Collect unique category keys (from VMs only) and sort for stable column order
    $uniqueKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($vm in $allVms) {
        $cats = $null
        if ($vm.PSObject.Properties['categories']) { $cats = $vm.categories }
        if ($cats) {
            foreach ($ref in $cats) {
                $extId = $ref.extId
                if ($extId -and $categoryByExtId.ContainsKey($extId)) {
                    [void]$uniqueKeys.Add($categoryByExtId[$extId].key)
                }
            }
        }
    }
    $orderedKeys = $uniqueKeys | Sort-Object

    # 4) Build one row per VM: VmName, VmExtId, then one property per key (first value wins per key)
    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($vm in $allVms) {
        $vmValues = @{}
        $cats = $null
        if ($vm.PSObject.Properties['categories']) { $cats = $vm.categories }
        if ($cats) {
            foreach ($ref in $cats) {
                $extId = $ref.extId
                if (-not $extId -or -not $categoryByExtId.ContainsKey($extId)) { continue }
                $kv = $categoryByExtId[$extId]
                if (-not $vmValues.ContainsKey($kv.key)) {
                    $vmValues[$kv.key] = $kv.value
                }
            }
        }
        $vmName = if ($vm.name) { $vm.name } else { '' }
        $vmExtId = if ($vm.extId) { $vm.extId } else { '' }
        $propHash = [ordered]@{
            VmName  = $vmName
            VmExtId = $vmExtId
        }
        foreach ($k in $orderedKeys) {
            $propHash[$k] = if ($vmValues.ContainsKey($k)) { $vmValues[$k] } else { '' }
        }
        $rows.Add([PSCustomObject]$propHash)
    }

    if ($DryRun) {
        Write-NtnxLog -Severity INFO -Message "DryRun: would write $($rows.Count) rows, $($orderedKeys.Count) category columns to $OutputPath"
        return [PSCustomObject]@{ VmCount = $rows.Count; CategoryKeyCount = $orderedKeys.Count; OutputPath = $OutputPath; DryRun = $true }
    }

    # 5) Export CSV
    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-NtnxLog -Severity INFO -Message "Wrote CSV to $OutputPath ($($rows.Count) rows)" -Target $OutputPath
    return [PSCustomObject]@{ VmCount = $rows.Count; CategoryKeyCount = $orderedKeys.Count; OutputPath = $OutputPath }
}

Get-NtnxVmCategoriesExport -PrismCentral $PrismCentral -OutputPath $OutputPath -Username $Username -Credential $Credential -TimeoutSec $TimeoutSec -DryRun:$DryRun
