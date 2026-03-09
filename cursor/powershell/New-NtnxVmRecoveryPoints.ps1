#Requires -Version 7.0
<#
.SYNOPSIS
    Creates VM recovery points for VMs specified by file, single name, or category.
.DESCRIPTION
    VMs can be specified in one of three ways: a text file (one VM name per line), a single
    VM name (-VmName), or a category key:value pair (-Category, e.g. "env:prod") to include
    all VMs that have that category. Resolves to extIds via the VMM AHV API, then creates
    one or more Data Protection recovery points (batches of up to 30 VMs) with configurable
    expiration in days. Supports -WhatIf.
    Each recovery point can contain up to 30 VMs; you can still restore a single VM or any
    subset from a recovery point via the Nutanix restore API.
.EXAMPLE
    .\New-NtnxVmRecoveryPoints.ps1 -PrismCentral 'myprism.domain.local' -VmListPath '.\vms.txt'
    Creates recovery points for VMs listed in vms.txt; expiration default 2 days.
.EXAMPLE
    .\New-NtnxVmRecoveryPoints.ps1 -PrismCentral 'myprism.domain.local' -VmName 'my-vm-01'
    Creates a recovery point for the single VM named my-vm-01.
.EXAMPLE
    .\New-NtnxVmRecoveryPoints.ps1 -PrismCentral 'myprism.domain.local' -Category 'env:production'
    Creates recovery points for all VMs that have category env=production.
.EXAMPLE
    .\New-NtnxVmRecoveryPoints.ps1 -PrismCentral 'myprism.domain.local' -VmListPath '.\vms.txt' -ExpirationDays 5 -Verbose
    Recovery points expire 5 days from now; verbose logging.
.EXAMPLE
    .\New-NtnxVmRecoveryPoints.ps1 -PrismCentral 'myprism.domain.local' -VmListPath '.\vms.txt' -WhatIf
    Shows what would be created without calling the API.
.EXAMPLE
    .\New-NtnxVmRecoveryPoints.ps1 -PrismCentral 'myprism.domain.local' -VmListPath '.\vms.txt' -RecoveryPointNamePrefix 'PreUpgrade'
    Uses recovery point names like PreUpgrade_20250309_143022_batch1.
.EXAMPLE
    .\New-NtnxVmRecoveryPoints.ps1 -PrismCentral 'myprism.domain.local' -VmListPath '.\vms.txt' -PollIntervalSec 10
    Creates recovery points and polls task status every 10s until each completes or fails (default).
.EXAMPLE
    .\New-NtnxVmRecoveryPoints.ps1 -PrismCentral 'myprism.domain.local' -VmListPath '.\vms.txt' -NoWait
    Submits create requests and returns immediately without waiting for task completion.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'File')]
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'Vm')]
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'Category')]
    [string]$PrismCentral,
    [Parameter(Mandatory, ParameterSetName = 'File')]
    [string]$VmListPath,
    [Parameter(Mandatory, ParameterSetName = 'Vm')]
    [string]$VmName,
    [Parameter(Mandatory, ParameterSetName = 'Category')]
    [string]$Category,
    [int]$ExpirationDays = 2,
    [string]$RecoveryPointNamePrefix = 'ScriptRP',
    [string]$Username,
    [PSCredential]$Credential,
    [int]$TimeoutSec = 60,
    [switch]$NoWait,
    [int]$PollIntervalSec = 15,
    [int]$TaskTimeoutSec = 3600
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:DEFAULT_TIMEOUT_SEC = 60
$script:MAX_RETRIES = 3
$script:PAGE_LIMIT = 100
$script:MAX_VMS_PER_RECOVERY_POINT = 30
$script:TASK_STATUS_TERMINAL_SUCCESS = 'SUCCEEDED'
$script:TASK_STATUS_TERMINAL_FAILURE = @('FAILED', 'CANCELED', 'SUSPENDED')

function Write-NtnxConsoleLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'FATAL')]
        [string]$Severity,
        [Parameter(Mandatory)]
        [string]$Message,
        [string]$Target = '',
        [string]$RequestId = ''
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $targetStr = if ($Target) { " Target=$Target" } else { '' }
    $requestStr = if ($RequestId) { " RequestId=$RequestId" } else { '' }
    $line = "[$timestamp] [$Severity] $Message$targetStr$requestStr"
    $color = switch ($Severity) {
        'INFO'    { [ConsoleColor]::Cyan }
        'WARNING' { [ConsoleColor]::Yellow }
        'ERROR'   { [ConsoleColor]::Red }
        'FATAL'   { [ConsoleColor]::DarkRed }
        default   { [ConsoleColor]::Gray }
    }
    Write-Host $line -ForegroundColor $color
}

function Write-NtnxLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'FATAL')]
        [string]$Severity,
        [Parameter(Mandatory)]
        [string]$Message,
        [string]$Target = '',
        [string]$RequestId = ''
    )
    $timestamp = [DateTime]::UtcNow.ToString('o')
    $targetStr = if ($Target) { " Target=$Target" } else { '' }
    $requestStr = if ($RequestId) { " RequestId=$RequestId" } else { '' }
    $verboseLine = "[$timestamp] [$Severity] $Message$targetStr$requestStr"
    Write-Verbose $verboseLine
    $consoleSeverity = if ($Severity -eq 'WARN') { 'WARNING' } else { $Severity }
    Write-NtnxConsoleLog -Severity $consoleSeverity -Message $Message -Target $Target -RequestId $RequestId
    if ($Severity -eq 'ERROR' -or $Severity -eq 'FATAL') { Write-Error $Message -ErrorAction Continue }
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

function Get-NtnxTaskStatusUntilTerminal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BaseUri,
        [Parameter(Mandatory)]
        [hashtable]$Headers,
        [Parameter(Mandatory)]
        [string]$TaskExtId,
        [string]$RecoveryPointName = '',
        [int]$PollIntervalSec = 15,
        [int]$TaskTimeoutSec = 3600,
        [int]$TimeoutSec = 60
    )
    $progressId = 1
    $startTime = [DateTime]::UtcNow
    $taskUri = "${BaseUri}/prism/v4.0/config/tasks/$TaskExtId"
    $activity = if ($RecoveryPointName) { "Recovery point: $RecoveryPointName" } else { 'Recovery point task' }
    try {
        while ($true) {
            $elapsed = ([DateTime]::UtcNow - $startTime).TotalSeconds
            if ($elapsed -ge $TaskTimeoutSec) {
                Write-Progress -Id $progressId -Activity $activity -Completed
                return [PSCustomObject]@{
                    Status      = 'TIMEOUT'
                    ErrorMessage = "Task did not complete within $TaskTimeoutSec seconds."
                }
            }
            $invokeParams = @{
                Uri        = $taskUri
                Method     = 'GET'
                Headers    = $Headers
                TimeoutSec = $TimeoutSec
            }
            try {
                $response = Invoke-NtnxRestWithRetry -InvokeParams $invokeParams -RequestId $TaskExtId
            }
            catch {
                Write-Progress -Id $progressId -Activity $activity -Completed
                return [PSCustomObject]@{
                    Status      = 'ERROR'
                    ErrorMessage = "Failed to get task status: $($_.Exception.Message)"
                }
            }
            $taskData = $response.data
            $status = $null
            $progressPct = -1
            if ($taskData) {
                if ($taskData.PSObject.Properties['status']) { $status = $taskData.status }
                if ($taskData.PSObject.Properties['progressPercentage'] -and $null -ne $taskData.progressPercentage) {
                    $progressPct = [int]$taskData.progressPercentage
                }
            }
            $statusText = if ($status) { $status } else { 'Unknown' }
            $elapsedStr = [Math]::Floor($elapsed).ToString()
            $statusMsg = "Status: $statusText | Elapsed: ${elapsedStr}s / ${TaskTimeoutSec}s"
            Write-Progress -Id $progressId -Activity $activity -Status $statusMsg -PercentComplete $progressPct

            if ($status -eq $script:TASK_STATUS_TERMINAL_SUCCESS) {
                Write-Progress -Id $progressId -Activity $activity -Status 'Completed successfully' -PercentComplete 100
                Write-Progress -Id $progressId -Activity $activity -Completed
                $errMsg = ''
                if ($taskData.PSObject.Properties['errorMessages'] -and $taskData.errorMessages -and $taskData.errorMessages.Count -gt 0) {
                    $errMsg = ($taskData.errorMessages | ForEach-Object { if ($_ -is [string]) { $_ } else { $_.message } }) -join '; '
                }
                return [PSCustomObject]@{
                    Status      = $status
                    ErrorMessage = $errMsg
                }
            }
            if ($status -in $script:TASK_STATUS_TERMINAL_FAILURE) {
                Write-Progress -Id $progressId -Activity $activity -Completed
                $errMsg = ''
                if ($taskData.PSObject.Properties['errorMessages'] -and $taskData.errorMessages -and $taskData.errorMessages.Count -gt 0) {
                    $errMsg = ($taskData.errorMessages | ForEach-Object { if ($_ -is [string]) { $_ } else { $_.message } }) -join '; '
                }
                if (-not $errMsg) { $errMsg = "Task ended with status: $status" }
                return [PSCustomObject]@{
                    Status      = $status
                    ErrorMessage = $errMsg
                }
            }
            Start-Sleep -Seconds $PollIntervalSec
        }
    }
    finally {
        Write-Progress -Id $progressId -Activity $activity -Completed -ErrorAction SilentlyContinue
    }
}

function New-NtnxVmRecoveryPoints {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PrismCentral,
        [string]$VmListPath,
        [string]$VmName,
        [string]$Category,
        [int]$ExpirationDays = 2,
        [string]$RecoveryPointNamePrefix = 'ScriptRP',
        [string]$Username,
        [PSCredential]$Credential,
        [int]$TimeoutSec = $script:DEFAULT_TIMEOUT_SEC,
        [switch]$NoWait,
        [int]$PollIntervalSec = 15,
        [int]$TaskTimeoutSec = 3600
    )
    $waitForCompletion = -not $NoWait

    Write-NtnxConsoleLog -Severity INFO -Message "Starting New-NtnxVmRecoveryPoints (Prism Central: $PrismCentral, Expiration: $ExpirationDays day(s))."

    $hostPart = $PrismCentral.Trim() -replace '^https?://', ''
    $baseUri = "https://${hostPart}:9440/api"

    # Exactly one of VmListPath, VmName, or Category must be specified
    $hasFile = [bool]($VmListPath -and $VmListPath.Trim().Length -gt 0)
    $hasVm = [bool]($VmName -and $VmName.Trim().Length -gt 0)
    $hasCat = [bool]($Category -and $Category.Trim().Length -gt 0)
    $count = ([int]$hasFile) + ([int]$hasVm) + ([int]$hasCat)
    if ($count -ne 1) {
        Write-NtnxLog -Severity ERROR -Message "Specify exactly one of: -VmListPath, -VmName, or -Category."
        throw "Specify exactly one of: -VmListPath, -VmName, or -Category."
    }

    # Credentials and headers (needed for all paths)
    if (-not $Credential) {
        if ($Username) {
            $Credential = Get-Credential -UserName $Username -Message 'Prism Central (Create Recovery Point)'
        } else {
            $Credential = Get-Credential -Message 'Prism Central (Create Recovery Point)'
        }
    }
    $pair = "$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($pair)
    $base64 = [Convert]::ToBase64String($bytes)
    $headers = @{
        'Content-Type'   = 'application/json'
        'Accept'         = 'application/json'
        'Authorization'  = "Basic $base64"
    }

    $resolvedExtIds = [System.Collections.Generic.List[string]]::new()
    $vmCountRequested = 0
    $vmCountResolved = 0

    if ($hasCat) {
        # Category path: key:value (e.g. "env:production") -> find category extId, list VMs with categories, filter
        $catPart = $Category.Trim()
        $colonIdx = $catPart.IndexOf(':')
        if ($colonIdx -lt 0) {
            Write-NtnxLog -Severity ERROR -Message "Category must be in key:value format (e.g. env:production)."
            throw "Category must be in key:value format (e.g. env:production)."
        }
        $categoryKey = $catPart.Substring(0, $colonIdx).Trim()
        $categoryValue = $catPart.Substring($colonIdx + 1).Trim()
        if ($categoryKey.Length -eq 0 -or $categoryValue.Length -eq 0) {
            Write-NtnxLog -Severity ERROR -Message "Category key and value must be non-empty (key:value)."
            throw "Category key and value must be non-empty (key:value)."
        }
        Write-NtnxLog -Severity INFO -Message "Resolving VMs by category '$categoryKey'='$categoryValue'" -Target 'category'

        # Fetch Prism categories (paginate) and find extId for this key:value
        $categoryExtId = $null
        $page = 0
        do {
            $categoriesUri = "${baseUri}/prism/v4.0/config/categories?`$page=$page&`$limit=$script:PAGE_LIMIT"
            $invokeParams = @{ Uri = $categoriesUri; Method = 'GET'; Headers = $headers; TimeoutSec = $TimeoutSec }
            $catResponse = Invoke-NtnxRestWithRetry -InvokeParams $invokeParams
            $data = $catResponse.data
            if ($data -and $data.Count -gt 0) {
                foreach ($c in $data) {
                    if ($c.extId -and $null -ne $c.key -and $null -ne $c.value) {
                        if ($c.key -eq $categoryKey -and $c.value -eq $categoryValue) {
                            $categoryExtId = $c.extId
                            break
                        }
                    }
                }
            }
            $page++
        } while ($data -and $data.Count -eq $script:PAGE_LIMIT -and -not $categoryExtId)

        if (-not $categoryExtId) {
            Write-NtnxLog -Severity ERROR -Message "No category found with key='$categoryKey' and value='$categoryValue'." -Target 'category'
            throw "No category found with key='$categoryKey' and value='$categoryValue'."
        }

        # Fetch AHV VMs with extId, name, categories; filter those that have this category extId
        $page = 0
        $select = [uri]::EscapeDataString('extId,name,categories')
        do {
            $vmsUri = "${baseUri}/vmm/v4.0/ahv/config/vms?`$page=$page&`$limit=$script:PAGE_LIMIT&`$select=$select"
            Write-NtnxLog -Severity INFO -Message "Fetching VMs page $page" -Target 'vms'
            $invokeParams = @{ Uri = $vmsUri; Method = 'GET'; Headers = $headers; TimeoutSec = $TimeoutSec }
            $vmResponse = Invoke-NtnxRestWithRetry -InvokeParams $invokeParams
            $data = $vmResponse.data
            if ($data -and $data.Count -gt 0) {
                foreach ($vm in $data) {
                    $extId = if ($vm.extId) { $vm.extId } else { $null }
                    if (-not $extId) { continue }
                    $cats = $null
                    if ($vm.PSObject.Properties['categories']) { $cats = $vm.categories }
                    if ($cats) {
                        foreach ($ref in $cats) {
                            if ($ref.extId -eq $categoryExtId) {
                                $resolvedExtIds.Add($extId)
                                break
                            }
                        }
                    }
                }
            }
            $page++
        } while ($data -and $data.Count -eq $script:PAGE_LIMIT)

        $vmCountRequested = $vmCountResolved = $resolvedExtIds.Count
        Write-NtnxLog -Severity INFO -Message "Found $vmCountResolved VM(s) with category '$categoryKey'='$categoryValue'" -Target 'category'
        if ($vmCountResolved -eq 0) {
            Write-NtnxLog -Severity ERROR -Message "No VMs have category '$categoryKey'='$categoryValue'." -Target 'category'
            throw "No VMs have category '$categoryKey'='$categoryValue'."
        }
    }
    else {
        # File or single VM name: get requested names then resolve by name
        $requestedNames = [System.Collections.Generic.List[string]]::new()
        if ($hasFile) {
            $vmListFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($VmListPath)
            if (-not (Test-Path -LiteralPath $vmListFullPath -PathType Leaf)) {
                Write-NtnxLog -Severity ERROR -Message "VM list file not found: $vmListFullPath"
                throw "VM list file not found: $VmListPath"
            }
            foreach ($line in [System.IO.File]::ReadAllLines($vmListFullPath)) {
                $trimmed = $line.Trim()
                if ($trimmed.Length -gt 0) { $requestedNames.Add($trimmed) }
            }
            if ($requestedNames.Count -eq 0) {
                Write-NtnxLog -Severity ERROR -Message "VM list file is empty or has no non-empty lines: $VmListPath"
                throw "VM list file has no VM names: $VmListPath"
            }
            Write-NtnxLog -Severity INFO -Message "Read $($requestedNames.Count) VM name(s) from $VmListPath" -Target 'VmListPath'
        }
        else {
            $requestedNames.Add($VmName.Trim())
            Write-NtnxLog -Severity INFO -Message "Single VM name: $VmName" -Target 'VmName'
        }
        $vmCountRequested = $requestedNames.Count

        # Build name -> list of extIds from cluster
        $nameToExtIds = @{}
        $page = 0
        $select = [uri]::EscapeDataString('extId,name')
        do {
            $vmsUri = "${baseUri}/vmm/v4.0/ahv/config/vms?`$page=$page&`$limit=$script:PAGE_LIMIT&`$select=$select"
            Write-NtnxLog -Severity INFO -Message "Fetching VMs page $page" -Target 'vms'
            $invokeParams = @{ Uri = $vmsUri; Method = 'GET'; Headers = $headers; TimeoutSec = $TimeoutSec }
            $vmResponse = Invoke-NtnxRestWithRetry -InvokeParams $invokeParams
            $data = $vmResponse.data
            if ($data -and $data.Count -gt 0) {
                foreach ($vm in $data) {
                    $name = if ($vm.name) { $vm.name } else { '' }
                    $extId = if ($vm.extId) { $vm.extId } else { $null }
                    if (-not $extId) { continue }
                    if (-not $nameToExtIds.ContainsKey($name)) {
                        $nameToExtIds[$name] = [System.Collections.Generic.List[string]]::new()
                    }
                    $nameToExtIds[$name].Add($extId)
                }
            }
            $page++
        } while ($data -and $data.Count -eq $script:PAGE_LIMIT)

        $missingNames = [System.Collections.Generic.List[string]]::new()
        $ambiguousNames = [System.Collections.Generic.List[string]]::new()
        foreach ($name in $requestedNames) {
            if (-not $nameToExtIds.ContainsKey($name)) {
                $missingNames.Add($name)
                continue
            }
            $extIds = $nameToExtIds[$name]
            if ($extIds.Count -gt 1) {
                if ($ambiguousNames -notcontains $name) { $ambiguousNames.Add($name) }
                continue
            }
            $resolvedExtIds.Add($extIds[0])
        }

        if ($missingNames.Count -gt 0) {
            $missingList = $missingNames -join ', '
            Write-NtnxLog -Severity ERROR -Message "VM name(s) not found in cluster: $missingList" -Target 'resolution'
            throw "VM name(s) not found in cluster: $missingList"
        }
        if ($ambiguousNames.Count -gt 0) {
            $ambigList = $ambiguousNames -join ', '
            Write-NtnxLog -Severity ERROR -Message "VM name(s) are ambiguous (multiple VMs with same name): $ambigList" -Target 'resolution'
            throw "VM name(s) are ambiguous (multiple VMs with same name): $ambigList"
        }

        $vmCountResolved = $resolvedExtIds.Count
        Write-NtnxLog -Severity INFO -Message "Resolved $vmCountResolved VM(s) to extIds" -Target 'resolution'
    }

    # Expiration time (UTC, ISO-8601)
    $expirationTime = [DateTime]::UtcNow.AddDays($ExpirationDays).ToString('o')
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

    $batchCount = [Math]::Ceiling($resolvedExtIds.Count / $script:MAX_VMS_PER_RECOVERY_POINT)
    Write-NtnxConsoleLog -Severity INFO -Message "Creating $batchCount recovery point(s) for $vmCountResolved VM(s) (expiration: $ExpirationDays day(s))."

    # Batch into chunks of 30
    $batches = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $resolvedExtIds.Count; $i += $script:MAX_VMS_PER_RECOVERY_POINT) {
        $end = [Math]::Min($i + $script:MAX_VMS_PER_RECOVERY_POINT, $resolvedExtIds.Count)
        $chunk = $resolvedExtIds.GetRange($i, $end - $i)
        $batches.Add($chunk)
    }
    $batchCount = $batches.Count

    $recoveryPointNames = [System.Collections.Generic.List[string]]::new()
    $taskIds = [System.Collections.Generic.List[string]]::new()
    $taskResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    for ($b = 0; $b -lt $batches.Count; $b++) {
        $batch = $batches[$b]
        $batchIndex = $b + 1
        $rpName = if ($batchCount -gt 1) {
            "${RecoveryPointNamePrefix}_${timestamp}_batch${batchIndex}"
        } else {
            "${RecoveryPointNamePrefix}_${timestamp}"
        }
        $recoveryPointNames.Add($rpName)

        $vmRecoveryPoints = @($batch | ForEach-Object { @{ vmExtId = $_ } })
        $bodyObj = @{
            name             = $rpName
            expirationTime   = $expirationTime
            vmRecoveryPoints = $vmRecoveryPoints
        }
        $bodyJson = $bodyObj | ConvertTo-Json -Depth 10 -Compress

        $targetDescription = "Recovery point '$rpName' ($($batch.Count) VM(s))"
        if ($PSCmdlet.ShouldProcess($targetDescription, 'Create')) {
            $requestId = (New-Guid).ToString()
            $postHeaders = $headers.Clone()
            $postHeaders['NTNX-Request-Id'] = $requestId
            $createUri = "${baseUri}/dataprotection/v4.0/config/recovery-points"
            Write-NtnxLog -Severity INFO -Message "Creating recovery point '$rpName'" -Target $rpName -RequestId $requestId
            $invokeParams = @{
                Uri        = $createUri
                Method     = 'POST'
                Headers    = $postHeaders
                Body       = $bodyJson
                TimeoutSec = $TimeoutSec
            }
            try {
                $response = Invoke-NtnxRestWithRetry -InvokeParams $invokeParams -RequestId $requestId
                $taskId = $null
                if ($response.data -and $response.data.PSObject.Properties['extId']) {
                    $taskId = $response.data.extId
                }
                if ($taskId) {
                    $taskIds.Add($taskId)
                    Write-NtnxLog -Severity INFO -Message "Created recovery point '$rpName', task extId=$taskId" -Target $rpName -RequestId $taskId
                    if ($waitForCompletion) {
                        Write-NtnxLog -Severity INFO -Message "Waiting for task $taskId to complete (poll every ${PollIntervalSec}s, timeout ${TaskTimeoutSec}s)" -Target $rpName
                        $pollResult = Get-NtnxTaskStatusUntilTerminal -BaseUri $baseUri -Headers $headers -TaskExtId $taskId `
                            -RecoveryPointName $rpName -PollIntervalSec $PollIntervalSec -TaskTimeoutSec $TaskTimeoutSec -TimeoutSec $TimeoutSec
                        $taskResults.Add([PSCustomObject]@{
                                TaskId           = $taskId
                                RecoveryPointName = $rpName
                                Status           = $pollResult.Status
                                ErrorMessage     = $pollResult.ErrorMessage
                            })
                        if ($pollResult.Status -eq $script:TASK_STATUS_TERMINAL_SUCCESS) {
                            Write-NtnxLog -Severity INFO -Message "Task $taskId completed successfully" -Target $rpName -RequestId $taskId
                        } else {
                            Write-NtnxLog -Severity ERROR -Message "Task $taskId ended with status $($pollResult.Status): $($pollResult.ErrorMessage)" -Target $rpName -RequestId $taskId
                        }
                    }
                }
            }
            catch {
                Write-NtnxLog -Severity ERROR -Message "Failed to create recovery point '$rpName': $($_.Exception.Message)" -Target $rpName
                throw
            }
        }
        else {
            Write-NtnxLog -Severity INFO -Message "WhatIf: would create recovery point '$rpName' with $($batch.Count) VM(s)" -Target $rpName
        }
    }

    $succeeded = ($taskResults | Where-Object { $_.Status -eq $script:TASK_STATUS_TERMINAL_SUCCESS }).Count
    if ($WhatIfPreference) {
        Write-NtnxConsoleLog -Severity INFO -Message "WhatIf complete. Would create $batchCount recovery point(s) for $vmCountResolved VM(s)."
    } elseif ($taskResults.Count -gt 0) {
        Write-NtnxConsoleLog -Severity INFO -Message "Complete. $succeeded of $($taskResults.Count) task(s) succeeded."
    } else {
        Write-NtnxConsoleLog -Severity INFO -Message "Complete. $batchCount recovery point(s) submitted (task IDs returned; use -NoWait to skip waiting)."
    }

    $result = [PSCustomObject]@{
        VmCountRequested    = $vmCountRequested
        VmCountResolved    = $vmCountResolved
        BatchCount         = $batchCount
        RecoveryPointNames = [string[]]$recoveryPointNames
        TaskIds            = [string[]]$taskIds
        ExpirationTime     = $expirationTime
    }
    if ($taskResults.Count -gt 0) {
        $result | Add-Member -NotePropertyName 'TaskResults' -NotePropertyValue ([PSCustomObject[]]$taskResults)
    }
    if ($WhatIfPreference) {
        $result | Add-Member -NotePropertyName 'WhatIf' -NotePropertyValue $true
    }
    return $result
}

New-NtnxVmRecoveryPoints -PrismCentral $PrismCentral -VmListPath $VmListPath -VmName $VmName -Category $Category `
    -ExpirationDays $ExpirationDays -RecoveryPointNamePrefix $RecoveryPointNamePrefix -Username $Username -Credential $Credential -TimeoutSec $TimeoutSec `
    -NoWait:$NoWait -PollIntervalSec $PollIntervalSec -TaskTimeoutSec $TaskTimeoutSec
