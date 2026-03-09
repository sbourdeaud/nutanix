# Nutanix PowerShell Scripts

This folder contains PowerShell scripts for Nutanix Prism Central (API v4). Below: **Get-NtnxVmCategoriesExport** (export VM categories to CSV) and **New-NtnxVmRecoveryPoints** (create VM recovery points from a VM list file).

## Table of contents

| Script | Description |
|--------|-------------|
| [Get-NtnxVmCategoriesExport.ps1](#get-ntnxvmcategoriesexportps1) | Export all AHV VMs and their Nutanix categories to CSV. |
| [New-NtnxVmRecoveryPoints.ps1](#new-ntnxvmrecoverypointsps1) | Create VM recovery points from a file, single VM name, or category. |

---

# Get-NtnxVmCategoriesExport.ps1

PowerShell script that exports all AHV virtual machines and their Nutanix categories to a CSV file. Each category key appears as a single column (no duplicates); each row is one VM with its category values.

## Requirements

### Prerequisites

- **PowerShell 7 or later** (`#Requires -Version 7.0`)
- **Nutanix Prism Central** reachable over the network
- **Nutanix API v4** (VMM for VMs, Prism for categories)

### Permissions

The account used for authentication must have **read** access to:

- **VMM (VM Management):** List AHV VMs and read their `categories` field  
  - Endpoint: `GET /vmm/v4.0/ahv/config/vms`
- **Prism:** List categories (to resolve category extIds to key/value)  
  - Endpoint: `GET /prism/v4.0/config/categories`

The script is **read-only**: it does not create, update, or delete any cluster or VM state. It only writes a local CSV file.

### Prism Central address

- Provide the Prism Central **FQDN or hostname** (e.g. `myprism.domain.local`).  
- The script builds the API base URL as **https** on **TCP port 9440**: `https://<PrismCentral>:9440/api`.

---

## Implementation

### High-level flow

1. **Resolve categories**  
   Call the Prism Categories API with pagination (`$page`, `$limit=100`). Build a lookup map: category `extId` → `{ key, value }`.

2. **List VMs**  
   Call the VMM AHV VMs API with pagination and `$select=extId,name,categories` to fetch only needed fields.

3. **Build column set**  
   From all VMs, resolve each category reference (extId) via the lookup. Collect **unique category keys** (e.g. `dept`, `env`, `app`) and sort them for stable column order. No duplicate column names.

4. **Build rows**  
   For each VM, create one row: `VmName`, `VmExtId`, then one cell per category key. The cell value is the category value for that VM (from the resolved categories). If a VM has no category for a key, the cell is empty. If a VM has multiple categories with the same key, the **first** value is used.

5. **Export**  
   Write the rows to the specified CSV path with UTF-8 encoding. If no path was provided, write to `.output/Get-NtnxVmCategoriesExport_<PrismCentral>_<yyyyMMdd_HHmmss>.csv` in the current directory (creating `.output` if needed).

### APIs used

| API | Path | Purpose |
|-----|------|---------|
| Prism Categories | `GET /prism/v4.0/config/categories` | List categories; get `extId`, `key`, `value` for lookup |
| VMM AHV VMs | `GET /vmm/v4.0/ahv/config/vms` | List VMs with `extId`, `name`, `categories` |

- **Authentication:** Basic (username/password from `PSCredential`).  
- **Pagination:** `$page` and `$limit` (max 100) until all pages are fetched.  
- **Resilience:** Transient HTTP 429/503 are retried with exponential backoff; other 4xx are not retried.  
- **Logging:** Structured log lines (timestamp, severity, message, target) via `Write-Verbose`; no credentials are logged.

### CSV format

- **Columns:** `VmName`, `VmExtId`, then one column per unique category key (alphabetically sorted).  
- **Rows:** One per VM.  
- **Cells:** Category value for that VM and key, or empty string if the VM has no category for that key.  
- **Encoding:** UTF-8.

---

## Usage

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `PrismCentral` | string | Yes | — | Prism Central FQDN or hostname (e.g. `myprism.domain.local`). The script uses HTTPS on port 9440 to build the API base URL. |
| `OutputPath` | string | No | — | Full or relative path of the output CSV file. If omitted, the CSV is written to a `.output` directory in the current directory (created if it does not exist), with a filename of the form `Get-NtnxVmCategoriesExport_<PrismCentral>_<timestamp>.csv` (e.g. `Get-NtnxVmCategoriesExport_myprism_domain_local_20250309_143022.csv`). |
| `Username` | string | No | — | Prism Central username. If provided (and `Credential` is not), the user is prompted securely for the password only. |
| `Credential` | PSCredential | No | — | Prism Central credentials. If omitted, the script prompts: use `Username` to prompt for password only, or leave both unset to prompt for username and password. |
| `TimeoutSec` | int | No | 60 | Timeout in seconds for each REST call. |
| `DryRun` | switch | No | false | If set, fetches data and builds the result in memory but does **not** write the CSV. The script still returns counts and the path. |

### Examples

**Basic run (prompt for credentials, output to default path):**

```powershell
.\Get-NtnxVmCategoriesExport.ps1 -PrismCentral 'myprism.domain.local'
```

**Basic run with explicit output path:**

```powershell
.\Get-NtnxVmCategoriesExport.ps1 -PrismCentral 'myprism.domain.local' -OutputPath '.\vm-categories.csv'
```

**Specify username (prompt for password only):**

```powershell
.\Get-NtnxVmCategoriesExport.ps1 -PrismCentral 'myprism.domain.local' -OutputPath '.\vm-categories.csv' -Username 'admin' -Verbose
```

**With full credential object and verbose logging:**

```powershell
$cred = Get-Credential -Message 'Prism Central'
.\Get-NtnxVmCategoriesExport.ps1 -PrismCentral 'myprism.domain.local' -OutputPath '.\vm-categories.csv' -Credential $cred -Verbose
```

**Dry run (no file written):**

```powershell
.\Get-NtnxVmCategoriesExport.ps1 -PrismCentral 'myprism.domain.local' -OutputPath '.\out.csv' -DryRun
```

**Longer timeout:**

```powershell
.\Get-NtnxVmCategoriesExport.ps1 -PrismCentral 'myprism.domain.local' -OutputPath '.\vm-categories.csv' -TimeoutSec 120
```

### Output

The script returns a single object with:

- **VmCount** — Number of VMs written (or that would be written with `-DryRun`).  
- **CategoryKeyCount** — Number of unique category key columns.  
- **OutputPath** — The CSV path.  
- **DryRun** — `$true` when `-DryRun` was used; otherwise not present or `$false`.

Example:

```powershell
$result = .\Get-NtnxVmCategoriesExport.ps1 -PrismCentral 'myprism.domain.local'
$result.VmCount        # e.g. 42
$result.OutputPath    # e.g. .\vm-categories.csv or .\.output\Get-NtnxVmCategoriesExport_myprism_domain_local_20250309_143022.csv
```

### Validation

- Open the CSV and confirm columns: `VmName`, `VmExtId`, then one column per category key.  
- For a VM with no categories, all category columns for that row should be empty.  
- For a VM with categories, each key column should show the expected value (first value if multiple categories share the same key).

---

# New-NtnxVmRecoveryPoints.ps1

Creates VM recovery points (point-in-time copies) for VMs that you specify in one of three ways: a **text file** (one VM name per line), a **single VM name** (`-VmName`), or a **category key:value** (`-Category`, e.g. `env:production`) to include all VMs that have that Nutanix category. The script resolves to cluster extIds via the VMM API, then calls the Data Protection API to create one or more recovery points. When there are more than 30 VMs, the script batches them into chunks of 30 (API limit) and creates one recovery point per chunk, each with the same expiration.

**Restore behavior:** Each recovery point can contain up to 30 VMs. You can still restore a **single VM** (or any subset) from that recovery point; the Nutanix restore API lets you choose which VM recovery points within the recovery point to restore. Batching does not force you to restore all VMs in the batch.

## Requirements

### Prerequisites

- **PowerShell 7 or later** (`#Requires -Version 7.0`)
- **Nutanix Prism Central** reachable over the network
- **Nutanix API v4** (VMM for VM list and categories, Prism for categories, Data Protection for recovery point create)

### Permissions

The account must have **Create Recovery Point** permission (e.g. Prism Admin, Self-Service Admin, Super Admin, Disaster Recovery Admin). For category-based selection, read access to Prism categories and VMM VM list (with categories) is also required.

### Specifying VMs (exactly one of)

- **`-VmListPath`** — Path to a text file: one VM name per line (trimmed; empty lines ignored). VM names must exist in the cluster and be unique.
- **`-VmName`** — A single VM name (one recovery point for that VM).
- **`-Category`** — A category in **key:value** form (e.g. `env:production`). All VMs that have that Nutanix category are included. The category must exist in Prism; if no VMs have that category, the script errors.

### Prism Central address

- Provide the Prism Central **FQDN or hostname**. The script uses **https** on **port 9440**: `https://<PrismCentral>:9440/api`.

## Usage

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `PrismCentral` | string | Yes | — | Prism Central FQDN or hostname. |
| `VmListPath` | string | Yes (set File) | — | Path to text file: one VM name per line. Use exactly one of **VmListPath**, **VmName**, or **Category**. |
| `VmName` | string | Yes (set Vm) | — | Single VM name. Use exactly one of **VmListPath**, **VmName**, or **Category**. |
| `Category` | string | Yes (set Category) | — | Category as **key:value** (e.g. `env:production`). All VMs with that category are included. Use exactly one of **VmListPath**, **VmName**, or **Category**. |
| `ExpirationDays` | int | No | 2 | Days from now when the recovery point(s) expire. |
| `RecoveryPointNamePrefix` | string | No | `ScriptRP` | Prefix for recovery point names (suffix: timestamp and batch index if multiple batches). |
| `Username` | string | No | — | Prism Central username (prompts for password if no `Credential`). |
| `Credential` | PSCredential | No | — | Prism Central credentials. |
| `TimeoutSec` | int | No | 60 | Timeout in seconds for each REST call. |
| `NoWait` | switch | No | false | If set, the script returns after submitting create requests (task IDs only) and does not poll for completion. By default, the script waits for each task to complete or fail. |
| `PollIntervalSec` | int | No | 15 | Seconds between task status polls when waiting for completion. |
| `TaskTimeoutSec` | int | No | 3600 | Maximum seconds to wait per task before treating it as timed out. |
| `WhatIf` | switch | No | false | If set, resolves VMs and shows what would be created without calling the API. |

### Examples

**Create recovery points from a file (default 2-day expiration):**

```powershell
.\New-NtnxVmRecoveryPoints.ps1 -PrismCentral 'myprism.domain.local' -VmListPath '.\vms.txt'
```

**Single VM by name:**

```powershell
.\New-NtnxVmRecoveryPoints.ps1 -PrismCentral 'myprism.domain.local' -VmName 'my-vm-01'
```

**All VMs with a given category (e.g. env=production):**

```powershell
.\New-NtnxVmRecoveryPoints.ps1 -PrismCentral 'myprism.domain.local' -Category 'env:production'
```

**Expiration 5 days from now:**

```powershell
.\New-NtnxVmRecoveryPoints.ps1 -PrismCentral 'myprism.domain.local' -VmListPath '.\vms.txt' -ExpirationDays 5
```

**WhatIf (no API create):**

```powershell
.\New-NtnxVmRecoveryPoints.ps1 -PrismCentral 'myprism.domain.local' -VmListPath '.\vms.txt' -WhatIf -Verbose
```

**Custom prefix and credentials:**

```powershell
$cred = Get-Credential -Message 'Prism Central'
.\New-NtnxVmRecoveryPoints.ps1 -PrismCentral 'myprism.domain.local' -VmListPath '.\vms.txt' -RecoveryPointNamePrefix 'PreUpgrade' -Credential $cred -Verbose
```

**Submit only (do not wait for task completion):**

```powershell
.\New-NtnxVmRecoveryPoints.ps1 -PrismCentral 'myprism.domain.local' -VmListPath '.\vms.txt' -NoWait
```

**Wait for completion with custom poll interval and task timeout:**

```powershell
.\New-NtnxVmRecoveryPoints.ps1 -PrismCentral 'myprism.domain.local' -VmListPath '.\vms.txt' -PollIntervalSec 10 -TaskTimeoutSec 1800
```

### Output

The script returns an object with:

- **VmCountRequested** — Number of VM names read from the file.
- **VmCountResolved** — Number of VMs resolved to extIds (after removing duplicates by name in file, same as requested if all unique).
- **BatchCount** — Number of recovery points created (or that would be created with `-WhatIf`).
- **RecoveryPointNames** — Names of the recovery points.
- **TaskIds** — Task extIds returned by the API (one per created recovery point; empty when `-WhatIf`).
- **ExpirationTime** — Expiration time in ISO-8601 UTC.
- **TaskResults** — When waiting for completion (default), array of objects with **TaskId**, **RecoveryPointName**, **Status** (e.g. `SUCCEEDED`, `FAILED`, `TIMEOUT`), and **ErrorMessage** (if failed). Omitted when `-NoWait` or `-WhatIf`.
- **WhatIf** — Present and `$true` when `-WhatIf` was used.

### Validation

- In Prism Central, use the returned **TaskIds** to monitor recovery point creation (Tasks or Data Protection).
- List recovery points via Data Protection API or UI and confirm names and expiration.
- To restore a single VM from a recovery point, use the restore API and specify the desired VM recovery point(s) within that recovery point.
