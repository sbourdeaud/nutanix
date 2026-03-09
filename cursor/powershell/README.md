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
