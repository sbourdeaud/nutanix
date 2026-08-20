""" gets virtual machines list from Prism Central using v4 API and python SDK

    Args:
        prism: The IP or FQDN of Prism.
        username: The Prism user name.

    Returns:
        html report file.
"""


#region IMPORT
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.parse import parse_qs

import argparse
import getpass
import json
from pathlib import Path
import urllib3
import pandas
import keyring

import ntnx_vmm_py_client
import ntnx_clustermgmt_py_client
import ntnx_networking_py_client
import ntnx_prism_py_client
import ntnx_iam_py_client
#endregion IMPORT


# region HEADERS
"""
# * author:       stephane.bourdeaud@nutanix.com
# * version:      2024/12/17

# description:
"""
# endregion HEADERS


#region CLASS
class PrintColors:
    """Used for colored output formatting.
    """
    OK = '\033[92m' #GREEN
    SUCCESS = '\033[96m' #CYAN
    DATA = '\033[097m' #WHITE
    WARNING = '\033[93m' #YELLOW
    FAIL = '\033[91m' #RED
    STEP = '\033[95m' #PURPLE
    RESET = '\033[0m' #RESET COLOR
#endregion CLASS


#region FUNCTIONS
def ntnx_api_pagination_get_page_links(response):
    '''retrieves self, next and last page links from metadata section of a response.
        Args:
            response: response payload.
        Returns:
            response_self_page_link,response_next_page_link,response_last_page_link (python sets)
    '''
    response_self_page_link ={ link.href for link in response.metadata.links if link.rel == "self" }
    response_next_page_link ={ link.href for link in response.metadata.links if link.rel == "next" }
    response_last_page_link ={ link.href for link in response.metadata.links if link.rel == "last" }
    return response_self_page_link,response_next_page_link,response_last_page_link


def ntnx_api_pagination_get_next_page_number(response_next_page_link):
    '''extracts the $page parameter value from a url.
        Args:
            response_next_page_link: python set containing the url to parse.
        Returns:
            next_page_number (integer)
    '''
    next_page_link = next(iter(response_next_page_link))
    parsed_url_next_page_link = urlparse(next_page_link)
    next_page_number = parse_qs(parsed_url_next_page_link.query)['$page'][0]
    return next_page_number


def ntnx_api_pagination(api_instance,function):
    '''gets all available objects of a specific type.
        api_instance:
            api instance object
        function:
            name of function to run on the api instance (exp: list_clusters)
        Returns:
            entity_list (cumulated data section from all pages)
    '''

    #get the name of the list function for this specific api instance
    list_function = getattr(api_instance, function)

    #* paginate thru all response pages
    entity_list=[]
    response_self_page_link = 'a'
    response_last_page_link = 'b'
    next_page_number = 0
    while response_self_page_link != response_last_page_link:
        response = list_function(_page=next_page_number)
        entity_list = entity_list + response.data
        response_self_page_link,response_next_page_link,response_last_page_link = ntnx_api_pagination_get_page_links(response)
        if response_next_page_link:
            next_page_number = ntnx_api_pagination_get_next_page_number(response_next_page_link)
    return entity_list


def main(api_server,username,secret,secure=False):
    '''main function.
        Args:
            api_server: IP or FQDN of the REST API server.
            username: Username to use for authentication.
            secret: Secret for the username.
            secure: indicates if certs should be verified.
        Returns:
    '''

    def get_name_by_ext_id(entries, ext_id, default=''):
        """Returns an entry name by ext_id, or default."""
        if not ext_id:
            return default
        return next((entry['name'] for entry in entries if entry.get('ext_id') == ext_id), default)

    def get_disk_size_bytes(disk):
        """Returns disk size in bytes when available."""
        return getattr(getattr(disk, 'backing_info', None), 'disk_size_bytes', None)

    def write_interactive_html_report(data_rows, output_file, origin):
        """Writes an interactive HTML report with SQL filtering and CSV export."""
        data_json = json.dumps(data_rows, default=str)
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
        orchestrator_css = ""
        orchestrator_css_candidates = [
            Path("/Users/stephan.bourdea/Documents/github/hybrid-cloud-infra-automation/nvd_x_iac/orchestrator/web/ui/tokens.css"),
            Path("/Users/stephan.bourdea/Documents/github/hybrid-cloud-infra-automation/nvd_x_iac/orchestrator/web/ui/style.css"),
        ]
        for css_path in orchestrator_css_candidates:
            try:
                if css_path.exists():
                    orchestrator_css += f"\n/* Source: {css_path} */\n"
                    orchestrator_css += css_path.read_text(encoding="utf-8")
            except Exception:
                continue

        html_content = """<!doctype html>
<html lang="en" data-theme="iris">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Nutanix VM Report</title>
  <link href="https://unpkg.com/tabulator-tables@6.3.0/dist/css/tabulator.min.css" rel="stylesheet">
  <style>
    __ORCHESTRATOR_CSS__

    /* Report-specific overrides */
    :root {
      --ec-grey-00: #ffffff;
      --ec-grey-50: #f5f7f9;
      --ec-grey-100: #edf0f2;
      --ec-grey-200: #d0d4d9;
      --ec-grey-300: #b8bfca;
      --ec-grey-650: #5b6168;
      --ec-grey-800: #2a2f36;
      --ec-grey-995: #131313;
      --ec-purple-400: #9c84fc;
      --ec-purple-500: #7855fa;
      --ec-purple-600: #6740ee;
      --ec-purple-700: #5530d2;
      --ec-green-200: #d7f6e1;
      --ec-green-700: #20973e;
      --ec-red-200: #fddddd;
      --ec-red-800: #d02550;
      --ec-yellow-200: #fff2ce;
      --ec-yellow-750: #b85c00;
      --ec-blue-200: #cfe4f8;
      --ec-blue-600: #2778ce;

      --ec-bg-body: var(--ec-grey-00);
      --ec-bg-surface: var(--ec-grey-00);
      --ec-bg-surface-alt: var(--ec-grey-50);
      --ec-bg-nav: var(--ec-grey-995);
      --ec-fg-body: var(--ec-grey-995);
      --ec-fg-muted: var(--ec-grey-650);
      --ec-fg-on-nav: var(--ec-grey-00);
      --ec-border-card: var(--ec-grey-200);
      --ec-border-table-row: var(--ec-grey-200);
      --ec-border-input: var(--ec-grey-300);
      --ec-action-primary: var(--ec-purple-500);
      --ec-action-primary-hover: var(--ec-purple-600);
      --ec-action-primary-active: var(--ec-purple-700);
      --ec-action-on-primary: var(--ec-grey-00);
      --ec-focus-ring: var(--ec-purple-400);
      --ec-status-ok: var(--ec-green-700);
      --ec-status-ok-bg: var(--ec-green-200);
      --ec-status-warn: var(--ec-yellow-750);
      --ec-status-warn-bg: var(--ec-yellow-200);
      --ec-status-error: var(--ec-red-800);
      --ec-status-error-bg: var(--ec-red-200);
      --ec-status-info: var(--ec-blue-600);
      --ec-status-info-bg: var(--ec-blue-200);

      --ec-space-1: 0.25rem;
      --ec-space-2: 0.5rem;
      --ec-space-3: 0.75rem;
      --ec-space-4: 1rem;
      --ec-space-5: 1.5rem;
      --ec-radius-card: 4px;
      --ec-radius-pill: 10px;
      --ec-radius-input: 3px;
      --ec-nav-height: 56px;
      --ec-content-max: 1600px;
      --ec-font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Helvetica, Arial, system-ui, sans-serif;
      --ec-font-mono: "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
      --ec-font-size-base: 14px;
      --ec-font-size-sm: 12px;
      --ec-font-size-h1: 20px;
      --ec-font-weight-strong: 600;
    }

    * { box-sizing: border-box; }
    html, body { margin: 0; padding: 0; height: 100%; }
    body {
      font-family: var(--ec-font-sans);
      font-size: var(--ec-font-size-base);
      color: var(--ec-fg-body);
      background: var(--ec-bg-body);
      display: flex;
      flex-direction: column;
      height: 100vh;
    }

    .topbar {
      flex: none;
      height: var(--ec-nav-height);
      background: var(--ec-bg-nav);
      color: var(--ec-fg-on-nav);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 var(--ec-space-5);
    }
    .brand {
      font-weight: var(--ec-font-weight-strong);
      letter-spacing: 0.02em;
    }
    .small-muted {
      font-size: var(--ec-font-size-sm);
      color: var(--ec-grey-300);
    }

    .content { flex: 1; min-height: 0; overflow-y: auto; }
    .wrap {
      max-width: none;
      width: 100%;
      margin: 0;
      padding: var(--ec-space-4);
    }
    .card {
      background: var(--ec-bg-surface);
      border: 1px solid var(--ec-border-card);
      border-radius: var(--ec-radius-card);
    }
    .card > .card-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: var(--ec-space-3) var(--ec-space-4);
      border-bottom: 1px solid var(--ec-border-card);
    }
    .card > .card-head h1 {
      margin: 0;
      font-size: var(--ec-font-size-h1);
      font-weight: var(--ec-font-weight-strong);
    }
    .card > .card-body { padding: var(--ec-space-4); }

    .toolbar { display: flex; gap: var(--ec-space-2); align-items: center; flex-wrap: wrap; margin-bottom: var(--ec-space-3); }
    .input {
      flex: 1 1 640px;
      min-width: 280px;
      padding: var(--ec-space-2);
      border: 1px solid var(--ec-border-input);
      border-radius: var(--ec-radius-input);
      background: var(--ec-bg-surface);
      color: var(--ec-fg-body);
      font-family: var(--ec-font-mono);
      font-size: var(--ec-font-size-sm);
    }
    .input:focus-visible {
      outline: 2px solid var(--ec-focus-ring);
      outline-offset: 0;
      border-color: var(--ec-focus-ring);
    }
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font: inherit;
      font-weight: var(--ec-font-weight-strong);
      border: 1px solid var(--ec-border-input);
      background: var(--ec-bg-surface);
      color: var(--ec-fg-body);
      border-radius: var(--ec-radius-input);
      padding: var(--ec-space-2) var(--ec-space-4);
      cursor: pointer;
      white-space: nowrap;
    }
    .btn:hover { background: var(--ec-bg-surface-alt); }
    .btn.primary {
      background: var(--ec-action-primary);
      border-color: var(--ec-action-primary);
      color: var(--ec-action-on-primary);
    }
    .btn.primary:hover { background: var(--ec-action-primary-hover); border-color: var(--ec-action-primary-hover); }
    .btn.primary:active { background: var(--ec-action-primary-active); border-color: var(--ec-action-primary-active); }
    .hint {
      color: var(--ec-fg-muted);
      font-size: var(--ec-font-size-sm);
      margin: var(--ec-space-2) 0 var(--ec-space-3);
    }
    code {
      font-family: var(--ec-font-mono);
      background: var(--ec-bg-surface-alt);
      border: 1px solid var(--ec-border-card);
      border-radius: var(--ec-radius-input);
      padding: 0 5px;
    }

    #table {
      border: 1px solid var(--ec-border-card);
      height: 70vh;
      min-height: 420px;
      border-radius: var(--ec-radius-card);
      overflow: hidden;
    }
    .tabulator {
      border: 0;
      background: var(--ec-bg-surface);
      color: var(--ec-fg-body);
    }
    .tabulator .tabulator-header {
      position: sticky;
      top: 0;
      z-index: 20;
      background: var(--ec-bg-surface);
      border-bottom: 1px solid var(--ec-border-table-row);
    }
    .tabulator .tabulator-col {
      border-right: 1px solid var(--ec-border-table-row);
      background: var(--ec-bg-surface);
    }
    .tabulator .tabulator-col .tabulator-col-title {
      color: var(--ec-fg-muted);
      font-size: var(--ec-font-size-sm);
      text-transform: uppercase;
      letter-spacing: 0.03em;
      font-weight: var(--ec-font-weight-strong);
    }
    .tabulator .tabulator-header .tabulator-col input {
      border: 1px solid var(--ec-border-input);
      border-radius: var(--ec-radius-input);
      padding: 4px 6px;
      background: var(--ec-bg-surface);
      color: var(--ec-fg-body);
      font-size: var(--ec-font-size-sm);
    }
    .tabulator .tabulator-row {
      border-bottom: 1px solid var(--ec-border-table-row);
    }
    .tabulator .tabulator-row:hover {
      background: var(--ec-bg-surface-alt);
    }
    .tabulator .tabulator-cell {
      border-right: 1px solid var(--ec-border-table-row);
      padding: var(--ec-space-2) var(--ec-space-3);
    }
    .tabulator .tabulator-footer {
      background: var(--ec-bg-surface);
      border-top: 1px solid var(--ec-border-table-row);
    }

    #status {
      margin-top: var(--ec-space-3);
      font-size: var(--ec-font-size-sm);
      color: var(--ec-fg-muted);
    }
    .context-menu {
      position: fixed;
      z-index: 10000;
      min-width: 260px;
      background: var(--ec-bg-surface);
      border: 1px solid var(--ec-border-card);
      border-radius: var(--ec-radius-input);
      box-shadow: 0 4px 14px rgba(0, 0, 0, 0.18);
      padding: 4px 0;
      display: none;
    }
    .context-menu.open { display: block; }
    .context-menu button {
      width: 100%;
      border: 0;
      background: transparent;
      color: var(--ec-fg-body);
      text-align: left;
      padding: 8px 12px;
      font-size: var(--ec-font-size-sm);
      cursor: pointer;
    }
    .context-menu button:hover {
      background: var(--ec-bg-surface-alt);
    }
  </style>
</head>
<body>
  <header class="topbar">
    <span class="brand">NVD VM Report</span>
    <span class="small-muted">Origin: __ORIGIN__ | Generated: __GENERATED_AT__</span>
  </header>
  <main class="content">
    <div class="wrap">
      <div class="card">
        <div class="card-head">
          <h1>Virtual Machines</h1>
        </div>
        <div class="card-body">
          <div class="toolbar">
            <input id="sql" class="input" type="text" value="SELECT * FROM ? WHERE 1=1" />
            <button class="btn primary" id="runSql">Run SQL</button>
            <button class="btn" id="resetSql">Reset</button>
            <button class="btn" id="downloadCsv">Export CSV</button>
            <button class="btn" id="downloadInventory">Export inventory.ini</button>
          </div>
          <div class="hint">
            SQL examples:
            <code>SELECT * FROM ? WHERE ngt_effective_status = 'not_connected'</code> |
            <code>SELECT name, cluster, ngt_status FROM ? WHERE power_state = 'ON'</code>
          </div>
          <div id="table"></div>
          <div id="status"></div>
        </div>
      </div>
    </div>
  </main>
  <div id="cellContextMenu" class="context-menu" role="menu" aria-hidden="true"></div>

  <script src="https://cdn.jsdelivr.net/npm/alasql@4.6/dist/alasql.min.js"></script>
  <script src="https://unpkg.com/tabulator-tables@6.3.0/dist/js/tabulator.min.js"></script>
  <script>
    const originalData = __DATA_JSON__;
    const statusEl = document.getElementById("status");
    const sqlInput = document.getElementById("sql");
    const contextMenuEl = document.getElementById("cellContextMenu");
    let currentData = [...originalData];
    let contextCell = null;
    let lastSqlResultCount = null;

    const inferColumns = (rows) => {
      if (!rows.length) return [];
      return Object.keys(rows[0]).map((key) => ({
        title: key,
        field: key,
        headerFilter: true,
        sorter: "string",
        formatter: (cell) => {
          const v = cell.getValue();
          if (Array.isArray(v)) return v.join(", ");
          if (v === null || v === undefined) return "";
          return String(v);
        }
      }));
    };

    let table = new Tabulator("#table", {
      data: currentData,
      layout: "fitDataTable",
      height: "100%",
      pagination: false,
      movableColumns: true,
      clipboard: true,
      headerVisible: true,
      columns: inferColumns(currentData),
    });

    const updateStatus = (msg) => {
      statusEl.textContent = msg;
    };

    const getActiveRowData = () => table.getRows("active").map((row) => row.getData());

    const refreshMatchedStatus = (prefix = "Matched rows", explicitCount = null) => {
      const count = explicitCount !== null
        ? explicitCount
        : (lastSqlResultCount !== null ? lastSqlResultCount : getActiveRowData().length);
      updateStatus(`${prefix}: ${count} (scroll inside table to view all)`);
    };

    const escapeSqlValue = (value) => String(value).replace(/'/g, "''");
    const escapeSqlField = (field) => String(field).replace(/`/g, "``");
    let previousHeaderFilterCount = 0;

    const normalizeSqlQuery = (query) =>
      query.replace(/CAST\(\s*`([^`]+)`\s+AS\s+STRING\s*\)/gi, "`$1`");

    const toComparableString = (value) => {
      if (value === null || value === undefined) {
        return "";
      }
      if (Array.isArray(value)) {
        return value.join(", ");
      }
      return String(value);
    };

    const runDeterministicLikeQuery = (query) => {
      const normalized = normalizeSqlQuery(query).trim();
      const match = normalized.match(/^SELECT\s+\*\s+FROM\s+\?\s+WHERE\s+(.+)$/i);
      if (!match) {
        return null;
      }
      const whereClause = match[1].trim();
      if (!whereClause) {
        return [...originalData];
      }

      const conditions = whereClause.split(/\s+AND\s+/i).map((part) => part.trim()).filter(Boolean);
      if (!conditions.length) {
        return [...originalData];
      }

      const parsedConditions = [];
      for (const condition of conditions) {
        const condMatch = condition.match(/^`([^`]+)`\s+LIKE\s+'%(.*)%'$/i);
        if (!condMatch) {
          return null;
        }
        const field = condMatch[1];
        const needle = condMatch[2].replace(/''/g, "'").toLowerCase();
        parsedConditions.push({ field, needle });
      }

      return originalData.filter((row) =>
        parsedConditions.every(({ field, needle }) => {
          const haystack = toComparableString(row[field]).toLowerCase();
          return haystack.includes(needle);
        })
      );
    };

    const runQueryAgainstOriginalData = (query) => {
      const normalizedQuery = normalizeSqlQuery(query);
      let result = runDeterministicLikeQuery(normalizedQuery);
      if (result === null) {
        result = alasql(normalizedQuery, [originalData]);
      }
      return { normalizedQuery, result };
    };

    const buildSqlFromHeaderFilters = (headerFilters) => {
      if (!headerFilters.length) {
        return "SELECT * FROM ? WHERE 1=1";
      }
      const whereClauses = headerFilters
        .filter((flt) => flt && flt.field && flt.value !== null && flt.value !== undefined && String(flt.value).trim() !== "")
        .map((flt) => {
          const field = escapeSqlField(flt.field);
          const value = escapeSqlValue(String(flt.value).trim());
          return `CAST(\`${field}\` AS STRING) LIKE '%${value}%'`;
        });
      if (!whereClauses.length) {
        return "SELECT * FROM ? WHERE 1=1";
      }
      return `SELECT * FROM ? WHERE ${whereClauses.join(" AND ")}`;
    };

    const applyData = (rows, messagePrefix) => {
      currentData = rows;
      table.setColumns(inferColumns(currentData));
      table.setData(currentData);
      // Let Tabulator finish applying internal filters/sort before counting.
      setTimeout(() => refreshMatchedStatus(messagePrefix), 0);
    };

    document.getElementById("runSql").addEventListener("click", () => {
      const query = sqlInput.value.trim();
      try {
        const { normalizedQuery, result } = runQueryAgainstOriginalData(query);
        if (!Array.isArray(result)) {
          updateStatus("SQL executed, but result is not a row set.");
          return;
        }
        lastSqlResultCount = result.length;
        if (normalizedQuery !== query) {
          sqlInput.value = normalizedQuery;
        }
        applyData(result, "Filtered");
        setTimeout(() => refreshMatchedStatus("Matched rows", lastSqlResultCount), 0);
      } catch (err) {
        updateStatus(`SQL error: ${err.message}`);
      }
    });

    document.getElementById("resetSql").addEventListener("click", () => {
      sqlInput.value = "SELECT * FROM ? WHERE 1=1";
      lastSqlResultCount = null;
      applyData([...originalData], "Reset");
    });

    const toCsv = (rows) => {
      if (!rows || !rows.length) {
        return "";
      }
      const headers = Object.keys(rows[0]);
      const escapeCsv = (value) => {
        if (value === null || value === undefined) {
          return "";
        }
        const normalized = Array.isArray(value) ? value.join(", ") : String(value);
        if (/[",\\n]/.test(normalized)) {
          return `"${normalized.replace(/"/g, '""')}"`;
        }
        return normalized;
      };
      const lines = [headers.join(",")];
      for (const row of rows) {
        lines.push(headers.map((header) => escapeCsv(row[header])).join(","));
      }
      return lines.join("\\n");
    };

    document.getElementById("downloadCsv").addEventListener("click", () => {
      const activeRows = getActiveRowData();
      const exportRows = activeRows.length ? activeRows : currentData;
      const csvContent = toCsv(exportRows);
      const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "get_vm_report.csv";
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      updateStatus(`Exported CSV from ${exportRows.length} row(s)`);
    });

    const toArray = (value) => {
      if (Array.isArray(value)) {
        return value;
      }
      if (typeof value === "string" && value.trim().startsWith("[") && value.trim().endsWith("]")) {
        try {
          const parsed = JSON.parse(value.replace(/'/g, '"'));
          return Array.isArray(parsed) ? parsed : [];
        } catch (e) {
          return [];
        }
      }
      return [];
    };

    const inferVmGroup = (row) => {
      const name = String(row.name || "").toLowerCase();
      if (/w\\d+$/.test(name) || name.includes("windows")) {
        return "windows_vms";
      }
      if (/l\\d+$/.test(name) || name.includes("linux")) {
        return "linux_vms";
      }
      return "other_vms";
    };

    const toInventoryIni = (rows) => {
      const groups = {
        linux_vms: [],
        windows_vms: [],
        other_vms: [],
      };

      rows.forEach((row) => {
        const vmName = String(row.name || "").trim();
        if (!vmName) {
          return;
        }
        const learnedIps = toArray(row.learned_ip_addresses)
          .map((ip) => String(ip || "").trim())
          .filter((ip) => ip.length > 0);
        const ansibleHost = learnedIps.length ? learnedIps[0] : "";
        const inventoryLine = ansibleHost ? `${vmName} ansible_host=${ansibleHost}` : vmName;
        groups[inferVmGroup(row)].push(inventoryLine);
      });

      const lines = [];
      lines.push("# Generated from current report filter");
      lines.push(`# Total VMs: ${rows.length}`);
      lines.push("");
      lines.push("[linux_vms]");
      lines.push(...groups.linux_vms);
      lines.push("");
      lines.push("[windows_vms]");
      lines.push(...groups.windows_vms);
      lines.push("");
      lines.push("[other_vms]");
      lines.push(...groups.other_vms);
      lines.push("");
      lines.push("[nutanix_vms:children]");
      lines.push("linux_vms");
      lines.push("windows_vms");
      lines.push("other_vms");
      lines.push("");
      return lines.join("\\n");
    };

    document.getElementById("downloadInventory").addEventListener("click", () => {
      const activeRows = getActiveRowData();
      const exportRows = activeRows.length ? activeRows : currentData;
      const iniContent = toInventoryIni(exportRows);
      const blob = new Blob([iniContent], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "inventory.ini";
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      updateStatus(`Exported inventory.ini from ${exportRows.length} row(s)`);
    });

    const hideContextMenu = () => {
      contextMenuEl.classList.remove("open");
      contextMenuEl.setAttribute("aria-hidden", "true");
      contextMenuEl.innerHTML = "";
      contextCell = null;
    };

    const showContextMenu = (event, cell) => {
      event.preventDefault();
      const field = cell.getField();
      const rawValue = cell.getValue();
      const value = Array.isArray(rawValue) ? rawValue.join(", ") : String(rawValue ?? "");
      const safeValue = value.length > 80 ? `${value.slice(0, 77)}...` : value;

      contextCell = { field, value };
      contextMenuEl.innerHTML = `
        <button type="button" data-action="add-column-filter" title="Set ${field} filter to this value">
          Filter \`${field}\` by "${safeValue}"
        </button>
      `;

      const menuWidth = 320;
      const menuHeight = 44;
      const left = Math.min(event.clientX, window.innerWidth - menuWidth - 8);
      const top = Math.min(event.clientY, window.innerHeight - menuHeight - 8);
      contextMenuEl.style.left = `${Math.max(8, left)}px`;
      contextMenuEl.style.top = `${Math.max(8, top)}px`;
      contextMenuEl.classList.add("open");
      contextMenuEl.setAttribute("aria-hidden", "false");
    };

    contextMenuEl.addEventListener("click", (event) => {
      const target = event.target;
      if (!target || !target.dataset || target.dataset.action !== "add-column-filter") {
        return;
      }
      if (!contextCell) {
        hideContextMenu();
        return;
      }
      table.setHeaderFilterValue(contextCell.field, contextCell.value);
      hideContextMenu();
      updateStatus(`Applied header filter: ${contextCell.field} contains "${contextCell.value}"`);
    });

    document.addEventListener("click", () => hideContextMenu());
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        hideContextMenu();
      }
    });
    window.addEventListener("resize", () => hideContextMenu());
    window.addEventListener("scroll", () => hideContextMenu(), true);

    table.on("cellContext", (event, cell) => {
      showContextMenu(event, cell);
    });

    table.on("dataFiltered", () => {
      const headerFilters = table.getHeaderFilters() || [];
      const activeRows = getActiveRowData();
      currentData = activeRows;

      if (headerFilters.length > 0) {
        sqlInput.value = buildSqlFromHeaderFilters(headerFilters);
      } else if (previousHeaderFilterCount > 0) {
        sqlInput.value = "SELECT * FROM ? WHERE 1=1";
      }
      previousHeaderFilterCount = headerFilters.length;
      try {
        const { normalizedQuery, result } = runQueryAgainstOriginalData(sqlInput.value.trim());
        if (Array.isArray(result)) {
          lastSqlResultCount = result.length;
          if (normalizedQuery !== sqlInput.value.trim()) {
            sqlInput.value = normalizedQuery;
          }
        }
      } catch (err) {
        // Keep UI responsive even when query is temporarily invalid while typing.
      }
      refreshMatchedStatus();
    });

    refreshMatchedStatus();
  </script>
</body>
</html>
"""
        html_content = html_content.replace("__DATA_JSON__", data_json)
        html_content = html_content.replace("__ORCHESTRATOR_CSS__", orchestrator_css)
        html_content = html_content.replace("__ORIGIN__", str(origin or "unknown"))
        html_content = html_content.replace("__GENERATED_AT__", generated_at)
        with open(output_file, "w", encoding="utf-8") as html_file:
            html_file.write(html_content)

    #region clusters
    #* initialize variable for API client configuration
    api_client_configuration = ntnx_clustermgmt_py_client.Configuration()
    api_client_configuration.host = api_server
    api_client_configuration.username = username
    api_client_configuration.password = secret

    if secure == False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        #! suppress ssl certs verification
        api_client_configuration.verify_ssl = False

    api_client = ntnx_clustermgmt_py_client.ApiClient(configuration=api_client_configuration)

    #* getting list of clusters
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Gettting all clusters from {api_server}.{PrintColors.RESET}")

    api_instance_cluster = ntnx_clustermgmt_py_client.api.ClustersApi(api_client=api_client)

    cluster_list = ntnx_api_pagination(api_instance=api_instance_cluster,function='list_clusters')

    #* format output
    cluster_list_output = []
    for entity in cluster_list:
        if 'PRISM_CENTRAL' in entity.config.cluster_function:
            continue
        entity_output = {
            'name': entity.name,
            'ext_id': entity.ext_id,
            'incarnation_id': entity.config.incarnation_id,
            'is_available': entity.config.is_available,
            'operation_mode': entity.config.operation_mode,
            'redundancy_factor': entity.config.redundancy_factor,
            'domain_awareness_level': entity.config.fault_tolerance_state.domain_awareness_level,
            'current_max_fault_tolerance': entity.config.fault_tolerance_state.current_max_fault_tolerance,
            'desired_max_fault_tolerance': entity.config.fault_tolerance_state.desired_max_fault_tolerance,
            'upgrade_status': entity.upgrade_status,
            'vm_count': entity.vm_count,
            'inefficient_vm_count': entity.inefficient_vm_count,
            'cluster_arch': entity.config.cluster_arch,
            'cluster_function': entity.config.cluster_function,
            'hypervisor_types': entity.config.hypervisor_types,
            'is_password_remote_login_enabled': entity.config.is_password_remote_login_enabled,
            'is_remote_support_enabled': entity.config.is_remote_support_enabled,
            'pulse_enabled': entity.config.pulse_status.is_enabled,
            'timezone': entity.config.timezone,
            'ncc_version': next(iter({ software.version for software in entity.config.cluster_software_map if software.software_type == "NCC" })),
            'aos_full_version': entity.config.build_info.full_version,
            'aos_commit_id': entity.config.build_info.short_commit_id,
            'aos_version': entity.config.build_info.version,
            'is_segmentation_enabled': entity.network.backplane.is_segmentation_enabled,
            'external_address_ipv4': entity.network.external_address.ipv4.value,
            'external_data_service_ipv4': entity.network.external_data_service_ip.ipv4.value,
            'external_subnet': entity.network.external_subnet,
            'name_server_ipv4_list': list({ name_server.ipv4.value for name_server in entity.network.name_server_ip_list}),
            'ntp_server_fqdn_list': list({ ntp_server.fqdn.value for ntp_server in entity.network.ntp_server_ip_list}),
            'number_of_nodes': entity.nodes.number_of_nodes,
        }

        cluster_list_output.append(entity_output)
    #endregion clusters

    #region hosts
    #* getting list of hosts
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Gettting all hosts from {api_server}.{PrintColors.RESET}")
    host_list = ntnx_api_pagination(api_instance=api_instance_cluster,function='list_hosts')

    #* format output
    host_list_output = []
    for entity in host_list:
        entity_output = {
            'name': entity.host_name,
            'ext_id': entity.ext_id,
        }

        host_list_output.append(entity_output)
    #endregion hosts

    #region storage containers
    #* getting list of storage containers
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Gettting all storage containers from {api_server}.{PrintColors.RESET}")
    api_instance_storage_containers = ntnx_clustermgmt_py_client.api.StorageContainersApi(api_client=api_client)
    storage_container_list = ntnx_api_pagination(api_instance=api_instance_storage_containers,function='list_storage_containers')

    #* format output
    storage_container_list_output = []
    for entity in storage_container_list:
        entity_output = {
            'name': entity.name,
            'ext_id': entity.container_ext_id,
        }

        storage_container_list_output.append(entity_output)
    #endregion storage containers

    #region networks
    #* initialize variable for API client configuration
    api_client_configuration = ntnx_networking_py_client.Configuration()
    api_client_configuration.host = api_server
    api_client_configuration.username = username
    api_client_configuration.password = secret

    if secure == False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        #! suppress ssl certs verification
        api_client_configuration.verify_ssl = False

    api_client = ntnx_networking_py_client.ApiClient(configuration=api_client_configuration)

    #* getting list of subnets
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Gettting all subnets from {api_server}.{PrintColors.RESET}")

    api_instance_networking = ntnx_networking_py_client.api.SubnetsApi(api_client=api_client)

    subnet_list = ntnx_api_pagination(api_instance=api_instance_networking,function='list_subnets')

    #* format output
    subnet_list_output = []
    for entity in subnet_list:
        entity_output = {
            'name': entity.name,
            'ext_id': entity.ext_id,
        }

        subnet_list_output.append(entity_output)
    #endregion networks

    #region categories
    #* initialize variable for API client configuration
    api_client_configuration = ntnx_prism_py_client.Configuration()
    api_client_configuration.host = api_server
    api_client_configuration.username = username
    api_client_configuration.password = secret

    if secure == False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        #! suppress ssl certs verification
        api_client_configuration.verify_ssl = False

    api_client = ntnx_prism_py_client.ApiClient(configuration=api_client_configuration)

    #* getting list of categories
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Gettting all categories from {api_server}.{PrintColors.RESET}")

    api_instance_categories = ntnx_prism_py_client.api.CategoriesApi(api_client=api_client)

    category_list = ntnx_api_pagination(api_instance=api_instance_categories,function='list_categories')

    #* format output
    category_list_output = []
    for entity in category_list:
        entity_output = {
            'name': f"{entity.key}:{entity.value}",
            'ext_id': entity.ext_id,
        }

        category_list_output.append(entity_output)
    #endregion categories

    #region users
    #* initialize variable for API client configuration
    api_client_configuration = ntnx_iam_py_client.Configuration()
    api_client_configuration.host = api_server
    api_client_configuration.username = username
    api_client_configuration.password = secret

    if secure == False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        #! suppress ssl certs verification
        api_client_configuration.verify_ssl = False

    api_client = ntnx_iam_py_client.ApiClient(configuration=api_client_configuration)

    #* getting list of users
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Gettting all users from {api_server}.{PrintColors.RESET}")

    api_instance_users = ntnx_iam_py_client.api.UsersApi(api_client=api_client)

    user_list = ntnx_api_pagination(api_instance=api_instance_users,function='list_users')

    #* format output
    user_list_output = []
    for entity in user_list:
        entity_output = {
            'name': entity.username,
            'ext_id': entity.ext_id,
        }

        user_list_output.append(entity_output)
    #endregion users

    #region vms
    #* initialize variable for API client configuration
    api_client_configuration = ntnx_vmm_py_client.Configuration()
    api_client_configuration.host = api_server
    api_client_configuration.username = username
    api_client_configuration.password = secret

    if secure == False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        #! suppress ssl certs verification
        api_client_configuration.verify_ssl = False

    api_client = ntnx_vmm_py_client.ApiClient(configuration=api_client_configuration)

    #* getting list of virtual machines
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Gettting all virtual machines from {api_server}.{PrintColors.RESET}")
    api_instance_vm = ntnx_vmm_py_client.api.VmApi(api_client=api_client)
    vm_list = ntnx_api_pagination(api_instance=api_instance_vm,function='list_vms')

    #* format output
    vm_list_output = []
    boot_config = ''
    for entity in vm_list:
        cluster_ext_id = getattr(getattr(entity, 'cluster', None), 'ext_id', None)
        host_ext_id = getattr(getattr(entity, 'host', None), 'ext_id', None)
        owner_ext_id = getattr(getattr(getattr(entity, 'ownership_info', None), 'owner', None), 'ext_id', None)
        disk_sizes = [size for size in (get_disk_size_bytes(disk) for disk in (entity.disks or [])) if size is not None]
        entity_output = {
            'name': entity.name,
            'ext_id': entity.ext_id,
            'cluster': get_name_by_ext_id(cluster_list_output, cluster_ext_id),
            'host': get_name_by_ext_id(host_list_output, host_ext_id),
            'num_cores_per_socket': entity.num_cores_per_socket,
            'num_numa_nodes': entity.num_numa_nodes,
            'num_sockets': entity.num_sockets,
            'num_threads_per_core': entity.num_threads_per_core,
            'memory_size_bytes': entity.memory_size_bytes,
            'power_state': entity.power_state,
            'protection_type': entity.protection_type,
            'machine_type': entity.machine_type,
            'guest_tools_version': '',
            'ngt_config_enabled': '',
            'guest_tools_capabilities': '',
            'ngt_status': 'not_installed',
            'ngt_effective_status': 'not_installed',
            'is_agent_vm': entity.is_agent_vm,
            'is_cpu_hotplug_enabled': entity.is_cpu_hotplug_enabled,
            'is_memory_overcommit_enabled': entity.is_memory_overcommit_enabled,
            'is_vtpm_enabled': entity.vtpm_config.is_vtpm_enabled,
            'is_gpu_console_enabled': entity.is_gpu_console_enabled,
            'boot_type': '',
            'is_secure_boot_enabled': '',
            'boot_order': entity.boot_config.boot_order,
            'cdroms': list({ getattr(getattr(cdrom, 'disk_address', None), 'bus_type', None) for cdrom in entity.cd_roms if getattr(getattr(cdrom, 'disk_address', None), 'bus_type', None) }) if entity.cd_roms else [],
            'disks': list({ getattr(getattr(disk, 'disk_address', None), 'bus_type', None) for disk in entity.disks if getattr(getattr(disk, 'disk_address', None), 'bus_type', None) }) if entity.disks else [],
            'disks_bytes': disk_sizes,
            'disks_bytes_total': sum(disk_sizes) if disk_sizes else 0,
            'storage_containers': [],
            'categories': [],
            'mac_addresses': list({ vnic.backing_info.mac_address for vnic in entity.nics}) if entity.nics else [],
            'vnic_connection_status': list({ vnic.backing_info.is_connected for vnic in entity.nics}) if entity.nics else [],
            'vnic_types': list({ vnic.network_info.nic_type for vnic in entity.nics}) if entity.nics else [],
            'vnic_vlan_mode': list({ vnic.network_info.vlan_mode for vnic in entity.nics}) if entity.nics else [],
            'learned_ip_addresses': [],
            'subnets': [],
            'owner': get_name_by_ext_id(user_list_output, owner_ext_id),
        }

        #getting ngt information
        if entity.guest_tools:
            entity_output['guest_tools_version'] = entity.guest_tools.available_version
            entity_output['ngt_config_enabled'] = entity.guest_tools.is_enabled
            entity_output['guest_tools_capabilities'] = entity.guest_tools.capabilities
            is_installed = getattr(entity.guest_tools, 'is_installed', None)
            is_enabled = getattr(entity.guest_tools, 'is_enabled', None)
            is_reachable = getattr(entity.guest_tools, 'is_reachable', None)
            if is_installed is False:
                entity_output['ngt_status'] = 'not_installed'
                entity_output['ngt_effective_status'] = 'not_installed'
            elif is_enabled is False:
                entity_output['ngt_status'] = 'disabled'
                entity_output['ngt_effective_status'] = 'disabled'
            elif is_reachable is False:
                entity_output['ngt_status'] = 'not_connected'
                entity_output['ngt_effective_status'] = 'not_connected'
            elif is_enabled:
                entity_output['ngt_status'] = 'enabled'
                entity_output['ngt_effective_status'] = 'enabled'

        #getting boot information
        boot_config=(entity.boot_config._object_type).split('.')
        entity_output['boot_type'] = boot_config[len(boot_config)-1]
        if entity_output['boot_type'] == 'UefiBoot':
            entity_output['is_secure_boot_enabled'] = entity.boot_config.is_secure_boot_enabled

        #getting categories
        if entity.categories:
            for category in entity.categories:
                category_name = get_name_by_ext_id(category_list_output, getattr(category, 'ext_id', None))
                if category_name:
                    entity_output['categories'].append(category_name)

        #getting storage containers
        if entity.disks:
            for disk in entity.disks:
                storage_container_ext_id = getattr(
                    getattr(getattr(disk, 'backing_info', None), 'storage_container', None),
                    'ext_id',
                    None,
                )
                storage_container_name = get_name_by_ext_id(storage_container_list_output, storage_container_ext_id)
                if storage_container_name:
                    entity_output['storage_containers'].append(storage_container_name)

        #getting ip_addresses and subnets
        if entity.nics:
            for vnic in entity.nics:
                network_info = getattr(vnic, 'network_info', None)
                ipv4_info = getattr(network_info, 'ipv4_info', None)
                learned_ip_addresses = getattr(ipv4_info, 'learned_ip_addresses', None)
                if learned_ip_addresses:
                    for ip_address in learned_ip_addresses:
                        entity_output['learned_ip_addresses'].append(ip_address.value)
                subnet_ext_id = getattr(getattr(network_info, 'subnet', None), 'ext_id', None)
                subnet_name = get_name_by_ext_id(subnet_list_output, subnet_ext_id)
                if subnet_name:
                    entity_output['subnets'].append(subnet_name)

        vm_list_output.append(entity_output)
    #endregion vms

    #region html report
    #* exporting to html and csv
    html_file_name = "get_vm_report.html"
    csv_file_name = "get_vm_report.csv"
    df = pandas.DataFrame(vm_list_output)
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Exporting {len(df)} results to file {html_file_name}.{PrintColors.RESET}")
    write_interactive_html_report(vm_list_output, html_file_name, api_server)
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Exporting {len(df)} results to file {csv_file_name}.{PrintColors.RESET}")
    df.to_csv(csv_file_name, index=False)
    #endregion html report
#endregion FUNCTIONS


if __name__ == '__main__':
    # * parsing script arguments
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-p", "--prism", help="prism server.")
    parser.add_argument("-u", "--username", default='admin', help="username for prism server.")
    parser.add_argument("-s", "--secure", default=False, help="True of False to control SSL certs verification.")
    args = parser.parse_args()

    # * check for password (we use keyring python module to access the workstation operating system password store in an "ntnx" section)
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Trying to retrieve secret for user {args.username} from the password store.{PrintColors.RESET}")
    pwd = keyring.get_password("ntnx",args.username)
    if not pwd:
        try:
            pwd = getpass.getpass()
            keyring.set_password("ntnx",args.username,pwd)
        except Exception as error:
            print(f"{PrintColors.FAIL}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {error}.{PrintColors.RESET}")

    main(api_server=args.prism,username=args.username,secret=pwd,secure=args.secure)
