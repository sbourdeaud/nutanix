""" gets misc entities list from Prism Central using v4 API and python SDK

    Args:
        prism: The IP or FQDN of Prism.
        username: The Prism user name.

    Returns:
        html report file.
"""


#region IMPORT
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import math
import argparse
import getpass
import json

from humanfriendly import format_timespan

import urllib3
import pandas
import keyring
import tqdm

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
def fetch_entities(client,module,entity_api,function,page,limit):
    entity_api_module = getattr(module, entity_api)
    entity_api = entity_api_module(api_client=client)
    list_function = getattr(entity_api, function)
    response = list_function(_page=page,_limit=limit)
    return response


def format_vm_uptime(entity):
    """Best-effort VM uptime using available VM timestamps."""
    now = datetime.now(timezone.utc)
    candidates = [
        getattr(entity, 'boot_time', None),
        getattr(entity, 'last_powered_on_time', None),
        getattr(entity, 'power_state_transition_time', None),
        getattr(entity, 'create_time', None),
    ]
    timestamp = next((value for value in candidates if value), None)
    if not timestamp:
        return ''
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            return ''
    if not isinstance(timestamp, datetime):
        return ''
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    delta = now - timestamp
    if delta.total_seconds() < 0:
        return ''
    days = delta.days
    hours, remainder = divmod(delta.seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    return f"{days}d {hours}h {minutes}m"


def write_interactive_html_report(data_sets, output_file, origin, generated_at, csv_base_name):
    """Writes a styled interactive HTML report without datapane."""
    data_sets_json = json.dumps(data_sets, default=str)

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
  <title>Nutanix PC Report</title>
  <link href="https://unpkg.com/tabulator-tables@6.3.0/dist/css/tabulator.min.css" rel="stylesheet">
  <style>
    :root{--ec-grey-00:#ffffff;--ec-grey-50:#f5f7f9;--ec-grey-100:#edf0f2;--ec-grey-200:#d0d4d9;--ec-grey-300:#b8bfca;--ec-grey-650:#5b6168;--ec-grey-800:#2a2f36;--ec-grey-995:#131313;--ec-purple-400:#9c84fc;--ec-purple-500:#7855fa;--ec-purple-600:#6740ee;--ec-purple-700:#5530d2;--ec-green-200:#d7f6e1;--ec-green-700:#20973e;--ec-red-200:#fddddd;--ec-red-800:#d02550;--ec-yellow-200:#fff2ce;--ec-yellow-750:#b85c00;--ec-blue-200:#cfe4f8;--ec-blue-600:#2778ce;--ec-bg-body:var(--ec-grey-00);--ec-bg-surface:var(--ec-grey-00);--ec-bg-surface-alt:var(--ec-grey-50);--ec-bg-nav:var(--ec-grey-995);--ec-fg-body:var(--ec-grey-995);--ec-fg-muted:var(--ec-grey-650);--ec-fg-on-nav:var(--ec-grey-00);--ec-border-card:var(--ec-grey-200);--ec-border-table-row:var(--ec-grey-200);--ec-border-input:var(--ec-grey-300);--ec-action-primary:var(--ec-purple-500);--ec-action-primary-hover:var(--ec-purple-600);--ec-action-primary-active:var(--ec-purple-700);--ec-action-on-primary:var(--ec-grey-00);--ec-focus-ring:var(--ec-purple-400);--ec-status-ok:var(--ec-green-700);--ec-status-ok-bg:var(--ec-green-200);--ec-status-warn:var(--ec-yellow-750);--ec-status-warn-bg:var(--ec-yellow-200);--ec-status-error:var(--ec-red-800);--ec-status-error-bg:var(--ec-red-200);--ec-status-info:var(--ec-blue-600);--ec-status-info-bg:var(--ec-blue-200);--ec-space-1:0.25rem;--ec-space-2:0.5rem;--ec-space-3:0.75rem;--ec-space-4:1rem;--ec-space-5:1.5rem;--ec-radius-card:4px;--ec-radius-pill:10px;--ec-radius-input:3px;--ec-nav-height:56px;--ec-content-max:1600px;--ec-font-sans:-apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Helvetica, Arial, system-ui, sans-serif;--ec-font-mono:"SF Mono", Menlo, Consolas, "Liberation Mono", monospace;--ec-font-size-base:14px;--ec-font-size-sm:12px;--ec-font-size-h1:20px;--ec-font-weight-strong:600}*{box-sizing:border-box}body,html{margin:0;padding:0;height:100%}body{font-family:var(--ec-font-sans);font-size:var(--ec-font-size-base);color:var(--ec-fg-body);background:var(--ec-bg-body);display:flex;flex-direction:column;height:100vh}.topbar{flex:none;height:var(--ec-nav-height);background:var(--ec-bg-nav);color:var(--ec-fg-on-nav);display:flex;align-items:center;justify-content:space-between;padding:0 var(--ec-space-5)}.brand,.card>.card-head h1{font-weight:var(--ec-font-weight-strong)}.brand{letter-spacing:.02em}.small-muted{font-size:var(--ec-font-size-sm);color:var(--ec-grey-300)}.content{overflow:hidden}.card,.content,.wrap{flex:1;display:flex;flex-direction:column;min-height:0}.wrap{max-width:none;width:100%;margin:0;padding:var(--ec-space-4)}.card{background:var(--ec-bg-surface);border:1px solid var(--ec-border-card);border-radius:var(--ec-radius-card)}.card>.card-head,.toolbar{display:flex;align-items:center;flex:none}.card>.card-head{justify-content:space-between;padding:var(--ec-space-3) var(--ec-space-4);border-bottom:1px solid var(--ec-border-card)}.card>.card-head h1{margin:0;font-size:var(--ec-font-size-h1)}.card>.card-body{padding:var(--ec-space-4);flex:1;display:flex;flex-direction:column;min-height:0}.toolbar{gap:var(--ec-space-2);flex-wrap:wrap;margin-bottom:var(--ec-space-3)}.input{flex:1 1 640px;min-width:280px;padding:var(--ec-space-2);border:1px solid var(--ec-border-input);border-radius:var(--ec-radius-input);background:var(--ec-bg-surface);color:var(--ec-fg-body);font-family:var(--ec-font-mono);font-size:var(--ec-font-size-sm)}.input:focus-visible{outline:2px solid var(--ec-focus-ring);outline-offset:0;border-color:var(--ec-focus-ring)}.btn{display:inline-flex;align-items:center;gap:6px;font:inherit;font-weight:var(--ec-font-weight-strong);border:1px solid var(--ec-border-input);background:var(--ec-bg-surface);color:var(--ec-fg-body);border-radius:var(--ec-radius-input);padding:var(--ec-space-2) var(--ec-space-4);cursor:pointer;white-space:nowrap}.btn:hover{background:var(--ec-bg-surface-alt)}.btn.primary{background:var(--ec-action-primary);border-color:var(--ec-action-primary);color:var(--ec-action-on-primary)}.btn.primary:hover{background:var(--ec-action-primary-hover);border-color:var(--ec-action-primary-hover)}.btn.primary:active{background:var(--ec-action-primary-active);border-color:var(--ec-action-primary-active)}.hint{color:var(--ec-fg-muted);font-size:var(--ec-font-size-sm);margin:var(--ec-space-2)0 var(--ec-space-3)}.hint-row{flex:none}.matched-pill,.tabulator .tabulator-col .tabulator-col-title{font-size:var(--ec-font-size-sm);font-weight:var(--ec-font-weight-strong)}.matched-pill{display:inline-flex;align-items:center;border-radius:var(--ec-radius-pill);padding:1px var(--ec-space-2);color:var(--ec-status-info);background:var(--ec-status-info-bg);white-space:nowrap}#table,code{border:1px solid var(--ec-border-card)}code{font-family:var(--ec-font-mono);background:var(--ec-bg-surface-alt);border-radius:var(--ec-radius-input);padding:0 5px}#table{border-radius:var(--ec-radius-card);overflow:hidden;flex:1;min-height:0}.tabulator{border:0;background:var(--ec-bg-surface);color:var(--ec-fg-body)}.tabulator .tabulator-header{position:sticky;top:0;z-index:20;background:var(--ec-bg-surface);border-bottom:1px solid var(--ec-border-table-row)}.tabulator .tabulator-col{border-right:1px solid var(--ec-border-table-row);background:var(--ec-bg-surface)}.tabulator .tabulator-col .tabulator-col-title{color:var(--ec-fg-muted);text-transform:uppercase;letter-spacing:.03em}.context-menu,.tabulator .tabulator-header .tabulator-col input{background:var(--ec-bg-surface);border-radius:var(--ec-radius-input)}.tabulator .tabulator-header .tabulator-col input{border:1px solid var(--ec-border-input);padding:4px 6px;color:var(--ec-fg-body);font-size:var(--ec-font-size-sm)}.tabulator .tabulator-row{border-bottom:1px solid var(--ec-border-table-row)}.context-menu button:hover,.tabulator .tabulator-row:hover{background:var(--ec-bg-surface-alt)}.tabulator .tabulator-cell{border-right:1px solid var(--ec-border-table-row);padding:var(--ec-space-2) var(--ec-space-3)}.tabulator .tabulator-footer{background:var(--ec-bg-surface);border-top:1px solid var(--ec-border-table-row)}#status,.context-menu button{font-size:var(--ec-font-size-sm)}#status{margin-top:var(--ec-space-3);color:var(--ec-fg-muted);flex:none}.context-menu{position:fixed;z-index:10000;min-width:260px;border:1px solid var(--ec-border-card);box-shadow:0 4px 14px rgba(0,0,0,.18);padding:4px 0;display:none}.context-menu.open{display:block}.context-menu button{width:100%;border:0;background:0 0;color:var(--ec-fg-body);text-align:left;padding:8px 12px;cursor:pointer}
  </style>
</head>
<body>
  <header class="topbar">
    <span class="brand">NVD PC Report</span>
    <span class="small-muted">Origin: __ORIGIN__ | Generated: __GENERATED_AT__</span>
  </header>
  <main class="content">
    <div class="wrap">
      <div class="card">
        <div class="card-head"><h1>Prism Central Entities</h1></div>
        <div class="card-body">
          <div class="toolbar">
            <select id="datasetSelect" class="input"></select>
            <input id="sql" class="input sql" type="text" value="SELECT * FROM ? WHERE 1=1" />
            <button class="btn primary" id="runSql">Run SQL</button>
            <button class="btn" id="resetSql">Reset</button>
            <button class="btn" id="downloadCsv">Export CSV</button>
            <button class="btn" id="downloadInventory" style="display:none">Export inventory.ini</button>
          </div>
          <div class="hint-row">
            <span id="matchedRowsTop" class="matched-pill">Matched rows: 0</span>
            <div class="hint">
              SQL examples:
              <code>SELECT * FROM ? WHERE `name` LIKE '%az01%'</code> |
              <code>SELECT name, ext_id FROM ? WHERE `cluster` LIKE '%az01app01%'</code>
            </div>
          </div>
          <div id="table"></div>
          <div id="status" class="hint"></div>
        </div>
      </div>
    </div>
  </main>
  <div id="cellContextMenu" class="context-menu" role="menu" aria-hidden="true"></div>
  <script src="https://cdn.jsdelivr.net/npm/alasql@4.6/dist/alasql.min.js"></script>
  <script src="https://unpkg.com/tabulator-tables@6.3.0/dist/js/tabulator.min.js"></script>
  <script>
    const dataSets = __DATASETS_JSON__;
    const datasetKeys = Object.keys(dataSets);
    const datasetSelect = document.getElementById("datasetSelect");
    const sqlInput = document.getElementById("sql");
    const statusEl = document.getElementById("status");
    const matchedRowsTopEl = document.getElementById("matchedRowsTop");
    const contextMenuEl = document.getElementById("cellContextMenu");
    const downloadInventoryBtn = document.getElementById("downloadInventory");
    const csvBaseName = "__CSV_BASE_NAME__";
    const defaultQuery = "SELECT * FROM ? WHERE 1=1";
    let currentDatasetKey = datasetKeys[0] || "";
    let originalData = currentDatasetKey ? [...dataSets[currentDatasetKey]] : [];
    let currentData = [...originalData];
    let contextCell = null;
    let previousHeaderFilterCount = 0;
    const sqlByDataset = {};
    let isSwitchingDataset = false;

    const updateStatus = (text) => {
      statusEl.textContent = text;
      matchedRowsTopEl.textContent = text.startsWith("Matched rows:") ? text : matchedRowsTopEl.textContent;
    };
    const refreshMatchedStatus = (count) => updateStatus(`Matched rows: ${count}`);
    const toComparableString = (value) => Array.isArray(value) ? value.join(", ") : String(value ?? "");
    const normalizeSqlQuery = (query) => query.replace(/CAST\\(\\s*`([^`]+)`\\s+AS\\s+STRING\\s*\\)/gi, "`$1`");

    const runDeterministicLikeQuery = (query) => {
      const normalized = normalizeSqlQuery(query).trim();
      const match = normalized.match(/^SELECT\\s+\\*\\s+FROM\\s+\\?\\s+WHERE\\s+(.+)$/i);
      if (!match) return null;
      const conditions = match[1].split(/\\s+AND\\s+/i).map((x) => x.trim()).filter(Boolean);
      const parsed = [];
      for (const condition of conditions) {
        if (condition === "1=1") continue;
        const condMatch = condition.match(/^`([^`]+)`\\s+LIKE\\s+'%(.*)%'$/i);
        if (!condMatch) return null;
        parsed.push({ field: condMatch[1], needle: condMatch[2].replace(/''/g, "'").toLowerCase() });
      }
      return originalData.filter((row) => parsed.every(({ field, needle }) => toComparableString(row[field]).toLowerCase().includes(needle)));
    };

    const runQuery = (query) => {
      const normalized = normalizeSqlQuery(query);
      let result = runDeterministicLikeQuery(normalized);
      if (result === null) result = alasql(normalized, [originalData]);
      return { normalized, result };
    };

    const escapeSqlValue = (value) => String(value).replace(/'/g, "''");
    const escapeSqlField = (field) => String(field).replace(/`/g, "``");
    const buildSqlFromHeaderFilters = (headerFilters) => {
      if (!headerFilters.length) return "SELECT * FROM ? WHERE 1=1";
      const whereClauses = headerFilters
        .filter((flt) => flt && flt.field && flt.value !== null && flt.value !== undefined && String(flt.value).trim() !== "")
        .map((flt) => {
          const field = escapeSqlField(flt.field);
          const value = escapeSqlValue(String(flt.value).trim());
          return `CAST(\`${field}\` AS STRING) LIKE '%${value}%'`;
        });
      if (!whereClauses.length) return "SELECT * FROM ? WHERE 1=1";
      return `SELECT * FROM ? WHERE ${whereClauses.join(" AND ")}`;
    };

    const inferColumns = (rows) => {
      if (!rows.length) return [];
      return Object.keys(rows[0]).map((key) => ({
        title: key,
        field: key,
        headerFilter: true,
        sorter: "string",
        formatter: (cell) => toComparableString(cell.getValue()),
      }));
    };

    let table = new Tabulator("#table", {
      data: currentData,
      layout: "fitDataTable",
      height: "100%",
      movableColumns: true,
      columns: inferColumns(currentData),
    });

    const applySqlForCurrentDataset = (queryText) => {
      const query = (queryText || defaultQuery).trim();
      try {
        const { normalized, result } = runQuery(query);
        if (!Array.isArray(result)) {
          updateStatus("SQL executed, but result is not a row set.");
          return;
        }
        sqlInput.value = normalized;
        sqlByDataset[currentDatasetKey] = normalized;
        currentData = result;
        table.setData(result);
        refreshMatchedStatus(result.length);
      } catch (err) {
        updateStatus(`SQL error: ${err.message}`);
      }
    };

    const rebuildTableForDataset = () => {
      isSwitchingDataset = true;
      table.clearHeaderFilter();
      table.clearFilter();
      originalData = currentDatasetKey ? [...dataSets[currentDatasetKey]] : [];
      currentData = [...originalData];
      table.setColumns(inferColumns(originalData));
      table.setData(originalData);
      const restoredQuery = sqlByDataset[currentDatasetKey] || defaultQuery;
      sqlInput.value = restoredQuery;
      previousHeaderFilterCount = 0;
      downloadInventoryBtn.style.display = currentDatasetKey === "vms" ? "inline-flex" : "none";
      applySqlForCurrentDataset(restoredQuery);
      isSwitchingDataset = false;
    };

    const toCsv = (rows) => {
      if (!rows.length) return "";
      const headers = Object.keys(rows[0]);
      const escapeCsv = (value) => {
        const normalized = toComparableString(value);
        return /[",\\n]/.test(normalized) ? `"${normalized.replace(/"/g, '""')}"` : normalized;
      };
      const lines = [headers.join(",")];
      for (const row of rows) lines.push(headers.map((h) => escapeCsv(row[h])).join(","));
      return lines.join("\\n");
    };

    datasetKeys.forEach((key) => {
      const option = document.createElement("option");
      option.value = key;
      option.textContent = `${key} (${(dataSets[key] || []).length})`;
      datasetSelect.appendChild(option);
    });
    datasetSelect.value = currentDatasetKey;
    sqlByDataset[currentDatasetKey] = defaultQuery;
    downloadInventoryBtn.style.display = currentDatasetKey === "vms" ? "inline-flex" : "none";
    datasetSelect.addEventListener("change", () => {
      sqlByDataset[currentDatasetKey] = sqlInput.value.trim() || defaultQuery;
      currentDatasetKey = datasetSelect.value;
      rebuildTableForDataset();
    });

    document.getElementById("runSql").addEventListener("click", () => {
      applySqlForCurrentDataset(sqlInput.value);
    });

    document.getElementById("resetSql").addEventListener("click", () => {
      sqlInput.value = defaultQuery;
      sqlByDataset[currentDatasetKey] = defaultQuery;
      table.clearHeaderFilter();
      table.clearFilter();
      currentData = [...originalData];
      table.setData(currentData);
      refreshMatchedStatus(currentData.length);
    });

    document.getElementById("downloadCsv").addEventListener("click", () => {
      const rows = table.getRows("active").map((row) => row.getData());
      const exportRows = rows.length ? rows : currentData;
      const content = toCsv(exportRows);
      const blob = new Blob([content], { type: "text/csv;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${csvBaseName}_${currentDatasetKey}.csv`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      updateStatus(`Matched rows: ${exportRows.length}`);
    });

    const toArray = (value) => {
      if (Array.isArray(value)) return value;
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
      const guestOs = String(row.guest_os || "").toLowerCase();
      if (guestOs.includes("windows")) return "windows_vms";
      if (
        guestOs.includes("linux") ||
        guestOs.includes("ubuntu") ||
        guestOs.includes("red hat") ||
        guestOs.includes("rhel") ||
        guestOs.includes("centos") ||
        guestOs.includes("debian") ||
        guestOs.includes("suse")
      ) return "linux_vms";
      const name = String(row.name || "").toLowerCase();
      if (/w\\d+$/.test(name) || name.includes("windows")) return "windows_vms";
      if (/l\\d+$/.test(name) || name.includes("linux")) return "linux_vms";
      return "other_vms";
    };

    const toInventoryIni = (rows) => {
      const groups = { linux_vms: [], windows_vms: [], other_vms: [] };
      rows.forEach((row) => {
        const vmName = String(row.name || "").trim();
        if (!vmName) return;
        const learnedIps = toArray(row.learned_ip_addresses).map((ip) => String(ip || "").trim()).filter(Boolean);
        const ansibleHost = learnedIps.length ? learnedIps[0] : "";
        const inventoryLine = ansibleHost ? `${vmName} ansible_host=${ansibleHost}` : vmName;
        groups[inferVmGroup(row)].push(inventoryLine);
      });
      return [
        "# Generated from current report filter",
        `# Total VMs: ${rows.length}`,
        "",
        "[linux_vms]", ...groups.linux_vms, "",
        "[windows_vms]", ...groups.windows_vms, "",
        "[other_vms]", ...groups.other_vms, "",
        "[nutanix_vms:children]",
        "linux_vms",
        "windows_vms",
        "other_vms",
        "",
      ].join("\\n");
    };

    downloadInventoryBtn.addEventListener("click", () => {
      const rows = table.getRows("active").map((row) => row.getData());
      const exportRows = rows.length ? rows : currentData;
      const iniContent = toInventoryIni(exportRows);
      const blob = new Blob([iniContent], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${csvBaseName}_vms_inventory.ini`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      updateStatus(`Matched rows: ${exportRows.length}`);
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
      if (!target || !target.dataset || target.dataset.action !== "add-column-filter") return;
      if (!contextCell) {
        hideContextMenu();
        return;
      }
      table.setHeaderFilterValue(contextCell.field, contextCell.value);
      hideContextMenu();
    });
    document.addEventListener("click", () => hideContextMenu());
    document.addEventListener("keydown", (event) => { if (event.key === "Escape") hideContextMenu(); });
    window.addEventListener("resize", () => hideContextMenu());
    window.addEventListener("scroll", () => hideContextMenu(), true);
    table.on("cellContext", (event, cell) => showContextMenu(event, cell));

    table.on("dataFiltered", () => {
      if (isSwitchingDataset) {
        return;
      }
      const headerFilters = table.getHeaderFilters() || [];
      if (headerFilters.length > 0) {
        sqlInput.value = buildSqlFromHeaderFilters(headerFilters);
      } else if (previousHeaderFilterCount > 0) {
        sqlInput.value = defaultQuery;
      }
      previousHeaderFilterCount = headerFilters.length;

      try {
        const { normalized, result } = runQuery(sqlInput.value.trim());
        if (Array.isArray(result)) {
          if (normalized !== sqlInput.value.trim()) {
            sqlInput.value = normalized;
          }
          sqlByDataset[currentDatasetKey] = sqlInput.value.trim() || defaultQuery;
          refreshMatchedStatus(result.length);
          return;
        }
      } catch (err) {
        // Keep UI responsive while query text is temporarily invalid.
      }

      const rows = table.getRows("active").map((row) => row.getData());
      refreshMatchedStatus(rows.length);
    });

    refreshMatchedStatus(currentData.length);
  </script>
</body>
</html>
"""

    html_content = html_content.replace("__DATASETS_JSON__", data_sets_json)
    html_content = html_content.replace("__ORCHESTRATOR_CSS__", orchestrator_css)
    html_content = html_content.replace("__ORIGIN__", str(origin or "unknown"))
    html_content = html_content.replace("__GENERATED_AT__", generated_at)
    html_content = html_content.replace("__CSV_BASE_NAME__", csv_base_name)
    with open(output_file, "w", encoding="utf-8") as html_file:
        html_file.write(html_content)

def main(api_server,username,secret,secure=False):
    '''main function.
        Args:
            api_server: IP or FQDN of the REST API server.
            username: Username to use for authentication.
            secret: Secret for the username.
            secure: indicates if certs should be verified.
        Returns:
    '''

    LENGTH=100
    
    #region clusters
    #* initialize variable for API client configuration
    api_client_configuration = ntnx_clustermgmt_py_client.Configuration()
    api_client_configuration.host = api_server
    api_client_configuration.username = username
    api_client_configuration.password = secret

    if secure is False:
        #! suppress warnings about insecure connections
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        #! suppress ssl certs verification
        api_client_configuration.verify_ssl = False
   
    #* getting list of clusters
    client = ntnx_clustermgmt_py_client.ApiClient(configuration=api_client_configuration)
    entity_api = ntnx_clustermgmt_py_client.ClustersApi(api_client=client)
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching Clusters...{PrintColors.RESET}")
    entity_list=[]
    response = entity_api.list_clusters(_page=0,_limit=1)
    total_available_results=response.metadata.total_available_results
    page_count = math.ceil(total_available_results/LENGTH)
    with tqdm.tqdm(total=page_count, desc="Fetching entity pages") as progress_bar:  
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(
                    fetch_entities,
                    module=ntnx_clustermgmt_py_client,
                    entity_api='ClustersApi',
                    client=client,
                    function='list_clusters',
                    page=page_number,
                    limit=LENGTH
                ) for page_number in range(0, page_count, 1)]
            for future in as_completed(futures):
                try:
                    entities = future.result()
                    entity_list.extend(entities.data)
                except Exception as e:
                    print(f"{PrintColors.WARNING}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Task failed: {e}{PrintColors.RESET}")
                finally:
                    progress_bar.update(1)
    print(f"{PrintColors.SUCCESS}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [SUCCESS] {len(entity_list)} entities found.{PrintColors.RESET}")
    cluster_list = entity_list

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
            'ncc_version': next(iter({ software.version for software in entity.config.cluster_software_map if software.software_type == "NCC" }),''),
            'aos_full_version': entity.config.build_info.full_version,
            'aos_commit_id': entity.config.build_info.short_commit_id,
            'aos_version': entity.config.build_info.version,
            'is_segmentation_enabled': entity.network.backplane.is_segmentation_enabled,
            'external_address_ipv4': entity.network.external_address.ipv4.value,
            'external_data_service_ipv4': entity.network.external_data_service_ip.ipv4.value,
            'external_subnet': entity.network.external_subnet,
            'name_server_ipv4_list': list({ name_server.ipv4.value for name_server in entity.network.name_server_ip_list}),
            'ntp_server_list': "",
            'number_of_nodes': entity.nodes.number_of_nodes,
        }
        if "fqdn" in entity.network.ntp_server_ip_list:
            entity_output['ntp_server_list'] = list({ ntp_server.fqdn.value for ntp_server in entity.network.ntp_server_ip_list})
        elif "ipv4" in entity.network.ntp_server_ip_list:
            entity_output['ntp_server_list'] = list({ ntp_server.ipv4.value for ntp_server in entity.network.ntp_server_ip_list})
        
        cluster_list_output.append(entity_output)
    #endregion clusters

    #region hosts
    #* getting list of hosts
    client = ntnx_clustermgmt_py_client.ApiClient(configuration=api_client_configuration)
    entity_api = ntnx_clustermgmt_py_client.ClustersApi(api_client=client)
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching Hosts...{PrintColors.RESET}")
    entity_list=[]
    response = entity_api.list_hosts(_page=0,_limit=1)
    total_available_results=response.metadata.total_available_results
    page_count = math.ceil(total_available_results/LENGTH)
    with tqdm.tqdm(total=page_count, desc="Fetching entity pages") as progress_bar:    
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(
                    fetch_entities,
                    module=ntnx_clustermgmt_py_client,
                    entity_api='ClustersApi',
                    client=client,
                    function='list_hosts',
                    page=page_number,
                    limit=LENGTH
                ) for page_number in range(0, page_count, 1)]
            for future in as_completed(futures):
                try:
                    entities = future.result()
                    entity_list.extend(entities.data)
                except Exception as e:
                    print(f"{PrintColors.WARNING}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Task failed: {e}{PrintColors.RESET}")
                finally:
                    progress_bar.update(1)
    print(f"{PrintColors.SUCCESS}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [SUCCESS] {len(entity_list)} entities found.{PrintColors.RESET}")
    host_list = entity_list
    
    #* format output
    host_list_output = []
    for entity in host_list:
        entity_output = {
            'cluster': entity.cluster.name,
            'name': entity.host_name,
            'ext_id': entity.ext_id,
            'type': entity.host_type,
            'connection_state': entity.hypervisor.acropolis_connection_state,
            'hypervisor_ip': entity.hypervisor.external_address.ipv4.value,
            'cvm_ip': entity.controller_vm.external_address.ipv4.value,
            'ipmi_ip': entity.ipmi.ip.ipv4.value,
            'hypervisor': entity.hypervisor.type,
            'hypervisor_full_name': entity.hypervisor.full_name,
            'vms_qty': entity.hypervisor.number_of_vms,
            'acropolis_state': entity.hypervisor.state,
            'maintenance_state': entity.maintenance_state,
            'is_secure_booted': entity.is_secure_booted,
            'cpu_model': entity.cpu_model,
            'cpu_frequency_hz': entity.cpu_frequency_hz,
            'number_of_cpu_cores': entity.number_of_cpu_cores,
            'number_of_cpu_sockets': entity.number_of_cpu_sockets,
            'number_of_cpu_threads': entity.number_of_cpu_threads,
            'cpu_capacity_hz': entity.cpu_capacity_hz,
            'memory_size_bytes': entity.memory_size_bytes,
            'block_model': entity.block_model,
            'block_serial': entity.block_serial,
            'uptime': format_timespan(entity.boot_time_usecs/1000000000),
            'disks_serials': list({ disk.serial_id for disk in entity.disk}) if entity.disk else [],
            'disks_storage_tier': list({ disk.storage_tier for disk in entity.disk}) if entity.disk else [],
            'disks_size_in_bytes': list({ disk.size_in_bytes for disk in entity.disk}) if entity.disk else [],
            'gpu_list': entity.gpu_list if hasattr(entity, 'gpu_list') else [],
            'gpu_driver_version': entity.gpu_driver_version if hasattr(entity, 'gpu_list') else '',
        }
        
        host_list_output.append(entity_output)    
    #endregion hosts

    #region storage containers
    #* getting list of storage containers
    client = ntnx_clustermgmt_py_client.ApiClient(configuration=api_client_configuration)
    entity_api = ntnx_clustermgmt_py_client.StorageContainersApi(api_client=client)
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching Storage Containers...{PrintColors.RESET}")
    entity_list=[]
    response = entity_api.list_storage_containers(_page=0,_limit=1)
    total_available_results=response.metadata.total_available_results
    page_count = math.ceil(total_available_results/LENGTH)
    with tqdm.tqdm(total=page_count, desc="Fetching entity pages") as progress_bar:    
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(
                    fetch_entities,
                    module=ntnx_clustermgmt_py_client,
                    entity_api='StorageContainersApi',
                    client=client,
                    function='list_storage_containers',
                    page=page_number,
                    limit=LENGTH
                ) for page_number in range(0, page_count, 1)]
            for future in as_completed(futures):
                try:
                    entities = future.result()
                    entity_list.extend(entities.data)
                except Exception as e:
                    print(f"{PrintColors.WARNING}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Task failed: {e}{PrintColors.RESET}")
                finally:
                    progress_bar.update(1)
    print(f"{PrintColors.SUCCESS}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [SUCCESS] {len(entity_list)} entities found.{PrintColors.RESET}")
    storage_container_list = entity_list
    
    #* format output
    storage_container_list_output = []
    for entity in storage_container_list:
        entity_output = {
            'name': entity.name,
            'ext_id': entity.container_ext_id,
            'cluster': entity.cluster_name,
            'replication_factor': entity.replication_factor,
            'cache_deduplication': entity.cache_deduplication,
            'on_disk_dedup': entity.on_disk_dedup,
            'erasure_code': entity.erasure_code,
            'is_compression_enabled': entity.is_compression_enabled,
            'compression_delay_secs': entity.compression_delay_secs,
            'is_inline_ec_enabled': entity.is_inline_ec_enabled,
            'is_software_encryption_enabled': entity.is_software_encryption_enabled,
            'max_capacity_bytes': entity.max_capacity_bytes,
            'logical_explicit_reserved_capacity_bytes': entity.logical_explicit_reserved_capacity_bytes,
        }
        
        storage_container_list_output.append(entity_output)
    #endregion storage containers

    #region subnets
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
    client = ntnx_networking_py_client.ApiClient(configuration=api_client_configuration)
    entity_api = ntnx_networking_py_client.SubnetsApi(api_client=client)
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching Subnets...{PrintColors.RESET}")
    entity_list=[]
    response = entity_api.list_subnets(_page=0,_limit=1)
    total_available_results=response.metadata.total_available_results
    page_count = math.ceil(total_available_results/LENGTH)
    with tqdm.tqdm(total=page_count, desc="Fetching entity pages") as progress_bar:    
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(
                    fetch_entities,
                    module=ntnx_networking_py_client,
                    entity_api='SubnetsApi',
                    client=client,
                    function='list_subnets',
                    page=page_number,
                    limit=LENGTH
                ) for page_number in range(0, page_count, 1)]
            for future in as_completed(futures):
                try:
                    entities = future.result()
                    entity_list.extend(entities.data)
                except Exception as e:
                    print(f"{PrintColors.WARNING}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Task failed: {e}{PrintColors.RESET}")
                finally:
                    progress_bar.update(1)
    print(f"{PrintColors.SUCCESS}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [SUCCESS] {len(entity_list)} entities found.{PrintColors.RESET}")
    subnet_list = entity_list
    
    #* format output
    subnet_list_output = []
    #todo: add virtual switch reference (will require listing virtual switches as separate entities)
    for entity in subnet_list:
        entity_output = {
            'name': entity.name,
            'ext_id': entity.ext_id,
            'cluster': next(iter({ cluster['name'] for cluster in cluster_list_output if cluster['ext_id'] == entity.cluster_reference }),'') if hasattr(entity, 'cluster_reference') else '',
            'network_id': entity.network_id,
            'subnet_type': entity.subnet_type,
            'bridge_name': entity.bridge_name,
            'hypervisor_type': entity.hypervisor_type,
            'is_advanced_networking': entity.is_advanced_networking,
            'owner': entity.metadata.owner_user_name,
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
    client = ntnx_prism_py_client.ApiClient(configuration=api_client_configuration)
    entity_api = ntnx_prism_py_client.CategoriesApi(api_client=client)
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching Categories...{PrintColors.RESET}")
    entity_list=[]
    response = entity_api.list_categories(_page=0,_limit=1)
    total_available_results=response.metadata.total_available_results
    page_count = math.ceil(total_available_results/LENGTH)
    with tqdm.tqdm(total=page_count, desc="Fetching entity pages") as progress_bar:    
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(
                    fetch_entities,
                    module=ntnx_prism_py_client,
                    entity_api='CategoriesApi',
                    client=client,
                    function='list_categories',
                    page=page_number,
                    limit=LENGTH
                ) for page_number in range(0, page_count, 1)]
            for future in as_completed(futures):
                try:
                    entities = future.result()
                    entity_list.extend(entities.data)
                except Exception as e:
                    print(f"{PrintColors.WARNING}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Task failed: {e}{PrintColors.RESET}")
                finally:
                    progress_bar.update(1)
    print(f"{PrintColors.SUCCESS}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [SUCCESS] {len(entity_list)} entities found.{PrintColors.RESET}")
    category_list = entity_list
    
    #* format output
    category_list_output = []
    for entity in category_list:
        entity_output = {
            'name': f"{entity.key}:{entity.value}",
            'ext_id': entity.ext_id,
            'key': entity.key,
            'value': entity.value,
            'description': entity.description,
            'type': entity.type,
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
    client = ntnx_iam_py_client.ApiClient(configuration=api_client_configuration)
    entity_api = ntnx_iam_py_client.UsersApi(api_client=client)
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching Users...{PrintColors.RESET}")
    entity_list=[]
    response = entity_api.list_users(_page=0,_limit=1)
    total_available_results=response.metadata.total_available_results
    page_count = math.ceil(total_available_results/LENGTH)
    with tqdm.tqdm(total=page_count, desc="Fetching entity pages") as progress_bar:    
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(
                    fetch_entities,
                    module=ntnx_iam_py_client,
                    entity_api='UsersApi',
                    client=client,
                    function='list_users',
                    page=page_number,
                    limit=LENGTH
                ) for page_number in range(0, page_count, 1)]
            for future in as_completed(futures):
                try:
                    entities = future.result()
                    entity_list.extend(entities.data)
                except Exception as e:
                    print(f"{PrintColors.WARNING}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Task failed: {e}{PrintColors.RESET}")
                finally:
                    progress_bar.update(1)
    print(f"{PrintColors.SUCCESS}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [SUCCESS] {len(entity_list)} entities found.{PrintColors.RESET}")
    user_list = entity_list
    
    #* format output
    user_list_output = []
    for entity in user_list:
        entity_output = {
            'name': entity.username,
            'ext_id': entity.ext_id,
            'type': entity.user_type,
            'description': entity.description,
            'display_name': entity.display_name,
            'first_name': entity.first_name,
            'middle_initial': entity.middle_initial,
            'last_name': entity.last_name,
            'status': entity.status,
            'is_force_reset_password_enabled': entity.is_force_reset_password_enabled,
            'created_time': entity.created_time,
            'last_updated_time': entity.last_updated_time,
            'last_login_time': entity.last_login_time,
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
    client = ntnx_vmm_py_client.ApiClient(configuration=api_client_configuration)
    entity_api = ntnx_vmm_py_client.VmApi(api_client=client)
    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Fetching VMs...{PrintColors.RESET}")
    entity_list=[]
    response = entity_api.list_vms(_page=0,_limit=1)
    total_available_results=response.metadata.total_available_results
    page_count = math.ceil(total_available_results/LENGTH)
    with tqdm.tqdm(total=page_count, desc="Fetching entity pages") as progress_bar:    
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(
                    fetch_entities,
                    module=ntnx_vmm_py_client,
                    entity_api='VmApi',
                    client=client,
                    function='list_vms',
                    page=page_number,
                    limit=LENGTH
                ) for page_number in range(0, page_count, 1)]
            for future in as_completed(futures):
                try:
                    entities = future.result()
                    entity_list.extend(entities.data)
                except Exception as e:
                    print(f"{PrintColors.WARNING}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Task failed: {e}{PrintColors.RESET}")
                finally:
                    progress_bar.update(1)
    print(f"{PrintColors.SUCCESS}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [SUCCESS] {len(entity_list)} entities found.{PrintColors.RESET}")
    vm_list = entity_list


    #* format output
    vm_list_output = []
    boot_config = ''
    #TODO: deal appropriately with vms that use vgs instead of vdisks. This will require extracting the list of volume groups before extracting the list of vms.  The object type in backing info will be vmm.v4.ahv.config.ADSFVolumeGroupReference and backing info will contain the vg reference in volumeGroupExtId. Then use {{baseUrl}}/volumes/v4.1/config/volume-groups/{{volumeGroupExtId}}/disks?$page=0 and get the disk size from data[index]['disk_size_bytes']
    for entity in vm_list:
        entity_output = {
            'name': entity.name,
            'ext_id': entity.ext_id,
            'cluster': next(iter({ cluster['name'] for cluster in cluster_list_output if cluster['ext_id'] == entity.cluster.ext_id }),'') if hasattr(entity.cluster, 'ext_id') else '',
            'host': next(iter({ host['name'] for host in host_list_output if host['ext_id'] == entity.host.ext_id })) if hasattr(entity.host, 'ext_id') else '',
            'num_cores_per_socket': entity.num_cores_per_socket,
            'num_numa_nodes': entity.num_numa_nodes,
            'num_sockets': entity.num_sockets,
            'num_threads_per_core': entity.num_threads_per_core,
            'memory_size_bytes': entity.memory_size_bytes,
            'power_state': entity.power_state,
            'protection_type': entity.protection_type,
            'machine_type': entity.machine_type,
            'vm_uptime': format_vm_uptime(entity),
            'guest_os': getattr(entity, 'guest_os_name', '') or '',
            'guest_tools_version': '',
            'guest_tools_available_version': '',
            'guest_tools_enabled': '',
            'guest_tools_capabilities': '',
            'is_agent_vm': entity.is_agent_vm,
            'is_cpu_hotplug_enabled': entity.is_cpu_hotplug_enabled,
            'is_memory_overcommit_enabled': entity.is_memory_overcommit_enabled,
            'is_vtpm_enabled': entity.vtpm_config.is_vtpm_enabled,
            'is_gpu_console_enabled': entity.is_gpu_console_enabled,
            'boot_type': '',
            'is_secure_boot_enabled': '',
            'boot_order': entity.boot_config.boot_order,
            'cdroms': list({ cdrom.disk_address.bus_type for cdrom in entity.cd_roms}) if entity.cd_roms else [],
            'disks': list({ disk.disk_address.bus_type for disk in entity.disks}) if entity.disks else [],
            'disks_bytes': list({ getattr(disk.backing_info, 'disk_size_bytes', 0) for disk in entity.disks if hasattr(disk, 'backing_info') }) if entity.disks else [],
            'disks_bytes_total': sum(
                getattr(disk.backing_info, 'disk_size_bytes', 0)
                for disk in entity.disks
                if hasattr(disk, 'backing_info') and getattr(disk.backing_info, 'disk_size_bytes', None) is not None
            ) if entity.disks else 0,
            'storage_containers': [],
            'categories': [],
            'mac_addresses': list({ vnic.backing_info.mac_address for vnic in entity.nics}) if entity.nics else [],
            'vnic_connection_status': list({ vnic.backing_info.is_connected for vnic in entity.nics}) if entity.nics else [],
            'vnic_types': list({ vnic.network_info.nic_type for vnic in entity.nics}) if entity.nics else [],
            'vnic_vlan_mode': list({ vnic.network_info.vlan_mode for vnic in entity.nics}) if entity.nics else [],
            'learned_ip_addresses': [],
            'subnets': [],
            'owner': (
                next(
                    iter({
                        entry['name']
                        for entry in user_list_output
                        if hasattr(entity, 'ownership_info')
                        and hasattr(entity.ownership_info, 'owner')
                        and hasattr(entity.ownership_info.owner, 'ext_id')
                        and entry['ext_id'] == entity.ownership_info.owner.ext_id
                    }),
                    ''
                )
            ),
        }

        #getting ngt information
        if entity.guest_tools:
            entity_output['guest_tools_version'] = getattr(entity.guest_tools, 'version', '')
            entity_output['guest_tools_available_version'] = getattr(entity.guest_tools, 'available_version', '')
            if not entity_output['guest_os']:
                entity_output['guest_os'] = getattr(entity.guest_tools, 'guest_os_version', '') or ''
            entity_output['guest_tools_enabled'] = entity.guest_tools.is_enabled
            entity_output['guest_tools_capabilities'] = entity.guest_tools.capabilities

        #getting boot information
        boot_config=(entity.boot_config._object_type).split('.')
        entity_output['boot_type'] = boot_config[len(boot_config)-1]
        if entity_output['boot_type'] == 'UefiBoot':
            entity_output['is_secure_boot_enabled'] = entity.boot_config.is_secure_boot_enabled

        #getting categories
        if entity.categories:
            for category in entity.categories:
                entity_output['categories'].append(next(iter({ entry['name'] for entry in category_list_output if entry['ext_id'] == category.ext_id }),''))

        #getting storage containers
        if entity.disks:
            for disk in entity.disks:
                if hasattr(disk, 'backing_info') and hasattr(disk.backing_info, 'storage_container') and hasattr(disk.backing_info.storage_container, 'ext_id'):
                    entity_output['storage_containers'].append(
                        next(
                            iter({
                                storage_container['name']
                                for storage_container in storage_container_list_output
                                if storage_container['ext_id'] == disk.backing_info.storage_container.ext_id
                            }),
                            ''
                        )
                )

        #getting ip_addresses and subnets
        if entity.nics:
            for vnic in entity.nics:
                network_info = getattr(vnic, 'network_info', None)
                ipv4_info = getattr(network_info, 'ipv4_info', None)
                learned_ip_addresses = getattr(ipv4_info, 'learned_ip_addresses', None)
                if learned_ip_addresses:
                    for ip_address in learned_ip_addresses:
                        ip_value = getattr(ip_address, 'value', None)
                        if ip_value:
                            entity_output['learned_ip_addresses'].append(ip_value)
                # Fall back to configured NIC IPs when learned IPs are not populated.
                for info_obj in [network_info, getattr(vnic, 'nic_network_info', None)]:
                    ipv4_config = getattr(info_obj, 'ipv4_config', None) if info_obj else None
                    primary_ip = getattr(getattr(ipv4_config, 'ip_address', None), 'value', None) if ipv4_config else None
                    if primary_ip:
                        entity_output['learned_ip_addresses'].append(primary_ip)
                    for secondary_ip in (getattr(ipv4_config, 'secondary_ip_address_list', None) or []):
                        secondary_value = getattr(secondary_ip, 'value', None)
                        if secondary_value:
                            entity_output['learned_ip_addresses'].append(secondary_value)

                subnet_ext_id = getattr(getattr(network_info, 'subnet', None), 'ext_id', None)
                entity_output['subnets'].append(next(iter({ subnet['name'] for subnet in subnet_list_output if subnet['ext_id'] == subnet_ext_id }),''))
        
        vm_list_output.append(entity_output)
    #endregion vms

    #region html report
    #* exporting to html and csv
    safe_origin = "".join(char if (char.isalnum() or char in ("-", "_")) else "_" for char in str(api_server or "unknown"))
    report_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_base_name = f"{safe_origin}_{report_timestamp}_get_pc_report"
    html_file_name = f"{report_base_name}.html"
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")

    data_sets = {
        "vms": vm_list_output,
        "clusters": cluster_list_output,
        "hosts": host_list_output,
        "storage_containers": storage_container_list_output,
        "subnets": subnet_list_output,
        "categories": category_list_output,
        "users": user_list_output,
    }

    print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Exporting results to file {html_file_name}.{PrintColors.RESET}")
    write_interactive_html_report(
        data_sets=data_sets,
        output_file=html_file_name,
        origin=api_server,
        generated_at=generated_at,
        csv_base_name=report_base_name,
    )

    for dataset_name, dataset_rows in data_sets.items():
        csv_file_name = f"{report_base_name}_{dataset_name}.csv"
        pandas.DataFrame(dataset_rows).to_csv(csv_file_name, index=False)
        print(f"{PrintColors.OK}{(datetime.now(timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Exported {len(dataset_rows)} {dataset_name} rows to file {csv_file_name}.{PrintColors.RESET}")
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