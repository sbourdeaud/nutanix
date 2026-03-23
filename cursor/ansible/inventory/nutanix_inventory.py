#!/usr/bin/env python3
"""
Nutanix API v4 dynamic inventory for Ansible.

Queries Prism Central for AHV VMs matching specified category key:value pairs
and outputs Ansible-compatible JSON inventory.

Configuration via environment variables (preferred) or config file:
    NUTANIX_HOST          Prism Central IP/FQDN (required)
    NUTANIX_USERNAME      Basic auth username
    NUTANIX_PASSWORD      Basic auth password
    NUTANIX_CATEGORIES    Comma-separated key:value (e.g. Environment:Production,App:Web)
    NUTANIX_CATEGORY_MATCH 'any' (VM has ANY category) or 'all' (VM has ALL categories)
    NUTANIX_CONFIG        Path to YAML config file (vault-encryptable)
    NUTANIX_VERIFY_SSL    Set to 'false' for self-signed certs
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Suppress InsecureRequestWarning when verify=False
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# API paths (Nutanix API v4)
PRISM_CATEGORIES_PATH = "/api/prism/v4.2/config/categories"
VMM_VMS_PATH = "/api/vmm/v4.2/ahv/config/vms"

# Default group name for all matching VMs
DEFAULT_GROUP = "nutanix_vms"

# Valid characters for Ansible host names and group names
HOSTNAME_PATTERN = re.compile(r"[^a-zA-Z0-9_\-]")
GROUP_PATTERN = re.compile(r"[^a-zA-Z0-9_\-]")


class NutanixInventoryError(Exception):
    """Raised when inventory generation fails."""

    pass


def load_config() -> dict[str, Any]:
    """
    Load configuration from environment variables and optional config file.

    Environment variables take precedence. Config file path: NUTANIX_CONFIG
    or default nutanix_inventory.yml alongside this script.

    Returns:
        Configuration dict with host, username, password, categories, etc.

    Raises:
        NutanixInventoryError: If required configuration is missing.
    """
    config: dict[str, Any] = {
        "host": os.environ.get("NUTANIX_HOST", ""),
        "username": os.environ.get("NUTANIX_USERNAME", ""),
        "password": os.environ.get("NUTANIX_PASSWORD", ""),
        "verify_ssl": os.environ.get("NUTANIX_VERIFY_SSL", "false").lower() == "true",
        "ansible_port": int(os.environ.get("NUTANIX_ANSIBLE_PORT", "22")),
        "category_match": (os.environ.get("NUTANIX_CATEGORY_MATCH") or "").lower(),
    }

    # Parse categories from env: comma-separated key:value
    categories_env = os.environ.get("NUTANIX_CATEGORIES", "")
    if categories_env:
        config["categories"] = [s.strip() for s in categories_env.split(",") if s.strip()]
    else:
        config["categories"] = []

    # Load from config file if present
    config_path = os.environ.get("NUTANIX_CONFIG")
    if not config_path:
        script_dir = Path(__file__).resolve().parent
        config_path = script_dir / "nutanix_inventory.yml"

    config_file = Path(config_path)
    if config_file.exists():
        try:
            import yaml

            with open(config_file, encoding="utf-8") as f:
                file_config = yaml.safe_load(f) or {}
            for key, value in file_config.items():
                if key in config and (config[key] is None or config[key] == "" or config[key] == []):
                    config[key] = value
                elif key not in config:
                    config[key] = value
        except ImportError:
            logger.warning("PyYAML not installed; config file ignored. Install with: pip install PyYAML")
        except (OSError, yaml.YAMLError) as e:
            logger.warning("Could not load config file %s: %s", config_file, e)

    # Validate required fields
    if not config.get("host"):
        raise NutanixInventoryError(
            "NUTANIX_HOST is required. Set it or configure 'host' in the config file."
        )
    if not config.get("username") or not config.get("password"):
        raise NutanixInventoryError(
            "NUTANIX_USERNAME and NUTANIX_PASSWORD are required for Basic Auth."
        )
    if not config.get("categories"):
        raise NutanixInventoryError(
            "NUTANIX_CATEGORIES is required. Provide comma-separated key:value pairs "
            "(e.g. Environment:Production,App:Web)."
        )

    if not config.get("category_match"):
        config["category_match"] = "any"
    match_mode = config.get("category_match", "any").lower()
    if match_mode not in ("any", "all"):
        raise NutanixInventoryError(
            f"NUTANIX_CATEGORY_MATCH must be 'any' or 'all', got '{match_mode}'."
        )
    config["category_match"] = match_mode

    return config


def create_session(config: dict[str, Any]) -> requests.Session:
    """
    Create a requests session with retries and authentication.

    Args:
        config: Configuration dict with host, username, password, verify_ssl.

    Returns:
        Configured requests.Session.
    """
    session = requests.Session()
    session.auth = (config["username"], config["password"])
    session.headers.update({"Content-Type": "application/json", "Accept": "application/json"})
    session.verify = config.get("verify_ssl", False)

    retries = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    return session


def resolve_category_ext_ids(
    session: requests.Session,
    base_url: str,
    categories: list[str],
) -> set[str]:
    """
    Resolve category key:value pairs to Prism category extIds.

    Args:
        session: Authenticated requests session.
        base_url: Prism Central base URL (e.g. https://pc.example.com:9440).
        categories: List of "key:value" strings.

    Returns:
        Set of category extIds.
    """
    ext_ids: set[str] = set()

    for item in categories:
        if ":" not in item:
            logger.warning("Invalid category format '%s'; expected key:value", item)
            continue

        key, value = item.split(":", 1)
        key = key.strip()
        value = value.strip()

        if not key or not value:
            continue

        # OData filter: key eq 'X' and value eq 'Y' (escape single quotes in values)
        safe_key = key.replace("'", "''")
        safe_value = value.replace("'", "''")
        odata_filter = f"key eq '{safe_key}' and value eq '{safe_value}'"

        url = f"{base_url}{PRISM_CATEGORIES_PATH}"
        params = {"$filter": odata_filter, "$page": 0, "$limit": 100}
        page = 0

        while True:
            params["$page"] = page
            try:
                resp = session.get(
                    url,
                    params=params,
                    timeout=(5, 30),
                )
                resp.raise_for_status()
            except requests.RequestException as e:
                logger.error("Failed to list categories for %s:%s: %s", key, value, e)
                break

            data = resp.json()
            items = data.get("data") or []

            for cat in items:
                if ext_id := cat.get("extId"):
                    ext_ids.add(ext_id)

            meta = data.get("metadata") or {}
            total = meta.get("totalAvailableResults", 0)
            if page * params["$limit"] + len(items) >= total or not items:
                break
            page += 1

    return ext_ids


def fetch_vms(
    session: requests.Session,
    base_url: str,
) -> list[dict[str, Any]]:
    """
    Fetch all AHV VMs with minimal fields for inventory.

    Args:
        session: Authenticated requests session.
        base_url: Prism Central base URL.

    Returns:
        List of VM objects (extId, name, categories, guestTools, nics).
    """
    url = f"{base_url}{VMM_VMS_PATH}"
    # Include nics with networkInfo for IP extraction (ipv4Config, ipv4Info/learnedIpAddresses)
    select_fields = "extId,name,categories,guestTools,nics"

    all_vms: list[dict[str, Any]] = []
    page = 0
    limit = 100

    while True:
        params = {
            "$page": page,
            "$limit": limit,
            "$select": select_fields,
        }

        try:
            resp = session.get(url, params=params, timeout=(5, 30))
            resp.raise_for_status()
        except requests.RequestException as e:
            logger.error("Failed to list VMs: %s", e)
            raise NutanixInventoryError(f"VM listing failed: {e}") from e

        data = resp.json()
        items = data.get("data") or []

        for vm in items:
            all_vms.append(vm)

        meta = data.get("metadata") or {}
        total = meta.get("totalAvailableResults", 0)

        if page * limit + len(items) >= total or not items:
            break
        page += 1

    return all_vms


def _extract_ip_from_address_obj(obj: dict[str, Any]) -> str | None:
    """Extract IP string from IPv4 address object with value/prefixLength."""
    if not isinstance(obj, dict):
        return None
    val = obj.get("value")
    if val:
        return str(val).strip()
    return None


def get_vm_ip(vm: dict[str, Any]) -> str | None:
    """
    Extract VM IP address from NIC data.

    Tries, in order: learnedIpAddresses (NGT), ipv4Config.ipAddress (static),
    nicNetworkInfo.ipv4Info.learnedIpAddresses, assignedIpAddresses.

    Returns:
        First IP found, or None if no IP is available.
    """
    nics = vm.get("nics") or []
    for nic in nics:
        for network_key in ("networkInfo", "nicNetworkInfo"):
            net_info = nic.get(network_key) or {}
            # Learned IPs from NGT (most reliable for DHCP VMs)
            ipv4_info = net_info.get("ipv4Info") or {}
            learned = ipv4_info.get("learnedIpAddresses") or []
            for addr in learned:
                if isinstance(addr, str) and addr.strip():
                    return addr.strip()
                if isinstance(addr, dict):
                    if ip := _extract_ip_from_address_obj(addr):
                        return ip
            # Static IP from ipv4Config
            ipv4_config = net_info.get("ipv4Config") or {}
            ip_addr = ipv4_config.get("ipAddress") or {}
            if ip := _extract_ip_from_address_obj(ip_addr):
                return ip
        # Top-level assignedIpAddresses (some API versions)
        for addr in nic.get("assignedIpAddresses") or []:
            if ip := _extract_ip_from_address_obj(addr):
                return ip
    return None


def get_ansible_host(vm: dict[str, Any]) -> str:
    """
    Derive ansible_host from VM data.

    Priority: VM IP (from NICs), guestTools.dnsName (NGT), VM name.

    Args:
        vm: VM object from API.

    Returns:
        IP or hostname for Ansible to connect.
    """
    if ip := get_vm_ip(vm):
        return ip

    guest_tools = vm.get("guestTools") or {}
    guest_info = guest_tools.get("guestInfo") or {}
    dns_name = guest_info.get("dnsName") or {}
    if isinstance(dns_name, dict) and (dns_value := dns_name.get("value")):
        return str(dns_value).strip()
    if isinstance(dns_name, str) and dns_name.strip():
        return dns_name.strip()

    return vm.get("name") or vm.get("extId", "unknown")


def vm_matches_categories(
    vm: dict[str, Any],
    category_ext_ids: set[str],
    match_all: bool = False,
) -> bool:
    """
    Check if VM matches category filter.

    Args:
        vm: VM object with categories array.
        category_ext_ids: Set of target category extIds.
        match_all: If True, VM must have ALL categories; if False, VM must have ANY.

    Returns:
        True if VM matches the filter.
    """
    vm_cats = vm.get("categories") or []
    vm_ext_ids = {c.get("extId") for c in vm_cats if c.get("extId")}

    if match_all:
        return category_ext_ids <= vm_ext_ids
    return bool(vm_ext_ids & category_ext_ids)


def sanitize_hostname(name: str) -> str:
    """Replace invalid Ansible hostname characters with underscore."""
    return HOSTNAME_PATTERN.sub("_", name) or "vm"


def sanitize_group_name(name: str) -> str:
    """Replace invalid Ansible group name characters with underscore."""
    return GROUP_PATTERN.sub("_", name) or "group"


def build_category_key_values(
    vm: dict[str, Any],
    category_cache: dict[str, tuple[str, str]],
) -> list[str]:
    """
    Build list of key:value for VM categories using cache.

    VM categories only have extId; we need to resolve to key:value from cache.
    """
    result: list[str] = []
    vm_cats = vm.get("categories") or []
    for cat_ref in vm_cats:
        ext_id = cat_ref.get("extId")
        if ext_id and ext_id in category_cache:
            k, v = category_cache[ext_id]
            result.append(f"{k}:{v}")
    return result


def fetch_category_key_values(
    session: requests.Session,
    base_url: str,
    ext_ids: set[str],
) -> dict[str, tuple[str, str]]:
    """
    Fetch key and value for each category extId.

    Returns:
        Dict mapping extId -> (key, value).
    """
    if not ext_ids:
        return {}

    cache: dict[str, tuple[str, str]] = {}
    url = f"{base_url}{PRISM_CATEGORIES_PATH}"

    page = 0
    limit = 100

    while True:
        params = {"$page": page, "$limit": limit, "$select": "extId,key,value"}

        try:
            resp = session.get(url, params=params, timeout=(5, 30))
            resp.raise_for_status()
        except requests.RequestException as e:
            logger.warning("Could not fetch category details: %s", e)
            break

        data = resp.json()
        items = data.get("data") or []

        for cat in items:
            ext_id = cat.get("extId")
            if ext_id and ext_id in ext_ids:
                key = cat.get("key", "")
                value = cat.get("value", "")
                cache[ext_id] = (key, value)

        meta = data.get("metadata") or {}
        total = meta.get("totalAvailableResults", 0)
        if page * limit + len(items) >= total or not items:
            break
        page += 1

    return cache


def build_inventory(
    config: dict[str, Any],
) -> dict[str, Any]:
    """
    Build Ansible dynamic inventory from Prism Central.

    Args:
        config: Configuration dict.

    Returns:
        Ansible inventory dict (groups + _meta.hostvars).
    """
    base_url = config["host"].rstrip("/")
    if not base_url.startswith("http"):
        base_url = f"https://{base_url}"
    if ":" not in base_url.split("//", 1)[-1] or not base_url.split(":")[-1].isdigit():
        base_url = f"{base_url}:9440"

    session = create_session(config)
    categories = config["categories"]

    # Resolve category key:value -> extIds
    category_ext_ids = resolve_category_ext_ids(session, base_url, categories)
    if not category_ext_ids:
        logger.warning(
            "No matching categories found for %s. Inventory may be empty.",
            categories,
        )

    # Fetch category key:value for hostvars
    category_cache = fetch_category_key_values(session, base_url, category_ext_ids)

    # Fetch all VMs
    vms = fetch_vms(session, base_url)

    # Filter and build hostvars; track sub-groups by category
    hosts: list[str] = []
    hostvars: dict[str, dict[str, Any]] = {}
    seen_names: dict[str, int] = {}
    category_groups: dict[str, set[str]] = {}  # group_name -> set of host keys

    ansible_port = config.get("ansible_port", 22)

    for vm in vms:
        match_all = config.get("category_match") == "all"
        if not vm_matches_categories(vm, category_ext_ids, match_all=match_all):
            continue

        vm_name = vm.get("name") or "unknown"
        ext_id = vm.get("extId", "")

        # Unique host identifier: sanitize name, use vm-{extId} on collision
        safe_name = sanitize_hostname(vm_name)
        if safe_name in seen_names:
            host_key = f"vm-{ext_id}" if ext_id else f"{safe_name}_{seen_names[safe_name]}"
        else:
            seen_names[safe_name] = 1
            host_key = safe_name

        ansible_host = get_ansible_host(vm)
        nutanix_vm_ip = get_vm_ip(vm)
        nutanix_categories = build_category_key_values(vm, category_cache)

        hostvars[host_key] = {
            "ansible_host": ansible_host,
            "ansible_port": ansible_port,
            "nutanix_vm_ext_id": ext_id,
            "nutanix_vm_name": vm_name,
            "nutanix_vm_ip": nutanix_vm_ip,
            "nutanix_categories": nutanix_categories,
        }

        hosts.append(host_key)

        # Add to sub-groups by category (e.g. cat_Environment_Production)
        for kv in nutanix_categories:
            group_name = f"cat_{sanitize_group_name(kv.replace(':', '_'))}"
            category_groups.setdefault(group_name, set()).add(host_key)

    inventory: dict[str, Any] = {
        DEFAULT_GROUP: {"hosts": hosts, "vars": {}},
        "_meta": {"hostvars": hostvars},
    }

    for group_name, group_hosts in category_groups.items():
        inventory[group_name] = {"hosts": sorted(group_hosts), "vars": {}}

    return inventory


def main() -> int:
    """Entry point for Ansible dynamic inventory."""
    parser = argparse.ArgumentParser(description="Nutanix API v4 dynamic inventory")
    parser.add_argument("--list", action="store_true", help="Output full inventory JSON")
    parser.add_argument("--host", type=str, help="Host to query (returns {} when using _meta)")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging to stderr",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    if args.host:
        # Ansible may call --host when _meta is not used; we always use _meta, so return empty
        print("{}")
        return 0

    if not args.list:
        parser.error("Either --list or --host must be specified")

    try:
        config = load_config()
        inventory = build_inventory(config)
        print(json.dumps(inventory, indent=2))
        return 0
    except NutanixInventoryError as e:
        logger.error("%s", e)
        sys.exit(1)
    except Exception as e:
        logger.exception("Unexpected error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main())
