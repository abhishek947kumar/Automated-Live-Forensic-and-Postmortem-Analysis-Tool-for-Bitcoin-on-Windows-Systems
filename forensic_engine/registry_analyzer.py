"""
Windows Registry Forensics & UserAssist ROT13 Decoder
Analyzes Uninstall keys, UserAssist execution history, Run keys, and URL protocol handlers.
"""

import os
import struct
import codecs
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

# Known cryptocurrency wallet keywords for registry queries
CRYPTO_KEYWORDS = [
    "bitcoin", "electrum", "armory", "bither", "multibit", "copay",
    "bitpay", "coinomi", "exodus", "wasabi", "specter", "sparrow"
]

def rot13(s: str) -> str:
    """Decodes ROT13 strings commonly used by Windows UserAssist."""
    return codecs.decode(s, 'rot_13')

def parse_filetime(filetime_int: int) -> Optional[str]:
    """Converts a 64-bit Windows FILETIME integer to a human-readable ISO string."""
    if filetime_int <= 0:
        return None
    try:
        # Windows FILETIME is 100-ns intervals since January 1, 1601 UTC
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        dt = epoch + timedelta(microseconds=filetime_int / 10)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return None

def parse_userassist_entry(raw_name: str, raw_data: bytes) -> Optional[Dict[str, Any]]:
    """Parses a UserAssist registry entry, decrypting ROT13 name and extracting run count/timestamp."""
    decoded_name = rot13(raw_name)
    is_crypto_match = any(k in decoded_name.lower() for k in CRYPTO_KEYWORDS)
    
    # Windows 7 / 10 / 11 UserAssist format is typically 72 bytes
    run_count = 0
    last_run_time = "Unknown"
    
    if len(raw_data) >= 68:
        # Session ID (4 bytes), Run Count (4 bytes at offset 4)
        run_count = struct.unpack_from("<I", raw_data, 4)[0]
        # Focus count (4 bytes at offset 8), Focus time (4 bytes at offset 12)
        # FILETIME timestamp (8 bytes at offset 60)
        filetime = struct.unpack_from("<Q", raw_data, 60)[0]
        parsed_time = parse_filetime(filetime)
        if parsed_time:
            last_run_time = parsed_time
    elif len(raw_data) >= 16:
        # Older format or short buffer
        run_count = struct.unpack_from("<I", raw_data, 4)[0] if len(raw_data) >= 8 else 0

    return {
        "raw_rot13_name": raw_name,
        "decoded_path": decoded_name,
        "run_count": run_count,
        "last_executed": last_run_time,
        "is_crypto_related": is_crypto_match,
        "category": "UserAssist Execution Record"
    }

def scan_live_registry() -> Dict[str, Any]:
    """Inspects live Windows Registry hives for cryptocurrency artifacts."""
    results = {
        "installed_software": [],
        "userassist_executions": [],
        "autorun_keys": [],
        "protocol_handlers": [],
        "system_status": "LIVE_REGISTRY_ACCESSED" if HAS_WINREG else "WINREG_UNAVAILABLE"
    }

    if not HAS_WINREG:
        return results

    # 1. Scan Uninstall Keys for Installed & Residual Wallets
    uninstall_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
    ]

    for root_hive, subkey_path in uninstall_paths:
        try:
            with winreg.OpenKey(root_hive, subkey_path) as key:
                num_subkeys = winreg.QueryInfoKey(key)[0]
                for i in range(num_subkeys):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as app_key:
                            app_info = {}
                            try:
                                app_info["display_name"] = winreg.QueryValueEx(app_key, "DisplayName")[0]
                            except OSError:
                                app_info["display_name"] = subkey_name
                                
                            try:
                                app_info["install_location"] = winreg.QueryValueEx(app_key, "InstallLocation")[0]
                            except OSError:
                                app_info["install_location"] = "Not Recorded"
                                
                            try:
                                app_info["uninstall_string"] = winreg.QueryValueEx(app_key, "UninstallString")[0]
                            except OSError:
                                app_info["uninstall_string"] = "N/A"
                                
                            try:
                                app_info["version"] = winreg.QueryValueEx(app_key, "DisplayVersion")[0]
                            except OSError:
                                app_info["version"] = "N/A"

                            combined_str = f"{app_info['display_name']} {app_info.get('install_location', '')}".lower()
                            if any(k in combined_str for k in CRYPTO_KEYWORDS):
                                # Check if install directory still exists or if it's an uninstalled remnant
                                loc = app_info["install_location"]
                                exists_on_disk = os.path.exists(loc) if loc and loc != "Not Recorded" else False
                                results["installed_software"].append({
                                    "application_name": app_info["display_name"],
                                    "install_location": app_info["install_location"],
                                    "uninstall_command": app_info["uninstall_string"],
                                    "version": app_info["version"],
                                    "registry_path": f"{'HKLM' if root_hive == winreg.HKEY_LOCAL_MACHINE else 'HKCU'}\\{subkey_path}\\{subkey_name}",
                                    "disk_presence": "PRESENT" if exists_on_disk else "RESIDUAL_REMNANT",
                                    "is_remnant": not exists_on_disk
                                })
                    except OSError:
                        continue
        except OSError:
            continue

    # 2. Scan UserAssist (Execution Artifacts & Run Counts)
    userassist_base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, userassist_base) as ua_key:
            num_guids = winreg.QueryInfoKey(ua_key)[0]
            for i in range(num_guids):
                guid_name = winreg.EnumKey(ua_key, i)
                count_path = f"{userassist_base}\\{guid_name}\\Count"
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, count_path) as count_key:
                        num_values = winreg.QueryInfoKey(count_key)[1]
                        for j in range(num_values):
                            val_name, val_data, val_type = winreg.EnumValue(count_key, j)
                            if val_type == winreg.REG_BINARY and isinstance(val_data, bytes):
                                entry = parse_userassist_entry(val_name, val_data)
                                if entry and (entry["is_crypto_related"] or "electrum" in entry["decoded_path"].lower() or "bitcoin" in entry["decoded_path"].lower()):
                                    entry["guid"] = guid_name
                                    results["userassist_executions"].append(entry)
                except OSError:
                    continue
    except OSError:
        pass

    # 3. Check Bitcoin URL Protocol Handler
    try:
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, r"bitcoin\shell\open\command") as proto_key:
            cmd = winreg.QueryValue(proto_key, "")
            results["protocol_handlers"].append({
                "protocol": "bitcoin://",
                "command": cmd,
                "status": "REGISTERED"
            })
    except OSError:
        pass

    # 4. Check Run / RunOnce
    run_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
    ]
    for hive, path in run_paths:
        try:
            with winreg.OpenKey(hive, path) as rk:
                num_vals = winreg.QueryInfoKey(rk)[1]
                for k in range(num_vals):
                    vname, vdata, _ = winreg.EnumValue(rk, k)
                    if any(c in f"{vname} {vdata}".lower() for c in CRYPTO_KEYWORDS):
                        results["autorun_keys"].append({
                            "name": vname,
                            "command": vdata,
                            "hive": "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM",
                            "key_path": path
                        })
        except OSError:
            continue

    return results
