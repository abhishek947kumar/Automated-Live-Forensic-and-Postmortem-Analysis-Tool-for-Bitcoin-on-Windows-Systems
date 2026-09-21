"""
Postmortem File System & Remnants Extractor
Scans default Windows directories for Bitcoin Core, Electrum, Armory, Bither, MultiBit, Copay;
detects Berkeley DB headers (wallet.dat), JSON keystores, prefetch execution traces, and uninstalled remnants.
"""

import os
import glob
import json
import struct
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

BERKELEY_DB_MAGIC_BE = b'\x00\x05\x31\x62'
BERKELEY_DB_MAGIC_LE = b'\x62\x31\x05\x00'
SQLITE_MAGIC = b'SQLite format 3\x00'

KNOWN_WALLET_DIRS = [
    {"wallet": "Bitcoin Core", "rel_path": r"Bitcoin", "target_files": ["wallet.dat", "debug.log", "peers.dat", "bitcoin.conf"]},
    {"wallet": "Electrum", "rel_path": r"Electrum\wallets", "target_files": ["*", "default_wallet"]},
    {"wallet": "Armory", "rel_path": r"Armory", "target_files": ["armorylog.txt", "databases"]},
    {"wallet": "Bither", "rel_path": r"Bither", "target_files": ["bither.cfg", "address.db"]},
    {"wallet": "MultiBit HD", "rel_path": r"MultiBitHD", "target_files": ["mbhd.wallet.aes", "mbhd.spvchain"]},
    {"wallet": "Copay / BitPay", "rel_path": r"Copay\Local Storage\leveldb", "target_files": ["*.ldb", "*.log"]}
]

def check_file_format(file_path: str) -> Dict[str, Any]:
    """Inspects file headers to identify Berkeley DB, SQLite, or JSON wallet structures."""
    if not os.path.isfile(file_path):
        return {"format": "UNKNOWN", "valid": False}
        
    try:
        with open(file_path, "rb") as f:
            header = f.read(64)
            
        if len(header) >= 16:
            # Check Berkeley DB (magic often appears at offset 12 in page 0)
            if BERKELEY_DB_MAGIC_BE in header or BERKELEY_DB_MAGIC_LE in header:
                return {"format": "BERKELEY_DB", "valid": True, "description": "Bitcoin Core legacy Berkeley DB wallet"}
            if header.startswith(SQLITE_MAGIC):
                return {"format": "SQLITE3", "valid": True, "description": "Modern SQLite Bitcoin descriptor wallet"}
                
        # Try JSON parse for Electrum wallets
        if file_path.endswith((".json", ".dat")) or "electrum" in file_path.lower():
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as jf:
                    data = json.load(jf)
                    if isinstance(data, dict) and ("keystore" in data or "wallet_type" in data or "addresses" in data):
                        return {
                            "format": "ELECTRUM_JSON",
                            "valid": True,
                            "wallet_type": data.get("wallet_type", "Standard"),
                            "has_keystore": "keystore" in data,
                            "description": "Electrum JSON format wallet file"
                        }
            except Exception:
                pass
                
    except Exception:
        pass
        
    return {"format": "BINARY_OR_PLAIN", "valid": True}

def get_file_timestamps(path: str) -> Dict[str, str]:
    """Extracts creation, modification, and access timestamps in ISO format."""
    try:
        stat = os.stat(path)
        c_time = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        m_time = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        a_time = datetime.fromtimestamp(stat.st_atime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return {"created": c_time, "modified": m_time, "accessed": a_time}
    except Exception:
        return {"created": "Unknown", "modified": "Unknown", "accessed": "Unknown"}

def scan_prefetch_artifacts(prefetch_dir: str = r"C:\Windows\Prefetch") -> List[Dict[str, Any]]:
    """Scans Windows Prefetch for execution records of cryptocurrency binaries."""
    findings = []
    if not os.path.exists(prefetch_dir):
        return findings
        
    target_stems = ["BITCOIN-QT", "ELECTRUM", "ARMORY", "BITHER", "MULTIBIT", "COPAY", "BITPAY"]
    try:
        for fname in os.listdir(prefetch_dir):
            if not fname.upper().endswith(".PF"):
                continue
            for stem in target_stems:
                if stem in fname.upper():
                    full_p = os.path.join(prefetch_dir, fname)
                    ts = get_file_timestamps(full_p)
                    findings.append({
                        "file_name": fname,
                        "file_path": full_p,
                        "wallet_binary": stem,
                        "file_size": os.path.getsize(full_p),
                        "last_execution_estimate": ts["modified"],
                        "creation_timestamp": ts["created"],
                        "description": f"Windows Prefetch execution artifact for {stem} client."
                    })
    except PermissionError:
        # User may not be admin, prefetch read restricted
        pass
    except Exception:
        pass
        
    return findings

def scan_user_directories(base_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Scans user directories for known cryptocurrency wallet locations."""
    discovered = []
    
    appdata_roots = []
    if base_path and os.path.exists(base_path):
        appdata_roots.append(base_path)
    else:
        # Check current user's APPDATA and LOCALAPPDATA
        appdata = os.environ.get("APPDATA")
        localappdata = os.environ.get("LOCALAPPDATA")
        if appdata and os.path.exists(appdata):
            appdata_roots.append(appdata)
        if localappdata and os.path.exists(localappdata):
            appdata_roots.append(localappdata)
            
        # Also check all users under C:\Users if running with sufficient privileges
        users_dir = r"C:\Users"
        if os.path.exists(users_dir):
            try:
                for u in os.listdir(users_dir):
                    u_appdata = os.path.join(users_dir, u, "AppData", "Roaming")
                    u_local = os.path.join(users_dir, u, "AppData", "Local")
                    if os.path.isdir(u_appdata) and u_appdata not in appdata_roots:
                        appdata_roots.append(u_appdata)
                    if os.path.isdir(u_local) and u_local not in appdata_roots:
                        appdata_roots.append(u_local)
            except Exception:
                pass

    for root in appdata_roots:
        for conf in KNOWN_WALLET_DIRS:
            target_dir = os.path.join(root, conf["rel_path"])
            if os.path.exists(target_dir):
                # Search for files
                try:
                    for item in os.listdir(target_dir):
                        full_item = os.path.join(target_dir, item)
                        if os.path.isfile(full_item):
                            fmt = check_file_format(full_item)
                            ts = get_file_timestamps(full_item)
                            size = os.path.getsize(full_item)
                            
                            # Check if the application executable is present or if this is an uninstalled remnant
                            is_remnant = True
                            program_files_candidates = [
                                rf"C:\Program Files\{conf['wallet']}",
                                rf"C:\Program Files (x86)\{conf['wallet']}"
                            ]
                            for pfc in program_files_candidates:
                                if os.path.exists(pfc):
                                    is_remnant = False
                                    break
                                    
                            discovered.append({
                                "wallet_name": conf["wallet"],
                                "file_name": item,
                                "file_path": full_item,
                                "directory": target_dir,
                                "file_size_bytes": size,
                                "format_analysis": fmt,
                                "timestamps": ts,
                                "is_uninstalled_remnant": is_remnant,
                                "status": "DATA_REMNANT" if is_remnant else "ACTIVE_INSTALLATION",
                                "evidence_significance": "HIGH" if "wallet" in item.lower() or fmt.get("valid") else "MEDIUM"
                            })
                except Exception:
                    continue

    return discovered
