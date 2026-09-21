"""
Live Memory Forensics & Volatile Data Acquisition
Extracts running wallet processes, parses RAM/dumps, and scans for BIP-39 seeds,
WIF private keys, public addresses, and plaintext credentials.
"""

import os
import re
import psutil
import ctypes
from typing import List, Dict, Any, Optional
from datetime import datetime
from .bip39_wordlist import BIP39_SET, is_valid_bip39_phrase

# Regular expressions for Bitcoin artifacts
REGEX_WIF_COMPRESSED = re.compile(r'\b[KL][1-9A-HJ-NP-Za-km-z]{51}\b')
REGEX_WIF_UNCOMPRESSED = re.compile(r'\b5[1-9A-HJ-NP-Za-km-z]{50}\b')
REGEX_XPRV = re.compile(r'\bxprv[1-9A-HJ-NP-Za-km-z]{107,108}\b')
REGEX_XPUB = re.compile(r'\bxpub[1-9A-HJ-NP-Za-km-z]{107,108}\b')
REGEX_LEGACY_ADDR = re.compile(r'\b1[1-9A-HJ-NP-Za-km-z]{25,34}\b')
REGEX_P2SH_ADDR = re.compile(r'\b3[1-9A-HJ-NP-Za-km-z]{25,34}\b')
REGEX_BECH32_ADDR = re.compile(r'\bbc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,59}\b')
REGEX_RPC_CRED = re.compile(r'(rpcuser|rpcpassword)\s*=\s*([^\r\n]+)', re.IGNORECASE)
REGEX_HEX_KEY = re.compile(r'\b[0-9a-fA-F]{64}\b')

# Target cryptocurrency wallet processes
TARGET_WALLET_PROCESSES = {
    "bitcoin-qt.exe": "Bitcoin Core Desktop Wallet",
    "electrum.exe": "Electrum Lightweight Wallet",
    "armory.exe": "Armory Offline / Multi-Sig Wallet",
    "bither.exe": "Bither Bitcoin Wallet",
    "multibit.exe": "MultiBit HD Wallet",
    "multibithd.exe": "MultiBit HD Client",
    "copay.exe": "Copay / BitPay Multi-Sig Client",
    "bitpay.exe": "BitPay Desktop App",
    "coinomi.exe": "Coinomi Desktop Wallet",
    "exodus.exe": "Exodus Multi-Asset Wallet"
}

def format_hex_dump(buffer: bytes, start_offset: int = 0, length: int = 64) -> str:
    """Formats raw bytes into standard forensic hex / ASCII representation."""
    chunk = buffer[start_offset:start_offset + length]
    lines = []
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hex_str = " ".join(f"{b:02X}" for b in row)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in row)
        lines.append(f"0x{start_offset + i:08X}  {hex_str:<48}  |{ascii_str}|")
    return "\n".join(lines)

def extract_strings(data: bytes, min_len: int = 4) -> List[tuple[int, str]]:
    """Extracts printable ASCII strings and their byte offsets from raw data."""
    pattern = re.compile(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}')
    return [(m.start(), m.group().decode('ascii', errors='replace')) for m in pattern.finditer(data)]

def scan_bip39_seeds(text: str, base_offset: int = 0) -> List[Dict[str, Any]]:
    """Extracts consecutive sequences of BIP-39 dictionary words."""
    found = []
    # Tokenize words while tracking rough offsets
    words = re.findall(r'\b[a-z]{3,8}\b', text.lower())
    if len(words) < 12:
        return found
        
    for i in range(len(words) - 11):
        for length in (24, 12):
            if i + length <= len(words):
                candidate = words[i:i + length]
                if is_valid_bip39_phrase(candidate):
                    phrase = " ".join(candidate)
                    offset = text.lower().find(phrase)
                    if offset == -1:
                        offset = text.lower().find(candidate[0])
                    found.append({
                        "type": "BIP39_MNEMONIC_SEED",
                        "secret_value": phrase,
                        "word_count": length,
                        "offset": base_offset + (offset if offset != -1 else 0),
                        "confidence": "HIGH",
                        "description": f"{length}-word recovery seed phrase recovered from memory."
                    })
    return found

def scan_buffer_for_crypto_artifacts(raw_bytes: bytes, source_label: str = "Memory Block") -> Dict[str, Any]:
    """Scans a byte buffer for all cryptocurrency volatile artifacts."""
    artifacts = {
        "seeds": [],
        "private_keys": [],
        "public_addresses": [],
        "credentials": [],
        "hex_keys": []
    }
    
    # Scan raw strings
    text = raw_bytes.decode('latin-1', errors='replace')
    
    # 1. BIP-39 Seed Phrases
    artifacts["seeds"].extend(scan_bip39_seeds(text))
    
    # 2. WIF Private Keys
    for m in REGEX_WIF_COMPRESSED.finditer(text):
        val = m.group()
        start = m.start()
        # Snippet around key
        snippet_start = max(0, start - 16)
        hex_dump = format_hex_dump(raw_bytes, snippet_start, 64)
        artifacts["private_keys"].append({
            "type": "WIF_PRIVATE_KEY_COMPRESSED",
            "secret_value": val[:6] + "..." + val[-4:],
            "full_secret": val,
            "offset": f"0x{start:08X}",
            "hex_dump": hex_dump,
            "source": source_label,
            "risk_level": "CRITICAL",
            "description": "Compressed WIF Private Key (starts with K/L) found in volatile memory."
        })
        
    for m in REGEX_WIF_UNCOMPRESSED.finditer(text):
        val = m.group()
        start = m.start()
        snippet_start = max(0, start - 16)
        hex_dump = format_hex_dump(raw_bytes, snippet_start, 64)
        artifacts["private_keys"].append({
            "type": "WIF_PRIVATE_KEY_UNCOMPRESSED",
            "secret_value": val[:6] + "..." + val[-4:],
            "full_secret": val,
            "offset": f"0x{start:08X}",
            "hex_dump": hex_dump,
            "source": source_label,
            "risk_level": "CRITICAL",
            "description": "Uncompressed WIF Private Key (starts with 5) found in volatile memory."
        })

    # 3. Extended Keys (xprv / xpub)
    for m in REGEX_XPRV.finditer(text):
        val = m.group()
        artifacts["private_keys"].append({
            "type": "BIP32_EXTENDED_PRIVATE_KEY",
            "secret_value": val[:10] + "..." + val[-6:],
            "full_secret": val,
            "offset": f"0x{m.start():08X}",
            "hex_dump": format_hex_dump(raw_bytes, max(0, m.start() - 16), 64),
            "source": source_label,
            "risk_level": "CRITICAL",
            "description": "BIP32/44 Extended Master Private Key (xprv) discovered in process heap."
        })

    # 4. Public Addresses
    for regex, addr_type in [
        (REGEX_BECH32_ADDR, "Bech32 (SegWit)"),
        (REGEX_LEGACY_ADDR, "Legacy P2PKH (starts with 1)"),
        (REGEX_P2SH_ADDR, "Script Hash P2SH (starts with 3)")
    ]:
        for m in regex.finditer(text):
            val = m.group()
            artifacts["public_addresses"].append({
                "type": addr_type,
                "address": val,
                "offset": f"0x{m.start():08X}",
                "source": source_label
            })
            
    # 5. Credentials / RPC
    for m in REGEX_RPC_CRED.finditer(text):
        field, secret = m.group(1), m.group(2).strip()
        artifacts["credentials"].append({
            "type": "RPC_CONFIGURATION_CREDENTIAL",
            "key": field,
            "value": secret,
            "offset": f"0x{m.start():08X}",
            "source": source_label,
            "risk_level": "HIGH"
        })

    return artifacts

def get_live_target_processes() -> List[Dict[str, Any]]:
    """Scans all running processes and flags known Bitcoin wallet applications."""
    detected = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time', 'memory_info', 'username']):
        try:
            name = (proc.info['name'] or "").lower()
            if name in TARGET_WALLET_PROCESSES:
                mem = proc.info.get('memory_info')
                rss_mb = round(mem.rss / (1024 * 1024), 2) if mem else 0
                create_dt = datetime.fromtimestamp(proc.info['create_time']).strftime('%Y-%m-%d %H:%M:%S') if proc.info.get('create_time') else "Unknown"
                detected.append({
                    "pid": proc.info['pid'],
                    "name": proc.info['name'],
                    "wallet_type": TARGET_WALLET_PROCESSES[name],
                    "executable_path": proc.info.get('exe') or "Access Restricted",
                    "memory_rss_mb": rss_mb,
                    "started_at": create_dt,
                    "username": proc.info.get('username') or "N/A",
                    "status": "RUNNING"
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return detected

def scan_process_memory_dump(file_path: str) -> Dict[str, Any]:
    """Reads and parses an offline or captured RAM dump file (.raw, .dmp, .bin)."""
    if not os.path.exists(file_path):
        return {"error": f"Memory dump file not found: {file_path}"}
        
    file_size = os.path.getsize(file_path)
    # Read first 16MB or entire file for rapid triage
    read_limit = min(file_size, 32 * 1024 * 1024)
    with open(file_path, "rb") as f:
        buffer = f.read(read_limit)
        
    findings = scan_buffer_for_crypto_artifacts(buffer, source_label=os.path.basename(file_path))
    findings["meta"] = {
        "file_name": os.path.basename(file_path),
        "file_size_bytes": file_size,
        "scanned_bytes": len(buffer)
    }
    return findings
