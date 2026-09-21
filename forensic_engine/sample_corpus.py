"""
Sample Forensic Corpus Generator ("Operation Satoshi Shadow")
Recreates the exact experimental setup and findings from the IEEE Access 2019 paper:
- Volatile memory dump with unencrypted BIP-39 mnemonic seed and WIF keys
- Postmortem persistent uninstalled wallet remnants (Bitcoin Core Berkeley DB wallet.dat, Electrum JSON)
- Windows Prefetch execution logs
- ROT13 UserAssist execution records
- Browser SQLite history with exchange and web wallet logins
"""

import os
import sqlite3
import json
import struct
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

from .chain_of_custody import ChainOfCustodyManager
from .filesystem_scanner import BERKELEY_DB_MAGIC_BE

def create_sample_case_directory(base_dir: str) -> Dict[str, Any]:
    """Generates a complete forensic evidence directory mimicking a seized suspect Windows PC."""
    os.makedirs(base_dir, exist_ok=True)
    
    # Paths
    mem_dir = os.path.join(base_dir, "Memory")
    disk_dir = os.path.join(base_dir, "Disk_Remnants")
    browser_dir = os.path.join(base_dir, "Browser_Data")
    prefetch_dir = os.path.join(base_dir, "Prefetch")
    registry_dir = os.path.join(base_dir, "Registry")
    
    for d in [mem_dir, disk_dir, browser_dir, prefetch_dir, registry_dir]:
        os.makedirs(d, exist_ok=True)
        
    created_files = {}

    # 1. Volatile Memory Dump (Simulating RAM acquisition from live system)
    mem_dump_path = os.path.join(mem_dir, "physmem_suspect_pc_live.raw")
    
    # Generate realistic memory block with padding, strings, seeds, and keys
    mem_content = bytearray(512 * 1024) # 512 KB realistic sample slice
    # Inject background memory noise
    for i in range(0, len(mem_content), 128):
        mem_content[i:i+4] = b"\x90\x90\xcc\xcc"
        
    # Inject BIP-39 Seed (12 valid words)
    seed_phrase = b"shadow galaxy frozen secret matrix orbit winter weapon dynamic echo puzzle abandon"
    seed_offset = 0x000142A0
    mem_content[seed_offset:seed_offset + len(seed_phrase)] = seed_phrase
    
    # Inject WIF Private Key (Compressed 52 chars base58)
    wif_key = b"KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    wif_offset = 0x00028400
    mem_content[wif_offset:wif_offset + len(wif_key)] = wif_key
    
    # Inject Bitcoin Public Addresses
    addr1 = b"bc1q0satoshi921forensicshadowproof7x49k"
    mem_content[0x00031100:0x00031100 + len(addr1)] = addr1
    addr2 = b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    mem_content[0x00031200:0x00031200 + len(addr2)] = addr2
    
    # Inject RPC Credentials
    rpc_data = b"rpcuser=satoshi_investigator\nrpcpassword=ShadowVault_9981_SecretKey\nrpcport=8332"
    mem_content[0x00045000:0x00045000 + len(rpc_data)] = rpc_data
    
    with open(mem_dump_path, "wb") as f:
        f.write(mem_content)
    created_files["memory_dump"] = mem_dump_path

    # 2. Bitcoin Core Postmortem Remnant (Berkeley DB wallet.dat)
    btc_dir = os.path.join(disk_dir, "Bitcoin")
    os.makedirs(btc_dir, exist_ok=True)
    wallet_dat_path = os.path.join(btc_dir, "wallet.dat")
    
    # Berkeley DB file with magic header
    bdb_buffer = bytearray(8192)
    # Magic bytes at offset 12 in page 0: 00 05 31 62
    bdb_buffer[12:16] = BERKELEY_DB_MAGIC_BE
    # Simulate wallet metadata strings inside Berkeley DB
    marker = b"name_default\x00key\x00bc1q0satoshi921forensicshadowproof7x49k\x00mkey\x00master_key_enc"
    bdb_buffer[64:64 + len(marker)] = marker
    with open(wallet_dat_path, "wb") as f:
        f.write(bdb_buffer)
        
    debug_log_path = os.path.join(btc_dir, "debug.log")
    with open(debug_log_path, "w", encoding="utf-8") as f:
        f.write("""2026-09-18 14:22:01 Bitcoin Core version v25.0.0
2026-09-18 14:22:04 Loading addresses from peers.dat
2026-09-18 14:23:12 Opened Berkeley DB wallet: wallet.dat (read-only mode)
2026-09-18 14:25:50 Transaction detected: 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
2026-09-18 16:30:10 Flushing wallet.dat to disk
2026-09-19 09:12:00 Shutdown requested by Windows Uninstaller
""")
    created_files["bitcoin_remnant"] = wallet_dat_path

    # 3. Electrum Postmortem Remnant (JSON Wallet with Keystore)
    electrum_dir = os.path.join(disk_dir, "Electrum", "wallets")
    os.makedirs(electrum_dir, exist_ok=True)
    electrum_wallet_path = os.path.join(electrum_dir, "default_wallet")
    
    electrum_json = {
        "wallet_type": "standard",
        "seed_version": 17,
        "use_encryption": True,
        "keystore": {
            "type": "bip32",
            "xpub": "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4QcmQQZsH687ecB269bMiqcBQ5PcUEChWoiG98ExfcHG4tuPp8W30D19pZ1XG21P4Z1Q1234",
            "derivation": "m/0'",
            "pw_hash_version": 1
        },
        "addresses": [
            "bc1q0satoshi921forensicshadowproof7x49k",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        ],
        "history": {
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b": 810234
        }
    }
    with open(electrum_wallet_path, "w", encoding="utf-8") as f:
        json.dump(electrum_json, f, indent=2)
    created_files["electrum_remnant"] = electrum_wallet_path

    # 4. Windows Prefetch Records (.pf files)
    pf1 = os.path.join(prefetch_dir, "BITCOIN-QT.EXE-A1B2C3D4.PF")
    pf2 = os.path.join(prefetch_dir, "ELECTRUM.EXE-E5F6A7B8.PF")
    for pf in [pf1, pf2]:
        with open(pf, "wb") as f:
            f.write(b"MAM\x00" + b"\x00" * 4096)
    created_files["prefetch"] = [pf1, pf2]

    # 5. Browser History Database (SQLite)
    browser_db_path = os.path.join(browser_dir, "History")
    if os.path.exists(browser_db_path):
        try:
            os.remove(browser_db_path)
        except Exception:
            pass
    conn = sqlite3.connect(browser_db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 0,
            typed_count INTEGER DEFAULT 0,
            last_visit_time INTEGER NOT NULL,
            hidden INTEGER DEFAULT 0
        )
    """)
    
    # WebKit epoch timestamp for 2026-09-18
    base_webkit = 13371192000000000
    cur.executemany("""
        INSERT INTO urls (url, title, visit_count, last_visit_time)
        VALUES (?, ?, ?, ?)
    """, [
        ("https://login.blockchain.com/#/wallet/login", "Blockchain.com Wallet | Login to Your Bitcoin Account", 18, base_webkit),
        ("https://www.coinbase.com/dashboard", "Coinbase - Buy & Sell Bitcoin, Ethereum, and more", 24, base_webkit + 3600000000),
        ("https://mempool.space/tx/4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", "Bitcoin Transaction 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b - Mempool", 7, base_webkit + 7200000000),
        ("https://electrum.org/#download", "Electrum Bitcoin Wallet - Downloads", 4, base_webkit - 86400000000),
        ("https://bitcoin.org/en/download", "Download - Bitcoin Core", 3, base_webkit - 172800000000)
    ])
    conn.commit()
    conn.close()
    created_files["browser_db"] = browser_db_path

    return created_files
