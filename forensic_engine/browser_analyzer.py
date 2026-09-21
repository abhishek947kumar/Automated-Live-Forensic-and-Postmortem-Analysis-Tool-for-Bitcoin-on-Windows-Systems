"""
Browser & Web Wallet Forensics Analyzer
Scans Chrome, Edge, and Firefox history databases for cryptocurrency exchanges,
web wallets, transaction queries, and Bitcoin addresses.
Uses shadow temporary copies to bypass file locks and preserve evidence integrity.
"""

import os
import shutil
import sqlite3
import tempfile
import re
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

CRYPTO_DOMAINS = [
    "coinbase.com", "blockchain.com", "blockchain.info", "binance.com",
    "kraken.com", "bitfinex.com", "localbitcoins.com", "mempool.space",
    "blockstream.info", "btc.com", "bitpay.com", "electrum.org",
    "bitcoin.org", "bitcointalk.org", "gemini.com", "crypto.com", "bybit.com"
]

REGEX_URL_TXID = re.compile(r'\b[a-fA-F0-9]{64}\b')
REGEX_URL_ADDR = re.compile(r'\b(bc1[a-z0-9]{38,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')

def chrome_time_to_iso(microseconds: int) -> Optional[str]:
    """Converts Chrome/Edge WebKit timestamp (microseconds since Jan 1, 1601) to ISO string."""
    if not microseconds or microseconds <= 0:
        return None
    try:
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        dt = epoch + timedelta(microseconds=microseconds)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return None

def firefox_time_to_iso(microseconds: int) -> Optional[str]:
    """Converts Firefox timestamp (microseconds since Jan 1, 1970) to ISO string."""
    if not microseconds or microseconds <= 0:
        return None
    try:
        dt = datetime.fromtimestamp(microseconds / 1000000.0, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return None

def safe_query_sqlite(db_path: str, query: str, time_converter) -> List[Dict[str, Any]]:
    """Copies locked SQLite database to a temp file and executes read-only query."""
    if not os.path.exists(db_path):
        return []
        
    temp_dir = tempfile.gettempdir()
    temp_copy = os.path.join(temp_dir, f"dfir_browser_{os.getpid()}_{os.path.basename(db_path)}")
    results = []
    
    try:
        shutil.copy2(db_path, temp_copy)
        # Open in URI mode read-only
        uri = f"file:{os.path.abspath(temp_copy)}?immutable=1"
        conn = sqlite3.connect(uri, uri=True)
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        
        for row in rows:
            url = row[0]
            title = row[1] or ""
            visit_count = row[2] if len(row) > 2 else 1
            raw_time = row[3] if len(row) > 3 else 0
            
            # Check domain match
            matched_domains = [d for d in CRYPTO_DOMAINS if d in url.lower()]
            if matched_domains:
                # Look for txid and addresses inside the URL
                txids = REGEX_URL_TXID.findall(url)
                addresses = [m[0] for m in REGEX_URL_ADDR.findall(url)]
                
                results.append({
                    "url": url,
                    "title": title,
                    "visit_count": visit_count,
                    "last_visit_time": time_converter(raw_time) if raw_time else "Unknown",
                    "matched_domain": matched_domains[0],
                    "extracted_txids": txids,
                    "extracted_addresses": addresses
                })
        conn.close()
    except Exception:
        pass
    finally:
        if os.path.exists(temp_copy):
            try:
                os.remove(temp_copy)
            except Exception:
                pass
                
    return results

def scan_browser_histories() -> Dict[str, Any]:
    """Scans Chrome, Edge, and Firefox history databases for cryptocurrency activity."""
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    roaming_appdata = os.environ.get("APPDATA", "")
    
    findings = {
        "chrome": [],
        "edge": [],
        "firefox": [],
        "total_records_found": 0
    }

    # 1. Google Chrome
    if local_appdata:
        chrome_history = os.path.join(local_appdata, r"Google\Chrome\User Data\Default\History")
        query = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC"
        findings["chrome"] = safe_query_sqlite(chrome_history, query, chrome_time_to_iso)

    # 2. Microsoft Edge
    if local_appdata:
        edge_history = os.path.join(local_appdata, r"Microsoft\Edge\User Data\Default\History")
        query = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC"
        findings["edge"] = safe_query_sqlite(edge_history, query, chrome_time_to_iso)

    # 3. Mozilla Firefox
    if roaming_appdata:
        ff_profiles_dir = os.path.join(roaming_appdata, r"Mozilla\Firefox\Profiles")
        if os.path.exists(ff_profiles_dir):
            try:
                for prof in os.listdir(ff_profiles_dir):
                    places_db = os.path.join(ff_profiles_dir, prof, "places.sqlite")
                    if os.path.exists(places_db):
                        query = "SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC"
                        ff_res = safe_query_sqlite(places_db, query, firefox_time_to_iso)
                        findings["firefox"].extend(ff_res)
            except Exception:
                pass

    findings["total_records_found"] = len(findings["chrome"]) + len(findings["edge"]) + len(findings["firefox"])
    return findings
