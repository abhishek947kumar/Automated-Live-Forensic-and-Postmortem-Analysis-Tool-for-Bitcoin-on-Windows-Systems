# BitTrace DFIR: Automated Live & Postmortem Bitcoin Forensic Analysis Tool for Windows

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.3-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![IEEE Access](https://img.shields.io/badge/Research-IEEE%20Access%20(2019)-brightgreen.svg)](https://doi.org/10.1109/ACCESS.2019.2933100)
[![ISO Standard](https://img.shields.io/badge/Compliance-ISO%2FIEC%2027037-orange.svg)](#chain-of-custody--isoiec-27037-compliance)

An open-source, automated digital forensics and incident response (DFIR) platform designed to conduct both **live volatile memory (RAM)** and **persistent postmortem disk/registry** analysis of Bitcoin artifacts on Windows systems.

Based directly on the landmark peer-reviewed research:
> **Stephan Zollner, Kim-Kwang Raymond Choo, and Nhien-An Le-Khac (2019)**  
> *"Automated Live Forensic and Postmortem Analysis Tool for Bitcoin on Windows"*  
> **IEEE Access**, vol. 7, pp. 107693–107707. [DOI: 10.1109/ACCESS.2019.2933100](https://doi.org/10.1109/ACCESS.2019.2933100)

---

## 📑 Table of Contents

- [The Forensic Problem](#the-forensic-problem)
- [System Architecture](#system-architecture)
- [Key Features](#key-features)
- [Supported Wallets & Target Artifacts](#supported-wallets--target-artifacts)
- [Installation & Quick Start](#installation--quick-start)
- [Running Automated Tests](#running-automated-tests)
- [Repository Structure](#repository-structure)
- [Chain of Custody & ISO/IEC 27037 Compliance](#chain-of-custody--isoiec-27037-compliance)
- [Academic Citation](#academic-citation)
- [License & Ethical Disclaimer](#license--ethical-disclaimer)

---

## 🔍 The Forensic Problem

1. **Volatile Memory Degradation**: When a suspect's computer is powered down, temporary RAM vanishes immediately. Critical evidence—including **unencrypted BIP-39 recovery seed phrases, active WIF private keys, and RPC passwords**—only resides in volatile memory while a wallet application is unlocked.
2. **Persistent Post-Uninstall Remnants**: Suspects frequently uninstall cryptocurrency desktop wallets believing all evidence is eliminated. However, standard Windows uninstall routines frequently leave behind user `AppData` directories containing Berkeley DB `wallet.dat` files, debug logs, prefetch execution records, and registry entries.
3. **Manual Analysis Overhead**: Combing through gigabytes of raw memory dumps and registry hives during first-response triage is slow and error-prone. This tool automates the entire discovery, parsing, correlation, and evidence hashing pipeline.

---

## 🏗️ System Architecture

```
+---------------------------------------------------------------------------------+
|                       BitTrace DFIR Web Application                             |
|  (Cyber Glassmorphism Interface: Live Triage, RAM Hex Viewer, Timeline, Report) |
+----------------------------------------+----------------------------------------+
                                         | REST & WebSocket (Proxy: port 5173)
                                         v
+---------------------------------------------------------------------------------+
|                         FastAPI Forensic Bridge Server                          |
|         (Port 8000: Real-time scan orchestrator, evidence export, APIs)         |
+----------------------------------------+----------------------------------------+
                                         |
          +------------------------------+------------------------------+
          |                                                             |
          v                                                             v
+-----------------------------------+         +-----------------------------------+
|       Live Volatile Forensics     |         |     Postmortem & Remnants Engine  |
+-----------------------------------+         +-----------------------------------+
| - Process Memory RAM Inspection   |         | - File System (%APPDATA%, Roaming)|
| - BIP-39 Seed Mnemonic Extraction |         | - Windows Registry & UserAssist   |
| - WIF / Hex Private Key Detector  |         | - Windows Prefetch Execution Logs |
| - Address & RPC Credential Search |         | - Browser History & Web Wallets   |
| - Memory Dump (.raw/.dmp) Parser  |         | - Post-Uninstall Remnants Checker |
+-----------------------------------+         +-----------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
|             Evidence Vault, ISO/IEC 27037 Chain of Custody & Report Engine      |
|  - Cryptographic Hashes (SHA-256, MD5)                                          |
|  - Comprehensive Forensic Report (Executive Summary, Technical Audit, HTML/PDF) |
+---------------------------------------------------------------------------------+
```

---

## ✨ Key Features

- **Live Memory Forensics & Hex Viewer**:
  - Automatically identifies running wallet processes (`bitcoin-qt.exe`, `electrum.exe`, `armory.exe`, `bither.exe`, etc.).
  - Extracts 12-to-24-word BIP-39 seed phrases (validated against the official 2,048-word English dictionary).
  - Scans for compressed (`K`/`L`) and uncompressed (`5`) WIF private keys, `xprv` extended keys, and public addresses (Bech32, P2PKH, P2SH).
  - Built-in **Forensic Hex / ASCII Dump Viewer** displaying exact memory offsets and aligned byte buffers.
  - Supports uploading raw memory dumps (`.raw`, `.dmp`, `.bin`, `.vmem`).

- **Postmortem File System & Remnant Extractor**:
  - Scans user `%APPDATA%` and `%LOCALAPPDATA%` directories.
  - Validates Berkeley DB headers (`0x00053162`) for legacy Bitcoin Core wallets and JSON keystores for Electrum.
  - Automatically flags **uninstalled remnants** where wallet files exist on disk despite software removal.
  - Parses Windows Prefetch (`C:\Windows\Prefetch\*.pf`) to determine last execution timestamps and launch frequencies.

- **Windows Registry & UserAssist ROT13 Decoder**:
  - Decrypts Windows `UserAssist` execution history from ROT13 encoding to reveal exact application paths, run counts, and FILETIME timestamps.
  - Identifies registered `bitcoin://` URL protocol handlers and persistence keys (`Run`/`RunOnce`).
  - Audits `CurrentVersion\Uninstall` registry entries for residual footprints.

- **Browser & Web Wallet Forensics**:
  - Uses shadow temporary copying to bypass live database file locks in Chrome, Edge, and Firefox.
  - Detects visits to Coinbase, Blockchain.com, Binance, Kraken, and Mempool block explorers.
  - Automatically parses URLs for Bitcoin transaction IDs (`txid`) and public addresses.

- **Unified Chronological Event Timeline**:
  - Correlates disparate artifacts (downloads, initial launches, transactions, uninstallation, and triage acquisition) into a single visual timeline.

- **ISO/IEC 27037 Cryptographic Evidence Vault**:
  - Automatically computes **SHA-256 and MD5** cryptographic hashes for every discovered artifact and dump.
  - Includes a real-time **Re-Verify Hash** feature to prove evidence has not been altered or tampered with.

- **Court-Ready Audit Report Generator**:
  - 1-click generation of formal, printable PDF/HTML forensic reports containing an Executive Summary, Technical Inventory, Chain of Custody ledger, and Examiner Attestation block.

- **Built-in Benchmark Case ("Operation Satoshi Shadow")**:
  - Includes a synthetic reproduction of the IEEE Access 2019 test corpus, allowing complete evaluation without installing third-party wallets.

---

## 💼 Supported Wallets & Target Artifacts

| Wallet Client | Volatile Memory (RAM) | File System Artifact | Registry / Prefetch | Remnant Behavior |
| :--- | :--- | :--- | :--- | :--- |
| **Bitcoin Core** | Plaintext keys, Master key | `%APPDATA%\Bitcoin\wallet.dat` | `BITCOIN-QT.PF` | `wallet.dat` & logs remain post-uninstall |
| **Electrum** | BIP-39 Seed phrase, `xprv` | `%APPDATA%\Electrum\wallets\` | UserAssist ROT13 entry | Keystores & config persist post-uninstall |
| **Armory** | Root keys, unencrypted seeds | `%APPDATA%\Armory\databases` | Prefetch execution trace | Databases & `armorylog.txt` retained |
| **Bither** | Passwords & PIN strings | `%APPDATA%\Bither\address.db` | Run / Uninstall keys | Config and address DB remain |
| **MultiBit HD** | AES credential strings | `%APPDATA%\MultiBitHD` | Launch frequency count | Encrypted wallet file retained |
| **Copay / BitPay** | Session auth tokens | Local Storage LevelDB | URI protocol handler | LevelDB transaction history persists |
| **Web Wallets** | Browser process RAM | SQLite History / Cache | URL shortcut MRUs | Visited URLs & TXIDs recorded in history |

---

## 🚀 Installation & Quick Start

### Prerequisites
- **Python 3.10+** (tested on Python 3.13)
- **Node.js 18+** & **npm** (tested on Node v24)
- **Windows 7, 10, or 11** (recommended for live registry and prefetch inspection)

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/Forensic-and-Postmortem-Analysis-Tool-for-Bitcoin.git
cd "Forensic-and-Postmortem-Analysis-Tool-for-Bitcoin"
```

### 2. Install Python Backend Dependencies
```bash
pip install -r requirements.txt
```

### 3. Install Frontend Dependencies
```bash
cd frontend
npm install
cd ..
```

### 4. Start the Application

#### Option A: Start Backend (Terminal 1)
```bash
python -m uvicorn backend.server:app --host 127.0.0.1 --port 8000
```

#### Option B: Start Frontend Web Dashboard (Terminal 2)
```bash
cd frontend
npm run dev -- --host 127.0.0.1 --port 5173
```

Now open your browser and navigate to:
👉 **`http://127.0.0.1:5173/`**

API Documentation is available at:
👉 **`http://127.0.0.1:8000/docs`**

---

## 🧪 Running Automated Tests

The repository includes complete unit test suites for the forensic engine and integration tests for the FastAPI server:

```bash
# Run Forensic Engine Unit Tests (BIP-39, WIF keys, Berkeley DB, ROT13, Custody)
python -m unittest tests/test_engine.py

# Run API Integration Tests (Profile, Sample Scan, Ledger, Report)
python -m unittest tests/test_api.py
```

All 9 automated tests run in under 2 seconds.

---

## 📁 Repository Structure

```
.
├── backend/
│   └── server.py                 # FastAPI server with REST & WebSocket endpoints
├── forensic_engine/
│   ├── __init__.py               # Package initializer
│   ├── bip39_wordlist.py         # Official 2,048-word BIP-39 dictionary
│   ├── live_memory.py            # Volatile memory scanner, WIF keys, hex dump generator
│   ├── registry_analyzer.py      # Windows Registry & UserAssist ROT13 decoder
│   ├── filesystem_scanner.py     # %APPDATA% scanner, Berkeley DB magic bytes, Prefetch
│   ├── browser_analyzer.py       # Shadow copy SQLite history scanner (Chrome/Edge/Firefox)
│   ├── chain_of_custody.py       # ISO/IEC 27037 evidence manager & hash calculator
│   └── sample_corpus.py          # IEEE Access 2019 benchmark corpus generator
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Header.jsx                # Top telemetry header & quick actions
│   │   │   ├── OverviewDashboard.jsx     # Triage metrics & target artifact matrix
│   │   │   ├── LiveMemoryInspector.jsx   # Volatile secrets table & Hex Viewer
│   │   │   ├── PostmortemExplorer.jsx    # Persistent wallet files & prefetch
│   │   │   ├── RegistryViewer.jsx        # ROT13 UserAssist & uninstall remnants
│   │   │   ├── BrowserForensics.jsx      # Web wallet & exchange history
│   │   │   ├── ForensicTimeline.jsx      # Chronological event reconstruction
│   │   │   ├── EvidenceLedger.jsx        # ISO/IEC 27037 Chain of Custody ledger
│   │   │   ├── ReportModal.jsx           # Printable court-ready forensic report
│   │   │   └── LiveScanConsole.jsx       # Real-time WebSocket telemetry console
│   │   ├── App.jsx                       # Main application state & tabs
│   │   ├── main.jsx                      # React entry point
│   │   └── index.css                     # Cyber glassmorphism Vanilla CSS design system
│   ├── index.html                        # HTML template with typography
│   ├── package.json                      # Frontend dependencies
│   └── vite.config.js                    # Vite dev server & proxy configuration
├── tests/
│   ├── test_engine.py            # Unit tests for forensic modules
│   └── test_api.py               # Integration tests for FastAPI endpoints
├── .gitignore                    # Git exclusions (Python, Node, dumps)
├── LICENSE                       # MIT License
├── README.md                     # Documentation
└── requirements.txt              # Python requirements
```

---

## ⚖️ Chain of Custody & ISO/IEC 27037 Compliance

To ensure digital evidence is legally admissible in judicial proceedings, this platform adheres to **ISO/IEC 27037: Guidelines for identification, collection, acquisition, and preservation of digital evidence**:
- Every acquired memory segment, recovered wallet file, and database export is immediately fingerprinted with **SHA-256** and **MD5** cryptographic hashes.
- Evidence records store immutable acquisition timestamps, examiner identity, target host profiling, and provenance metadata.
- Investigators can execute the **"Verify Hash"** routine to recalculate hashes from disk in real time to mathematically demonstrate zero evidence tampering.

---

## 📚 Academic Citation

If you use this tool in academic research, digital forensics investigations, or cybersecurity education, please cite the underlying IEEE Access research paper:

```bibtex
@article{zollner2019automated,
  author    = {Zollner, Stephan and Choo, Kim-Kwang Raymond and Le-Khac, Nhien-An},
  title     = {Automated Live Forensic and Postmortem Analysis Tool for Bitcoin on Windows},
  journal   = {IEEE Access},
  volume    = {7},
  pages     = {107693--107707},
  year      = {2019},
  publisher = {IEEE},
  doi       = {10.1109/ACCESS.2019.2933100}
}
```

---

## 🛡️ License & Ethical Disclaimer

This project is licensed under the [MIT License](LICENSE).

**Ethical & Legal Notice**: This tool is designed and released strictly for **defensive digital forensics, law enforcement investigations, academic research, and authorized cybersecurity incident response**. It does not perform key brute-forcing or unauthorized remote access. Users are responsible for ensuring that all forensic acquisitions comply with applicable local laws, search warrant conditions, and digital evidence handling standards.
