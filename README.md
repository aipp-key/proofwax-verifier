# Proofwax Independent Cryptographic Verifier

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Base L2](https://img.shields.io/badge/Network-Base%20L2-0052FF.svg)](https://base.org)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-success.svg)](#)

> **Trustless, decentralized, open-source verification tool for SHA-256 document integrity and Base L2 immutable timestamps.**

---

## 💡 Overview

Proofwax Independent Verifier allows anyone (developers, auditors, or third parties) to mathematically verify document existence and timestamp authenticity **without relying on Proofwax servers, APIs, or vendor infrastructure**.

Verification is performed directly against public **Base L2** blockchain RPC nodes, comparing the local SHA-256 hash of your document with the immutable calldata anchored on-chain.

### Key Principles
- **100% Client-Side / Local:** Your files never leave your computer or browser. SHA-256 digests are computed locally.
- **Zero Vendor Lock-in:** If Proofwax ever ceased operation, every timestamp remains permanently verifiable using this repository.
- **Zero Dependencies:** Both the Python and Node.js verifiers use only the standard runtime libraries (no `npm install` or `pip install` needed).

---

## 🛠️ Verification Methods

You can verify documents using any of the following 3 independent methods:

### Method 1: Web GUI (Browser / GitHub Pages)
Open [`index.html`](index.html) directly in any web browser by double-clicking it, or visit the live GitHub Pages instance:
1. Drag and drop your local file to compute its SHA-256 fingerprint client-side.
2. Enter the Base L2 Transaction Hash from your receipt or certificate.
3. Click **"Verify On-Chain Cryptographic Integrity"**.
4. The browser directly queries public Base L2 RPCs (`https://mainnet.base.org`) and renders the verified block number, UTC timestamp, and Basescan explorer link.

---

### Method 2: Python CLI (Zero Dependencies)

Requires Python 3.8+ (uses standard library `hashlib`, `urllib.request`, `json`).

```bash
# Verify using a local file and transaction hash:
python verify.py --file path/to/document.pdf --tx 0x4d1685...

# Verify using a raw SHA-256 digest:
python verify.py --hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 --tx 0x4d1685...

# Verify using a Proofwax receipt JSON file:
python verify.py --receipt receipt.json
```

---

### Method 3: Node.js CLI (Zero Dependencies)

Requires Node.js 18+ (uses native `crypto`, `fetch`, `parseArgs`).

```bash
# Verify using a local file:
node verify.mjs --file path/to/document.pdf --tx 0x4d1685...

# Verify using a raw SHA-256 digest:
node verify.mjs --hash e3b0c442... --tx 0x4d1685...

# Verify using a receipt JSON file:
node verify.mjs --receipt receipt.json
```

---

## 🔬 How the Cryptographic Verification Works

```mermaid
flowchart LR
    A["Local File / Document"] -->|"Local SHA-256 Hashing"| B["Digest (e.g. 0xabcd...)"]
    C["Base L2 Public RPC"] -->|"eth_getTransactionByHash"| D["On-Chain Tx Calldata"]
    C -->|"eth_getBlockByNumber"| E["Immutable Block Timestamp"]
    B --> F{"Cryptographic Match?"}
    D --> F
    F -->|"YES (Exact Match)"| G["✔ CONFIRMED ON-CHAIN"]
    F -->|"NO"| H["✖ REJECTED / MISMATCH"]
```

1. **Local Digest Calculation:**
   $$\text{Digest} = \text{SHA-256}(\text{File Bytes})$$
2. **Blockchain Query:**
   The script queries public Base L2 JSON-RPC nodes (`https://mainnet.base.org`) to fetch transaction status, mined block number, and block header timestamp.
3. **Calldata Inspection:**
   The script checks whether the target 32-byte digest is included in the transaction calldata / `stamp(bytes32)` contract call.
4. **Deterministic Proof:**
   If the digest matches and the transaction receipt status is `0x1` (success), mathematical proof of existence at that exact block timestamp is established.

---

## ⚠️ Scope & Non-Notary Disclaimer

> **IMPORTANT:**
> 
> Proofwax Independent Verifier is an open-source decentralized utility designed exclusively for **mathematical verification of SHA-256 cryptographic fingerprints and Base L2 blockchain timestamping**.
> 
> - **NOT A LEGAL NOTARY:** This software does not provide legal notary services, identity verification, legal advice, or statutory certification.
> - **CONTENT-AGNOSTIC:** The protocol only verifies that a specific cryptographic hash existed at a specific block timestamp. It makes no claims regarding the truthfulness, ownership, legality, or authorship of the document content.
> - **AS-IS:** Provided under the MIT License without warranty of any kind.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
