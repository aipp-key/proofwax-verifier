#!/usr/bin/env python3
"""
Proofwax Independent Cryptographic Verifier (Python)
Zero-dependency verification tool for SHA-256 integrity and Base L2 immutable timestamps.

Usage:
    python verify.py --file document.pdf --tx 0x123...
    python verify.py --hash e3b0c442... --tx 0x123...
    python verify.py --receipt receipt.json
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import urllib.request
import urllib.error

DEFAULT_RPC_URLS = [
    "https://mainnet.base.org",
    "https://base-rpc.publicnode.com",
    "https://1rpc.io/base",
    "https://base.llamarpc.com",
]

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def compute_sha256(file_path: str) -> str:
    """Compute SHA-256 hash of a local file in 64KB chunks."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest().lower()

def rpc_call(method: str, params: list, rpc_urls: list) -> dict:
    """Execute JSON-RPC call against Base L2 nodes with automatic fallback."""
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    }).encode("utf-8")

    last_error = None
    for rpc in rpc_urls:
        try:
            req = urllib.request.Request(
                rpc,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "Proofwax-Verifier/1.0"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if "error" in data:
                    raise RuntimeError(f"RPC Error: {data['error']}")
                return data.get("result")
        except Exception as e:
            last_error = e
            continue
    raise RuntimeError(f"All RPC endpoints failed. Last error: {last_error}")

def normalize_hex(val: str) -> str:
    val = val.strip().lower()
    if val.startswith("0x"):
        return val[2:]
    return val

def verify(sha256_hash: str, tx_hash: str, rpc_urls: list) -> bool:
    print(f"\n{BOLD}{CYAN}=== Proofwax Independent Cryptographic Verifier ==={RESET}\n")
    clean_hash = normalize_hex(sha256_hash)
    clean_tx = tx_hash.strip()
    if not clean_tx.startswith("0x"):
        clean_tx = "0x" + clean_tx

    print(f"Target SHA-256 Digest: {BOLD}0x{clean_hash}{RESET}")
    print(f"Base L2 Transaction:   {BOLD}{clean_tx}{RESET}")
    print(f"Primary RPC:           {rpc_urls[0]}")
    print("\nFetching transaction data directly from Base L2 blockchain...")

    try:
        tx_data = rpc_call("eth_getTransactionByHash", [clean_tx], rpc_urls)
    except Exception as e:
        print(f"\n{RED}[FAILED] Unable to fetch transaction: {e}{RESET}")
        return False

    if not tx_data:
        print(f"\n{RED}[FAILED] Transaction {clean_tx} not found on Base L2.{RESET}")
        return False

    input_data = normalize_hex(tx_data.get("input", ""))
    block_num_hex = tx_data.get("blockNumber")

    if not block_num_hex:
        print(f"\n{YELLOW}[PENDING] Transaction is pending (not yet included in a block).{RESET}")
        return False

    block_num = int(block_num_hex, 16)

    # Fetch receipt for confirmation status
    receipt = rpc_call("eth_getTransactionReceipt", [clean_tx], rpc_urls)
    receipt_status = receipt.get("status") if receipt else None
    is_success = (receipt_status == "0x1" or receipt_status == 1)

    if not is_success:
        print(f"\n{RED}[FAILED] Transaction reverted or execution failed on-chain.{RESET}")
        return False

    # Fetch block timestamp
    block = rpc_call("eth_getBlockByNumber", [block_num_hex, False], rpc_urls)
    timestamp_hex = block.get("timestamp") if block else None
    timestamp = int(timestamp_hex, 16) if timestamp_hex else 0
    dt_utc = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)

    # Check if target hash is in input calldata
    hash_matched = clean_hash in input_data

    print("\n" + "=" * 55)
    if hash_matched:
        print(f"{BOLD}{GREEN}✔ CRYPTOGRAPHIC INTEGRITY VERIFIED (PASS){RESET}")
        print("=" * 55)
        print(f"Status:           {GREEN}CONFIRMED ON BASE L2{RESET}")
        print(f"Block Number:     {block_num}")
        print(f"Timestamp (UTC):  {dt_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"Timestamp (Unix): {timestamp}")
        print(f"Contract / To:    {tx_data.get('to')}")
        print(f"Sender / Relayer: {tx_data.get('from')}")
        print(f"Basescan URL:     https://basescan.org/tx/{clean_tx}")
        print("=" * 55)
        print(f"\n{BOLD}Conclusion:{RESET} The exact SHA-256 digest was anchored into the Base L2 blockchain at the confirmed timestamp above.")
        return True
    else:
        print(f"{BOLD}{RED}✖ HASH MISMATCH (FAIL){RESET}")
        print("=" * 55)
        print(f"The transaction exists on Base L2, but its calldata does NOT match the provided SHA-256 digest.")
        print(f"Expected: 0x{clean_hash}")
        print(f"Tx Input: 0x{input_data[:64]}...")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Proofwax Independent Cryptographic Verifier (Base L2 Proof of Existence)"
    )
    parser.add_argument("--file", "-f", help="Path to local file to verify")
    parser.add_argument("--hash", "-d", help="Direct SHA-256 digest hex (64 chars)")
    parser.add_argument("--tx", "-t", help="Base L2 Transaction Hash (0x...)")
    parser.add_argument("--receipt", "-r", help="Path to Proofwax receipt JSON file")
    parser.add_argument("--rpc", help="Custom Base L2 JSON-RPC URL")

    args = parser.parse_args()

    rpc_urls = [args.rpc] if args.rpc else DEFAULT_RPC_URLS

    sha256_hash = None
    tx_hash = None

    if args.receipt:
        if not os.path.exists(args.receipt):
            print(f"{RED}Receipt file not found: {args.receipt}{RESET}")
            sys.exit(1)
        with open(args.receipt, "r", encoding="utf-8") as f:
            data = json.load(f)
            sha256_hash = data.get("sha256") or data.get("digest") or data.get("documentHash")
            tx_hash = data.get("txHash") or data.get("transactionHash") or data.get("tx")
            if not tx_hash and "anchor" in data:
                tx_hash = data["anchor"].get("txHash")
            if not sha256_hash and "anchor" in data:
                sha256_hash = data["anchor"].get("digest")

    if args.file:
        if not os.path.exists(args.file):
            print(f"{RED}File not found: {args.file}{RESET}")
            sys.exit(1)
        print(f"Computing SHA-256 of file: {args.file}...")
        sha256_hash = compute_sha256(args.file)

    if args.hash:
        sha256_hash = args.hash

    if args.tx:
        tx_hash = args.tx

    if not sha256_hash:
        print(f"{RED}Error: Must provide --file, --hash, or --receipt containing a digest.{RESET}")
        parser.print_help()
        sys.exit(1)

    if not tx_hash:
        print(f"{RED}Error: Must provide --tx or a receipt file containing a transaction hash.{RESET}")
        parser.print_help()
        sys.exit(1)

    success = verify(sha256_hash, tx_hash, rpc_urls)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
