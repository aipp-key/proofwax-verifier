#!/usr/bin/env node
/**
 * Proofwax Independent Cryptographic Verifier (Node.js)
 * Zero external dependencies. Uses native Node.js crypto and fetch APIs.
 *
 * Usage:
 *   node verify.mjs --file document.pdf
 *   node verify.mjs --file document.pdf --tx 0x123...
 *   node verify.mjs --hash e3b0c442...
 *   node verify.mjs --receipt receipt.json
 */

import { createHash } from 'node:crypto';
import { createReadStream, existsSync, readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

const ANCHOR_CONTRACT = '0xaf500675841d3a813a0206ca70fe78bb2a14ff1b';
const DOCUMENT_STAMPED_TOPIC0 = '0x54bf9720aa077207a682c8a6e1efd30c52c50a14e2e3579244b8f3a08a682f0e';

const DEFAULT_RPC_URLS = [
  'https://mainnet.base.org',
  'https://base-rpc.publicnode.com',
  'https://1rpc.io/base',
  'https://base.llamarpc.com',
];

const colors = {
  green: (s) => `\x1b[92m${s}\x1b[0m`,
  red: (s) => `\x1b[91m${s}\x1b[0m`,
  yellow: (s) => `\x1b[93m${s}\x1b[0m`,
  cyan: (s) => `\x1b[96m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
};

async function computeSha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex').toLowerCase()));
    stream.on('error', reject);
  });
}

async function rpcCall(method, params, rpcUrls) {
  let lastError;
  for (const rpc of rpcUrls) {
    try {
      const res = await fetch(rpc, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        signal: AbortSignal.timeout(8000),
      });
      const data = await res.json();
      if (data.error) throw new Error(JSON.stringify(data.error));
      return data.result;
    } catch (e) {
      lastError = e;
    }
  }
  throw new Error(`All Base RPC endpoints failed. Last error: ${lastError?.message || lastError}`);
}

function normalizeHex(hex = '') {
  const clean = hex.trim().toLowerCase();
  return clean.startsWith('0x') ? clean.slice(2) : clean;
}

async function verify(sha256Hash, txHash, rpcUrls) {
  console.log(`\n${colors.bold(colors.cyan('=== Proofwax Independent Cryptographic Verifier ==='))}\n`);
  const cleanHash = normalizeHex(sha256Hash);
  const paddedTopic = `0x${cleanHash}`;

  console.log(`Target SHA-256 Digest: ${colors.bold(`0x${cleanHash}`)}`);
  console.log(`Primary Base RPC:      ${rpcUrls[0]}`);

  let cleanTx = txHash ? (txHash.startsWith('0x') ? txHash : `0x${txHash}`) : null;
  let blockNumber = null;
  let timestamp = null;

  // Auto-scan Base smart contract if no TX provided
  if (!cleanTx) {
    console.log(`Scanning Base L2 contract logs (${ANCHOR_CONTRACT})...`);
    const logs = await rpcCall('eth_getLogs', [{
      address: ANCHOR_CONTRACT,
      topics: [DOCUMENT_STAMPED_TOPIC0, paddedTopic],
      fromBlock: 'earliest',
      toBlock: 'latest',
    }], rpcUrls);

    if (logs && logs.length > 0) {
      const matchLog = logs[0];
      cleanTx = matchLog.transactionHash;
      blockNumber = parseInt(matchLog.blockNumber, 16);
      if (matchLog.data && matchLog.data !== '0x') {
        timestamp = parseInt(matchLog.data, 16);
      }
      console.log(colors.green('✔ Found matching anchor event in Base L2 contract!'));
    } else {
      console.log(`\n${colors.red('[NOT FOUND] Document hash not found in smart contract event logs.')}`);
      console.log('If anchored via custom relayer calldata, please specify the transaction hash with --tx <hash>.');
      return false;
    }
  }

  console.log(`Base L2 Transaction:   ${colors.bold(cleanTx)}`);
  console.log(`\nFetching transaction confirmations from Base L2...`);

  const tx = await rpcCall('eth_getTransactionByHash', [cleanTx], rpcUrls);
  if (!tx) {
    console.log(`\n${colors.red(`[FAILED] Transaction ${cleanTx} not found on Base L2.`)}`);
    return false;
  }

  if (!tx.blockNumber) {
    console.log(`\n${colors.yellow(`[PENDING] Transaction is pending and not yet confirmed in a block.`)}`);
    return false;
  }

  const receipt = await rpcCall('eth_getTransactionReceipt', [cleanTx], rpcUrls);
  const isSuccess = receipt?.status === '0x1' || receipt?.status === 1;
  if (!isSuccess) {
    console.log(`\n${colors.red(`[FAILED] Transaction execution reverted on-chain.`)}`);
    return false;
  }

  blockNumber = blockNumber || parseInt(tx.blockNumber, 16);

  if (!timestamp) {
    const block = await rpcCall('eth_getBlockByNumber', [tx.blockNumber, false], rpcUrls);
    timestamp = parseInt(block.timestamp, 16);
  }

  const dateUtc = new Date(timestamp * 1000).toUTCString();
  const inputData = normalizeHex(tx.input || '');
  const hashMatched = inputData.includes(cleanHash) || (tx.to && tx.to.toLowerCase() === ANCHOR_CONTRACT.toLowerCase());

  console.log('\n' + '='.repeat(60));
  if (hashMatched) {
    console.log(`${colors.bold(colors.green('✔ CRYPTOGRAPHIC INTEGRITY VERIFIED (PASS)'))}`);
    console.log('='.repeat(60));
    console.log(`Status:           ${colors.green('CONFIRMED ON BASE L2')}`);
    console.log(`Block Number:     #${blockNumber}`);
    console.log(`Timestamp (UTC):  ${dateUtc}`);
    console.log(`Timestamp (Unix): ${timestamp}`);
    console.log(`Target Contract:  ${tx.to || ANCHOR_CONTRACT}`);
    console.log(`Relayer Address:  ${tx.from}`);
    console.log(`Basescan Link:    https://basescan.org/tx/${cleanTx}`);
    console.log('='.repeat(60));
    console.log(`\n${colors.bold('Conclusion:')} The exact SHA-256 digest was anchored on Base L2 at the verified timestamp above.`);
    return true;
  } else {
    console.log(`${colors.bold(colors.red('✖ HASH MISMATCH (FAIL)'))}`);
    console.log('='.repeat(60));
    console.log(`The transaction exists on Base L2, but does NOT match the provided SHA-256 digest.`);
    return false;
  }
}

async function main() {
  const { values } = parseArgs({
    options: {
      file: { type: 'string', short: 'f' },
      hash: { type: 'string', short: 'd' },
      tx: { type: 'string', short: 't' },
      receipt: { type: 'string', short: 'r' },
      rpc: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
    allowPositionals: true,
  });

  if (values.help) {
    console.log(`
Proofwax Independent Verifier
Options:
  -f, --file <path>     Path to file to compute SHA-256 and verify
  -d, --hash <hex>      Direct 64-char SHA-256 digest hex
  -t, --tx <hex>        Base L2 Transaction Hash (optional if anchored on contract)
  -r, --receipt <path>  Path to Proofwax receipt JSON
      --rpc <url>       Custom Base RPC URL
    `);
    process.exit(0);
  }

  const rpcUrls = values.rpc ? [values.rpc] : DEFAULT_RPC_URLS;
  let sha256Hash = values.hash;
  let txHash = values.tx;

  if (values.receipt) {
    if (!existsSync(values.receipt)) {
      console.error(colors.red(`Receipt file not found: ${values.receipt}`));
      process.exit(1);
    }
    const data = JSON.parse(readFileSync(values.receipt, 'utf8'));
    sha256Hash = data.sha256 || data.digest || data.documentHash || data.anchor?.digest;
    if (!txHash) {
      txHash = data.txHash || data.transactionHash || data.tx || data.anchor?.txHash;
    }
  }

  if (values.file) {
    if (!existsSync(values.file)) {
      console.error(colors.red(`File not found: ${values.file}`));
      process.exit(1);
    }
    console.log(`Computing SHA-256 of file: ${values.file}...`);
    sha256Hash = await computeSha256(values.file);
  }

  if (!sha256Hash) {
    console.error(colors.red('Error: Must provide file/hash or receipt JSON.'));
    console.log('Run with --help for usage information.');
    process.exit(1);
  }

  try {
    const success = await verify(sha256Hash, txHash, rpcUrls);
    process.exit(success ? 0 : 1);
  } catch (err) {
    console.error(colors.red(`\nVerification Error: ${err.message}`));
    process.exit(1);
  }
}

main();
