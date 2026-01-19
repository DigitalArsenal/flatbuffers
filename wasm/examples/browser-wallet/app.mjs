/**
 * FlatBuffers Crypto Wallet Demo
 *
 * Login-first flow:
 * 1. User creates/restores wallet (username+password or seed phrase)
 * 2. Keys are derived and stored in memory
 * 3. Generate real FlatBuffer records with field-level encryption
 * 4. Toggle between encrypted/decrypted hex with value display
 * 5. Streaming demo with message routing by type
 */

import * as bip39 from 'bip39';
import { HDKey } from '@scure/bip32';
import QRCode from 'qrcode';
import { Buffer } from 'buffer';
import { createV3 } from 'vcard-cryptoperson';

// Make Buffer available globally for bip39
window.Buffer = Buffer;

import {
  loadEncryptionWasm,
  sha256,
  hkdf,
  x25519GenerateKeyPair,
  ed25519GenerateKeyPair,
  secp256k1GenerateKeyPair,
  p256GenerateKeyPair,
  encryptBytes,
  decryptBytes,
  EncryptionContext,
  encryptionHeaderToJSON,
  encryptionHeaderFromJSON,
  encryptBuffer,
  decryptBuffer,
} from '../../src/encryption.mjs';

import { FlatcRunner } from '../../src/runner.mjs';
import { FlatBufferParser, parseWithSchema, Schemas, toHex, toHexCompact } from './flatbuffer-parser.mjs';
import { VirtualTable } from './virtual-scroller.mjs';
import { StreamingDemo, MessageTypes, formatBytes, formatThroughput } from './streaming-demo.mjs';

// Import schemas as raw text
import monsterSchema from './schemas/monster.fbs?raw';
import basicSchema from './schemas/basic.fbs?raw';

// Paths - use relative path for GitHub Pages compatibility
const ENCRYPTION_WASM_PATH = './flatc-encryption.wasm';

// =============================================================================
// State
// =============================================================================

const state = {
  initialized: false,
  loggedIn: false,
  selectedCrypto: 'btc',
  addresses: {
    btc: null,
    eth: null,
    sol: null,
  },
  wallet: {
    x25519: null,
    ed25519: null,
    secp256k1: null,
    p256: null,
  },
  // HD wallet state
  masterSeed: null,
  hdRoot: null,
  // FlatBuffer state
  flatcRunner: null,
  buffers: [],
  encryptedBuffers: [],
  showEncrypted: true,
  encryptionKey: null,
  encryptionIV: null,
  // Field display state
  currentFieldData: null,
  showFieldDecrypted: false,
  // Virtual table
  virtualTable: null,
  // Streaming demo
  streamingDemo: null,
  // PKI Demo state
  pki: {
    alice: null,  // { privateKey, publicKey }
    bob: null,    // { privateKey, publicKey }
    algorithm: 'x25519',
    plaintext: null,
    ciphertext: null,
    header: null,
    decrypted: null,
  },
};

// =============================================================================
// Schema Configuration
// =============================================================================

const schemaConfig = {
  monster: {
    entry: '/monster.fbs',
    files: { '/monster.fbs': monsterSchema },
    sampleData: (index) => ({
      pos: { x: Math.random() * 100, y: Math.random() * 100, z: Math.random() * 50 },
      mana: 100 + Math.floor(Math.random() * 100),
      hp: 50 + Math.floor(Math.random() * 150),
      name: `Monster_${index}`,
      inventory: Array.from({ length: 3 + Math.floor(Math.random() * 5) }, () => Math.floor(Math.random() * 256)),
      color: Math.floor(Math.random() * 3),
    }),
    parserSchema: Schemas.monster,
  },
  weapon: {
    entry: '/weapon.fbs',
    files: {
      '/weapon.fbs': `
namespace MyGame.Sample;
table Weapon {
  name:string;
  damage:short;
}
root_type Weapon;
file_identifier "WEAP";
`,
    },
    sampleData: (index) => ({
      name: ['Sword', 'Axe', 'Bow', 'Dagger', 'Staff', 'Mace'][index % 6] + `_${index}`,
      damage: 10 + Math.floor(Math.random() * 90),
    }),
    parserSchema: Schemas.weapon,
  },
  galaxy: {
    entry: '/galaxy.fbs',
    files: {
      '/galaxy.fbs': `
namespace flatbuffers.goldens;
table Galaxy {
  num_stars:long;
}
root_type Galaxy;
file_identifier "GALX";
`,
    },
    sampleData: (index) => ({
      num_stars: BigInt(Math.floor(Math.random() * 1e12) + 1e9),
    }),
    parserSchema: Schemas.galaxy,
  },
};

// =============================================================================
// Crypto Address Generation & Explorers
// =============================================================================

const cryptoConfig = {
  btc: {
    name: 'Bitcoin',
    symbol: 'BTC',
    coinType: 0,
    explorer: 'https://blockstream.info/address/',
    balanceApi: 'https://blockstream.info/api/address/',
    formatBalance: (satoshis) => `${(satoshis / 100000000).toFixed(8)} BTC`,
  },
  eth: {
    name: 'Ethereum',
    symbol: 'ETH',
    coinType: 60,
    explorer: 'https://etherscan.io/address/',
    balanceApi: null,
    formatBalance: (wei) => `${(parseFloat(wei) / 1e18).toFixed(6)} ETH`,
  },
  sol: {
    name: 'Solana',
    symbol: 'SOL',
    coinType: 501,
    explorer: 'https://solscan.io/account/',
    balanceApi: null,
    formatBalance: (lamports) => `${(lamports / 1e9).toFixed(4)} SOL`,
  },
  ltc: {
    name: 'Litecoin',
    symbol: 'LTC',
    coinType: 2,
    explorer: 'https://blockchair.com/litecoin/address/',
    balanceApi: null,
    formatBalance: (lits) => `${(lits / 100000000).toFixed(8)} LTC`,
  },
  bch: {
    name: 'Bitcoin Cash',
    symbol: 'BCH',
    coinType: 145,
    explorer: 'https://blockchair.com/bitcoin-cash/address/',
    balanceApi: null,
    formatBalance: (sats) => `${(sats / 100000000).toFixed(8)} BCH`,
  },
  doge: {
    name: 'Dogecoin',
    symbol: 'DOGE',
    coinType: 3,
    explorer: 'https://dogechain.info/address/',
    balanceApi: null,
    formatBalance: (sats) => `${(sats / 100000000).toFixed(4)} DOGE`,
  },
  atom: {
    name: 'Cosmos',
    symbol: 'ATOM',
    coinType: 118,
    explorer: 'https://www.mintscan.io/cosmos/address/',
    balanceApi: null,
    formatBalance: (uatom) => `${(uatom / 1e6).toFixed(6)} ATOM`,
  },
  algo: {
    name: 'Algorand',
    symbol: 'ALGO',
    coinType: 330,
    explorer: 'https://algoexplorer.io/address/',
    balanceApi: null,
    formatBalance: (microalgos) => `${(microalgos / 1e6).toFixed(6)} ALGO`,
  },
  dot: {
    name: 'Polkadot',
    symbol: 'DOT',
    coinType: 354,
    explorer: 'https://polkascan.io/polkadot/account/',
    balanceApi: null,
    formatBalance: (planks) => `${(planks / 1e10).toFixed(4)} DOT`,
  },
  ada: {
    name: 'Cardano',
    symbol: 'ADA',
    coinType: 1815,
    explorer: 'https://cardanoscan.io/address/',
    balanceApi: null,
    formatBalance: (lovelace) => `${(lovelace / 1e6).toFixed(6)} ADA`,
  },
};

// Coin type to config mapping
const coinTypeToConfig = Object.fromEntries(
  Object.entries(cryptoConfig).map(([key, config]) => [config.coinType, { key, ...config }])
);

function generateBtcAddress(publicKey) {
  const hash = sha256(publicKey);
  return '1' + toBase58(hash.slice(0, 20));
}

function generateEthAddress(publicKey) {
  const hash = sha256(publicKey);
  return '0x' + toHexCompact(hash.slice(12, 32));
}

function generateSolAddress(publicKey) {
  return toBase58(publicKey);
}

function toBase58(bytes) {
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let num = BigInt('0x' + toHexCompact(bytes));
  let result = '';
  while (num > 0) {
    result = ALPHABET[Number(num % 58n)] + result;
    num = num / 58n;
  }
  for (const byte of bytes) {
    if (byte === 0) result = '1' + result;
    else break;
  }
  return result || '1';
}

function generateAddresses(wallet) {
  return {
    btc: generateBtcAddress(wallet.secp256k1.publicKey),
    eth: generateEthAddress(wallet.secp256k1.publicKey),
    sol: generateSolAddress(wallet.ed25519.publicKey),
  };
}

function truncateAddress(address) {
  if (address.length <= 16) return address;
  return address.slice(0, 8) + '...' + address.slice(-6);
}

async function fetchBalance(crypto, address) {
  const config = cryptoConfig[crypto];
  if (!config.balanceApi) return null;

  try {
    if (crypto === 'btc') {
      const response = await fetch(config.balanceApi + address);
      if (!response.ok) return null;
      const data = await response.json();
      const balance = data.chain_stats?.funded_txo_sum - data.chain_stats?.spent_txo_sum || 0;
      return config.formatBalance(balance);
    }
  } catch (err) {
    console.warn('Failed to fetch balance:', err);
  }
  return null;
}

function updateAddressDisplay() {
  const crypto = state.selectedCrypto;
  const address = state.addresses[crypto];
  const config = cryptoConfig[crypto];

  // Update hero stats
  const walletTypeEl = $('hero-wallet-type');
  const heroAddressEl = $('hero-address');

  if (walletTypeEl) {
    walletTypeEl.textContent = config.name;
  }
  if (heroAddressEl && address) {
    heroAddressEl.textContent = truncateAddress(address);
    heroAddressEl.title = address;
  }
}

// =============================================================================
// Utilities
// =============================================================================

function toBase64(arr) {
  return btoa(String.fromCharCode(...arr));
}

function $(id) {
  return document.getElementById(id);
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// =============================================================================
// Entropy Calculation
// =============================================================================

function calculateEntropy(password) {
  if (!password) return 0;

  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password)) charsetSize += 32;
  if (/\s/.test(password)) charsetSize += 1;
  if (/[^\x00-\x7F]/.test(password)) charsetSize += 100;

  if (charsetSize === 0) return 0;
  return Math.round(password.length * Math.log2(charsetSize));
}

function updatePasswordStrength(password) {
  const entropy = calculateEntropy(password);
  const fill = $('strength-fill');
  const bits = $('entropy-bits');
  const btn = $('derive-from-password');

  if (bits) bits.textContent = `${entropy}`;
  if (fill) fill.className = 'entropy-fill';

  let strength, percentage;

  if (entropy < 28) {
    strength = 'weak';
    percentage = Math.min(25, (entropy / 28) * 25);
  } else if (entropy < 60) {
    strength = 'fair';
    percentage = 25 + ((entropy - 28) / 32) * 25;
  } else if (entropy < 128) {
    strength = 'good';
    percentage = 50 + ((entropy - 60) / 68) * 25;
  } else {
    strength = 'strong';
    percentage = 75 + Math.min(25, ((entropy - 128) / 128) * 25);
  }

  if (fill) {
    fill.classList.add(strength);
    fill.style.width = `${percentage}%`;
  }

  const username = $('wallet-username').value;
  if (btn) btn.disabled = !username || password.length < 24;
}

// =============================================================================
// Key Derivation
// =============================================================================

async function deriveKeysFromPassword(username, password) {
  const encoder = new TextEncoder();
  const usernameSalt = encoder.encode(username);
  const passwordBytes = encoder.encode(password);

  const initialHash = sha256(new Uint8Array([...usernameSalt, ...passwordBytes]));
  const masterKey = hkdf(initialHash, usernameSalt, encoder.encode('master-key'), 32);

  state.encryptionKey = hkdf(masterKey, new Uint8Array(0), encoder.encode('buffer-encryption-key'), 32);
  state.encryptionIV = hkdf(masterKey, new Uint8Array(0), encoder.encode('buffer-encryption-iv'), 16);

  // Create 64-byte seed for HD wallet (password-based, not BIP39)
  const hdSeed = hkdf(masterKey, new Uint8Array(0), encoder.encode('hd-wallet-seed'), 64);
  state.masterSeed = hdSeed;
  state.hdRoot = HDKey.fromMasterSeed(hdSeed);

  const keys = {
    x25519: x25519GenerateKeyPair(),
    ed25519: ed25519GenerateKeyPair(),
    secp256k1: secp256k1GenerateKeyPair(),
    p256: p256GenerateKeyPair(),
  };

  return keys;
}

async function deriveKeysFromSeed(seedPhrase) {
  const seed = await bip39.mnemonicToSeed(seedPhrase);
  const encoder = new TextEncoder();

  const masterKey = hkdf(
    new Uint8Array(seed.slice(0, 32)),
    new Uint8Array(0),
    encoder.encode('flatbuffers-wallet'),
    32
  );

  state.encryptionKey = hkdf(masterKey, new Uint8Array(0), encoder.encode('buffer-encryption-key'), 32);
  state.encryptionIV = hkdf(masterKey, new Uint8Array(0), encoder.encode('buffer-encryption-iv'), 16);

  // Store seed for HD wallet derivation (BIP39 standard)
  state.masterSeed = new Uint8Array(seed);
  state.hdRoot = HDKey.fromMasterSeed(new Uint8Array(seed));

  const keys = {
    x25519: x25519GenerateKeyPair(),
    ed25519: ed25519GenerateKeyPair(),
    secp256k1: secp256k1GenerateKeyPair(),
    p256: p256GenerateKeyPair(),
  };

  return keys;
}

function generateSeedPhrase() {
  return bip39.generateMnemonic(256);
}

function validateSeedPhrase(phrase) {
  return bip39.validateMnemonic(phrase.trim().toLowerCase());
}

// =============================================================================
// HD Wallet Derivation
// =============================================================================

/**
 * Derive a child key from the HD root using BIP44 path
 * Path format: m/purpose'/coin_type'/account'/change/address_index
 */
function deriveHDKey(path) {
  if (!state.hdRoot) {
    throw new Error('HD wallet not initialized');
  }
  // @scure/bip32 uses derivePath method
  return state.hdRoot.derive(path);
}

/**
 * Generate address from public key based on coin type
 */
function generateAddressForCoin(publicKey, coinType) {
  const config = coinTypeToConfig[coinType];
  if (!config) {
    // Default to hex representation
    return toHexCompact(publicKey);
  }

  switch (coinType) {
    case 0:   // Bitcoin
    case 2:   // Litecoin
    case 3:   // Dogecoin
    case 145: // Bitcoin Cash
      return generateBtcAddress(publicKey);

    case 60:  // Ethereum
      return generateEthAddress(publicKey);

    case 501: // Solana
      return generateSolAddress(publicKey);

    default:
      // For unsupported coins, return a truncated public key hash
      const hash = sha256(publicKey);
      return toHexCompact(hash.slice(0, 20));
  }
}

/**
 * Get full BIP44 path from UI inputs
 */
function getHDPathFromUI() {
  const purpose = $('hd-purpose').value;
  const coin = $('hd-coin').value;
  const account = $('hd-account').value || '0';
  const change = $('hd-change').value;
  const index = $('hd-index').value || '0';

  return `m/${purpose}'/${coin}'/${account}'/${change}/${index}`;
}

/**
 * Update the path display from UI inputs
 */
function updatePathDisplay() {
  const path = getHDPathFromUI();
  $('full-path').textContent = path;
}

/**
 * Derive and display address from current path
 */
async function deriveAndDisplayAddress() {
  const path = getHDPathFromUI();
  const coinType = parseInt($('hd-coin').value);
  const coinOption = $('hd-coin').selectedOptions[0];
  const cryptoName = coinOption.dataset.name || 'Unknown';
  const cryptoSymbol = coinOption.dataset.symbol || '???';

  try {
    const childKey = deriveHDKey(path);
    const publicKey = childKey.publicKey;
    const address = generateAddressForCoin(publicKey, coinType);

    // Get config for explorer link
    const config = coinTypeToConfig[coinType];
    const explorerUrl = config ? config.explorer + address : null;

    // Update UI
    $('derived-result').style.display = 'block';
    $('derived-crypto-name').textContent = cryptoName;
    $('derived-icon').textContent = cryptoSymbol.substring(0, 2);
    $('derived-pubkey').textContent = toHexCompact(publicKey);
    $('derived-address').textContent = address;

    // Update explorer link
    const explorerLink = $('derived-explorer-link');
    if (explorerUrl) {
      explorerLink.href = explorerUrl;
      explorerLink.style.display = 'flex';
    } else {
      explorerLink.style.display = 'none';
    }

    // Generate QR code
    try {
      await QRCode.toCanvas($('address-qr'), address, {
        width: 128,
        margin: 2,
        color: { dark: '#1e293b', light: '#ffffff' },
      });
    } catch (qrErr) {
      console.warn('QR generation failed:', qrErr);
    }

    // Fetch balance if API available
    if (config && config.balanceApi) {
      $('balance-row').style.display = 'flex';
      $('derived-balance').textContent = 'Loading...';
      try {
        const balance = await fetchBalance(config.key, address);
        $('derived-balance').textContent = balance || 'Unable to fetch';
      } catch (err) {
        $('derived-balance').textContent = 'Error';
      }
    } else {
      $('balance-row').style.display = 'none';
    }

  } catch (err) {
    console.error('Derivation failed:', err);
    alert('Failed to derive address: ' + err.message);
  }
}

/**
 * Quick derive for a specific coin
 */
function quickDerive(coinType, purpose) {
  $('hd-purpose').value = purpose;
  $('hd-coin').value = coinType;
  $('hd-account').value = '0';
  $('hd-change').value = '0';
  $('hd-index').value = '0';
  updatePathDisplay();
  deriveAndDisplayAddress();
}

// =============================================================================
// Login / Logout
// =============================================================================

function login(keys) {
  state.loggedIn = true;
  state.wallet = keys;
  state.addresses = generateAddresses(keys);
  state.selectedCrypto = 'btc';

  // Hide login card, show hero stats
  $('login-card').style.display = 'none';
  $('hero-stats').style.display = 'flex';

  // Update hero stats display
  $('hero-wallet-type').textContent = cryptoConfig[state.selectedCrypto].name;
  $('hero-address').textContent = truncateAddress(state.addresses[state.selectedCrypto]);

  // Show main app content
  $('main-app').style.display = 'block';

  // Show nav action buttons
  $('nav-keys').style.display = 'flex';
  $('nav-logout').style.display = 'flex';

  // Update keys modal display
  $('wallet-x25519-pub').textContent = toHexCompact(keys.x25519.publicKey);
  $('wallet-ed25519-pub').textContent = toHexCompact(keys.ed25519.publicKey);
  $('wallet-secp256k1-pub').textContent = toHexCompact(keys.secp256k1.publicKey);
}

function logout() {
  state.loggedIn = false;
  state.wallet = { x25519: null, ed25519: null, secp256k1: null, p256: null };
  state.buffers = [];
  state.encryptedBuffers = [];
  state.encryptionKey = null;
  state.encryptionIV = null;
  state.currentFieldData = null;
  state.showFieldDecrypted = false;
  // Clear HD wallet state
  state.masterSeed = null;
  state.hdRoot = null;

  // Hide main app content
  $('main-app').style.display = 'none';

  // Hide hero stats, show login card
  $('hero-stats').style.display = 'none';
  $('login-card').style.display = 'block';

  // Hide nav action buttons
  $('nav-keys').style.display = 'none';
  $('nav-logout').style.display = 'none';

  // Clear form inputs
  $('wallet-username').value = '';
  $('wallet-password').value = '';
  $('seed-phrase').value = '';
  updatePasswordStrength('');
  clearBufferDisplay();
  clearFieldDisplay();

  // Clear HD wallet UI
  $('derived-result').style.display = 'none';

  // Reset to first tab
  document.querySelectorAll('.nav-link[data-tab]').forEach(l => l.classList.remove('active'));
  const firstLink = document.querySelector('.nav-link[data-tab="fields"]');
  if (firstLink) firstLink.classList.add('active');
  document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
  const fieldsTab = $('fields-tab');
  if (fieldsTab) fieldsTab.classList.add('active');
}

// =============================================================================
// FlatBuffer Generation
// =============================================================================

async function generateFlatBuffer(schemaType, data) {
  const config = schemaConfig[schemaType];
  if (!config) throw new Error(`Unknown schema: ${schemaType}`);

  // Convert BigInt to string for JSON serialization
  const jsonData = JSON.stringify(data, (key, value) =>
    typeof value === 'bigint' ? value.toString() : value
  );

  const binary = state.flatcRunner.generateBinary(
    { entry: config.entry, files: config.files },
    jsonData
  );

  return binary;
}

function encryptFieldBytes(bytes) {
  const encrypted = new Uint8Array(bytes);
  encryptBytes(encrypted, state.encryptionKey, state.encryptionIV);
  return encrypted;
}

function decryptFieldBytes(bytes) {
  const decrypted = new Uint8Array(bytes);
  decryptBytes(decrypted, state.encryptionKey, state.encryptionIV);
  return decrypted;
}

// =============================================================================
// Field-Level Encryption Display
// =============================================================================

async function generateSingleRecord() {
  const schemaType = $('schema-select').value;
  const config = schemaConfig[schemaType];

  try {
    const data = config.sampleData(0);
    const binary = await generateFlatBuffer(schemaType, data);

    const parser = new FlatBufferParser(binary);
    const parsed = parseWithSchema(parser, config.parserSchema.fields);

    // Encrypt each field
    const encryptedFields = parsed.fields.map(field => {
      if (field.bytes && field.bytes.length > 0) {
        return {
          ...field,
          encryptedBytes: encryptFieldBytes(field.bytes),
        };
      }
      return field;
    });

    state.currentFieldData = {
      binary,
      header: parsed.header,
      vtable: parsed.vtable,
      fields: encryptedFields,
      originalData: data,
    };
    state.showFieldDecrypted = false;

    renderFieldDisplay();
    $('toggle-field-decrypt').disabled = false;
    $('toggle-field-decrypt').textContent = 'Show Decrypted';

  } catch (err) {
    console.error('Failed to generate record:', err);
    alert('Error generating record: ' + err.message);
  }
}

function renderFieldDisplay() {
  const data = state.currentFieldData;
  if (!data) return;

  // Show header section
  $('fb-header').style.display = 'block';
  $('root-offset-hex').textContent = data.header.rootOffsetHex;
  $('root-offset-val').textContent = `(${data.header.rootOffset})`;
  $('file-id-hex').textContent = data.header.fileIdHex;
  $('file-id-val').textContent = data.header.fileId ? `"${data.header.fileId}"` : '--';
  $('vtable-size-hex').textContent = toHex(new Uint8Array([
    data.vtable.vtableSize & 0xFF,
    (data.vtable.vtableSize >> 8) & 0xFF,
  ]));
  $('vtable-size-val').textContent = `(${data.vtable.vtableSize})`;
  $('table-size-hex').textContent = toHex(new Uint8Array([
    data.vtable.tableSize & 0xFF,
    (data.vtable.tableSize >> 8) & 0xFF,
  ]));
  $('table-size-val').textContent = `(${data.vtable.tableSize})`;

  // Show field table
  $('field-table-container').style.display = 'block';
  const tbody = $('field-body');
  tbody.innerHTML = '';

  // Toggle decrypt columns visibility
  const table = $('field-table');
  if (state.showFieldDecrypted) {
    table.classList.add('show-decrypted');
  } else {
    table.classList.remove('show-decrypted');
  }

  for (const field of data.fields) {
    const tr = document.createElement('tr');

    // Field name
    const nameTd = document.createElement('td');
    nameTd.textContent = field.name;
    nameTd.className = 'field-name';
    tr.appendChild(nameTd);

    // Type
    const typeTd = document.createElement('td');
    typeTd.textContent = field.type;
    typeTd.className = 'field-type';
    tr.appendChild(typeTd);

    // Offset
    const offsetTd = document.createElement('td');
    offsetTd.textContent = field.present ? `0x${field.vtableOffset.toString(16).padStart(2, '0').toUpperCase()}` : '--';
    offsetTd.className = 'field-offset';
    tr.appendChild(offsetTd);

    // Encrypted hex
    const encTd = document.createElement('td');
    if (field.encryptedBytes) {
      encTd.textContent = toHex(field.encryptedBytes);
      encTd.title = `${field.encryptedBytes.length} bytes encrypted`;
    } else if (!field.present) {
      encTd.textContent = '(not present)';
      encTd.className = 'not-present';
    } else {
      encTd.textContent = '--';
    }
    encTd.className = 'hex encrypted-hex';
    tr.appendChild(encTd);

    // Decrypted hex (decrypt-col)
    const decHexTd = document.createElement('td');
    decHexTd.className = 'hex decrypt-col';
    if (field.bytes && state.showFieldDecrypted) {
      decHexTd.textContent = toHex(field.bytes);
    } else {
      decHexTd.textContent = '--';
    }
    tr.appendChild(decHexTd);

    // Value (decrypt-col)
    const valueTd = document.createElement('td');
    valueTd.className = 'decrypt-col';
    if (state.showFieldDecrypted && field.present) {
      valueTd.textContent = formatFieldValue(field.value, field.type);
    } else {
      valueTd.textContent = '--';
    }
    tr.appendChild(valueTd);

    tbody.appendChild(tr);
  }
}

function formatFieldValue(value, type) {
  if (value === null || value === undefined) return '--';

  if (type === 'string') return `"${value}"`;
  if (Array.isArray(value)) {
    if (value.length <= 8) return `[${value.join(', ')}]`;
    return `[${value.slice(0, 5).join(', ')}... (${value.length} items)]`;
  }
  if (typeof value === 'object') {
    // Struct display
    const entries = Object.entries(value);
    return `{${entries.map(([k, v]) => `${k}:${typeof v === 'number' ? v.toFixed(2) : v}`).join(', ')}}`;
  }
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number') {
    if (Number.isInteger(value)) return value.toString();
    return value.toFixed(4);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';

  return String(value);
}

function toggleFieldDecrypt() {
  state.showFieldDecrypted = !state.showFieldDecrypted;
  $('toggle-field-decrypt').textContent = state.showFieldDecrypted ? 'Show Encrypted' : 'Show Decrypted';
  renderFieldDisplay();
}

function clearFieldDisplay() {
  state.currentFieldData = null;
  state.showFieldDecrypted = false;
  $('fb-header').style.display = 'none';
  $('field-table-container').style.display = 'none';
  $('toggle-field-decrypt').disabled = true;
}

// =============================================================================
// Bulk Buffer Generation
// =============================================================================

// Reinitialize FlatcRunner periodically to prevent WASM memory fragmentation
const RUNNER_RESET_INTERVAL = 500;

/**
 * Reset the FlatcRunner to free WASM memory.
 * This creates a fresh WASM instance which releases memory from the old one.
 */
async function resetFlatcRunner() {
  state.flatcRunner = await FlatcRunner.init();
}

async function generateBulkBuffers() {
  const schemaType = $('bulk-schema').value;
  const count = parseInt($('buffer-count').value);
  const config = schemaConfig[schemaType];

  const btn = $('generate-buffers');
  btn.disabled = true;
  btn.textContent = 'Generating...';

  const startTime = performance.now();

  try {
    // Clear previous data to free memory
    state.buffers = [];
    state.encryptedBuffers = [];

    const batchSize = Math.min(100, count);
    let totalSize = 0;
    let runnerResetCounter = 0;

    for (let i = 0; i < count; i += batchSize) {
      const batchEnd = Math.min(i + batchSize, count);

      for (let j = i; j < batchEnd; j++) {
        const data = config.sampleData(j);
        const binary = await generateFlatBuffer(schemaType, data);

        // Encrypt the entire buffer
        const encrypted = new Uint8Array(binary);
        encryptBytes(encrypted, state.encryptionKey, state.encryptionIV);

        // Store data and encrypted buffer (not original binary to save memory)
        state.buffers.push({
          index: j,
          data,
          size: binary.length,
        });
        state.encryptedBuffers.push(encrypted);
        totalSize += binary.length;

        runnerResetCounter++;
      }

      // Periodically reset FlatcRunner to release WASM memory
      // This prevents "memory access out of bounds" on large generations
      if (runnerResetCounter >= RUNNER_RESET_INTERVAL && i + batchSize < count) {
        await resetFlatcRunner();
        runnerResetCounter = 0;
      }

      // Update progress and yield to UI
      const progress = Math.round((batchEnd / count) * 100);
      btn.textContent = `Generating... ${progress}%`;
      await new Promise(r => setTimeout(r, 0));
    }

    const elapsed = performance.now() - startTime;

    // Update stats
    $('stat-count').textContent = count.toLocaleString();
    $('stat-size').textContent = formatSize(totalSize);
    $('stat-time').textContent = `${Math.round(elapsed)} ms`;
    $('stat-memory').textContent = formatSize(performance.memory?.usedJSHeapSize || 0);
    $('stats-bar').style.display = 'flex';

    // Enable buttons
    $('toggle-encryption').disabled = false;
    $('toggle-encryption').textContent = 'Show Decrypted';
    $('clear-buffers').disabled = false;
    state.showEncrypted = true;

    // Render virtual table
    renderBulkTable(schemaType);
    $('data-card').style.display = 'block';

  } catch (err) {
    console.error('Failed to generate buffers:', err);
    alert('Error generating buffers: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Generate & Encrypt';
  }
}

function renderBulkTable(schemaType) {
  const config = schemaConfig[schemaType];
  const container = $('virtual-table-wrapper');

  // Define columns based on schema
  let columns;
  if (schemaType === 'monster') {
    columns = [
      { key: 'name', label: 'Name', width: '120px' },
      { key: 'hp', label: 'HP', width: '60px' },
      { key: 'mana', label: 'Mana', width: '60px' },
      { key: 'pos', label: 'Position', format: (v) => v ? `(${v.x.toFixed(1)}, ${v.y.toFixed(1)}, ${v.z.toFixed(1)})` : '--' },
      { key: 'encrypted', label: 'Encrypted Bytes', className: 'encrypted-hex', format: (_, record) => {
        const enc = state.encryptedBuffers[record.index];
        return toHex(enc.slice(0, 16)) + (enc.length > 16 ? '...' : '');
      }},
    ];
  } else if (schemaType === 'weapon') {
    columns = [
      { key: 'name', label: 'Name', width: '150px' },
      { key: 'damage', label: 'Damage', width: '80px' },
      { key: 'encrypted', label: 'Encrypted Bytes', className: 'encrypted-hex', format: (_, record) => {
        const enc = state.encryptedBuffers[record.index];
        return toHex(enc.slice(0, 16)) + (enc.length > 16 ? '...' : '');
      }},
    ];
  } else if (schemaType === 'galaxy') {
    columns = [
      { key: 'num_stars', label: 'Stars', format: (v) => typeof v === 'bigint' ? v.toLocaleString() : String(v) },
      { key: 'encrypted', label: 'Encrypted Bytes', className: 'encrypted-hex', format: (_, record) => {
        const enc = state.encryptedBuffers[record.index];
        return toHex(enc);
      }},
    ];
  }

  // Destroy old virtual table
  if (state.virtualTable) {
    state.virtualTable.destroy();
  }

  // Create new virtual table
  state.virtualTable = new VirtualTable(container, {
    columns,
    rowHeight: 36,
    onRowClick: (record, index) => {
      console.log('Clicked record:', record, 'at index:', index);
    },
  });

  // Prepare records
  const records = state.buffers.map(b => ({ ...b.data, index: b.index }));
  state.virtualTable.setData(records);

  // Update visible range display
  const updateRange = () => {
    const range = state.virtualTable.getVisibleRange();
    $('visible-range').textContent = `(showing ${range.start + 1}-${range.end} of ${range.total})`;
  };
  updateRange();

  // Update on scroll
  state.virtualTable.scrollWrapper.addEventListener('scroll', updateRange);
}

function toggleEncryption() {
  state.showEncrypted = !state.showEncrypted;
  $('toggle-encryption').textContent = state.showEncrypted ? 'Show Decrypted' : 'Show Encrypted';

  // Update virtual table columns if needed
  if (state.virtualTable && state.virtualTable.columns && state.virtualTable.columns.length > 0) {
    const columns = state.virtualTable.columns;
    const lastCol = columns[columns.length - 1];

    if (state.showEncrypted) {
      lastCol.label = 'Encrypted Bytes';
      lastCol.format = (_, record) => {
        const enc = state.encryptedBuffers[record.index];
        return toHex(enc.slice(0, 16)) + (enc.length > 16 ? '...' : '');
      };
    } else {
      lastCol.label = 'Decrypted Bytes';
      lastCol.format = (_, record) => {
        const dec = decryptFieldBytes(state.encryptedBuffers[record.index]);
        return toHex(dec.slice(0, 16)) + (dec.length > 16 ? '...' : '');
      };
    }

    state.virtualTable.setColumns(columns);
    state.virtualTable.render();
  }
}

function clearBufferDisplay() {
  state.buffers = [];
  state.encryptedBuffers = [];
  state.showEncrypted = true;

  if (state.virtualTable) {
    state.virtualTable.destroy();
    state.virtualTable = null;
  }

  $('data-card').style.display = 'none';
  $('stats-bar').style.display = 'none';
  $('toggle-encryption').disabled = true;
  $('clear-buffers').disabled = true;
  $('visible-range').textContent = '';
}

// =============================================================================
// PKI Demo (Alice/Bob Public Key Encryption)
// =============================================================================

const PKI_STORAGE_KEY = 'flatbuffers-pki-keys';

/**
 * Save PKI keys to localStorage (encrypted keys stored as hex)
 */
function savePKIKeys() {
  if (!state.pki.alice || !state.pki.bob) {
    console.warn('Cannot save PKI keys: alice or bob is null');
    return;
  }

  const data = {
    algorithm: state.pki.algorithm,
    alice: {
      publicKey: toHexCompact(state.pki.alice.publicKey),
      privateKey: toHexCompact(state.pki.alice.privateKey),
    },
    bob: {
      publicKey: toHexCompact(state.pki.bob.publicKey),
      privateKey: toHexCompact(state.pki.bob.privateKey),
    },
    savedAt: new Date().toISOString(),
  };

  try {
    localStorage.setItem(PKI_STORAGE_KEY, JSON.stringify(data));
    console.log('Saved PKI keys to localStorage:', data.algorithm);
  } catch (e) {
    console.warn('Failed to save PKI keys to localStorage:', e);
  }
}

/**
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Load PKI keys from localStorage
 * @returns {boolean} true if keys were loaded successfully
 */
function loadPKIKeys() {
  try {
    const stored = localStorage.getItem(PKI_STORAGE_KEY);
    if (!stored) {
      console.log('No PKI keys found in localStorage');
      return false;
    }

    const data = JSON.parse(stored);
    if (!data.alice || !data.bob || !data.algorithm) {
      console.warn('Invalid PKI data in localStorage');
      return false;
    }

    // Restore keys from hex
    state.pki.algorithm = data.algorithm;
    state.pki.alice = {
      publicKey: hexToBytes(data.alice.publicKey),
      privateKey: hexToBytes(data.alice.privateKey),
    };
    state.pki.bob = {
      publicKey: hexToBytes(data.bob.publicKey),
      privateKey: hexToBytes(data.bob.privateKey),
    };

    // Update UI elements (with null checks)
    const pkiAlgorithm = $('pki-algorithm');
    const alicePublicKey = $('alice-public-key');
    const alicePrivateKey = $('alice-private-key');
    const bobPublicKey = $('bob-public-key');
    const bobPrivateKey = $('bob-private-key');
    const pkiParties = $('pki-parties');
    const pkiDemo = $('pki-demo');
    const pkiSecurity = $('pki-security');
    const pkiClearKeys = $('pki-clear-keys');

    if (pkiAlgorithm) pkiAlgorithm.value = data.algorithm;
    if (alicePublicKey) alicePublicKey.textContent = data.alice.publicKey;
    if (alicePrivateKey) alicePrivateKey.textContent = data.alice.privateKey;
    if (bobPublicKey) bobPublicKey.textContent = data.bob.publicKey;
    if (bobPrivateKey) bobPrivateKey.textContent = data.bob.privateKey;

    // Show UI sections
    if (pkiParties) pkiParties.style.display = 'grid';
    if (pkiDemo) pkiDemo.style.display = 'block';
    if (pkiSecurity) pkiSecurity.style.display = 'block';
    if (pkiClearKeys) pkiClearKeys.style.display = 'inline-flex';

    console.log('Loaded PKI keys:', data.algorithm, 'Alice:', data.alice.publicKey.slice(0, 16) + '...');
    return true;
  } catch (e) {
    console.warn('Failed to load PKI keys from localStorage:', e);
    return false;
  }
}

/**
 * Clear saved PKI keys from localStorage and reset UI
 */
function clearPKIKeys() {
  try {
    localStorage.removeItem(PKI_STORAGE_KEY);
  } catch (e) {
    console.warn('Failed to clear PKI keys from localStorage:', e);
  }

  // Reset state
  state.pki.alice = null;
  state.pki.bob = null;
  state.pki.algorithm = 'x25519';
  state.pki.plaintext = null;
  state.pki.ciphertext = null;
  state.pki.header = null;
  state.pki.decrypted = null;

  // Reset UI
  $('pki-algorithm').value = 'x25519';
  $('alice-public-key').textContent = '--';
  $('alice-private-key').textContent = '--';
  $('bob-public-key').textContent = '--';
  $('bob-private-key').textContent = '--';
  $('pki-parties').style.display = 'none';
  $('pki-demo').style.display = 'none';
  $('pki-security').style.display = 'none';
  $('pki-clear-keys').style.display = 'none';
  $('pki-plaintext').value = '';
  $('pki-ciphertext-step').style.display = 'none';
  $('pki-decrypt-step').style.display = 'none';
  $('pki-result-step').style.display = 'none';
  $('pki-wrong-result').style.display = 'none';
}

function generatePKIKeyPairs() {
  const algorithm = $('pki-algorithm').value;
  state.pki.algorithm = algorithm;

  // Generate key pairs for Alice and Bob
  let generateFn;
  switch (algorithm) {
    case 'x25519':
      generateFn = x25519GenerateKeyPair;
      break;
    case 'secp256k1':
      generateFn = secp256k1GenerateKeyPair;
      break;
    case 'p256':
      generateFn = p256GenerateKeyPair;
      break;
    default:
      generateFn = x25519GenerateKeyPair;
  }

  try {
    state.pki.alice = generateFn();
    state.pki.bob = generateFn();
    console.log('Generated PKI keys:', {
      alicePub: state.pki.alice?.publicKey?.length,
      alicePriv: state.pki.alice?.privateKey?.length,
      bobPub: state.pki.bob?.publicKey?.length,
      bobPriv: state.pki.bob?.privateKey?.length,
    });
  } catch (e) {
    console.error('Failed to generate PKI keys:', e);
    alert('Failed to generate keys: ' + e.message);
    return;
  }

  // Save keys to localStorage
  savePKIKeys();

  // Display keys
  $('alice-public-key').textContent = toHexCompact(state.pki.alice.publicKey);
  $('alice-private-key').textContent = toHexCompact(state.pki.alice.privateKey);
  $('bob-public-key').textContent = toHexCompact(state.pki.bob.publicKey);
  $('bob-private-key').textContent = toHexCompact(state.pki.bob.privateKey);

  // Show UI sections
  $('pki-parties').style.display = 'grid';
  $('pki-demo').style.display = 'block';
  $('pki-security').style.display = 'block';
  $('pki-clear-keys').style.display = 'inline-flex';

  // Reset encryption state
  resetPKIDemo();
}

function resetPKIDemo() {
  state.pki.plaintext = null;
  state.pki.ciphertext = null;
  state.pki.header = null;
  state.pki.decrypted = null;

  $('pki-plaintext').value = '';
  $('pki-ciphertext-step').style.display = 'none';
  $('pki-decrypt-step').style.display = 'none';
  $('pki-result-step').style.display = 'none';
  $('pki-wrong-result').style.display = 'none';
}

function pkiEncrypt() {
  const plaintext = $('pki-plaintext').value;
  if (!plaintext.trim()) {
    alert('Please enter a message to encrypt');
    return;
  }

  if (!state.pki.bob) {
    alert('Please generate key pairs first');
    return;
  }

  // Convert plaintext to bytes
  const encoder = new TextEncoder();
  state.pki.plaintext = encoder.encode(plaintext);

  // Create encryption context using Bob's public key (Alice encrypts FOR Bob)
  const encryptCtx = EncryptionContext.forEncryption(state.pki.bob.publicKey, {
    algorithm: state.pki.algorithm,
    context: 'flatbuffers-pki-demo-v1',
  });

  // Encrypt the data
  const ciphertext = new Uint8Array(state.pki.plaintext);
  encryptBytes(ciphertext, encryptCtx.key, encryptCtx.nonce);
  state.pki.ciphertext = ciphertext;

  // Get the header (contains ephemeral public key, etc.)
  state.pki.header = encryptCtx.getHeaderJSON();

  // Display results
  $('pki-ciphertext').textContent = toHexCompact(ciphertext);
  $('pki-header').textContent = JSON.stringify(state.pki.header, null, 2);

  // Show next steps
  $('pki-ciphertext-step').style.display = 'flex';
  $('pki-decrypt-step').style.display = 'flex';
  $('pki-result-step').style.display = 'none';
  $('pki-wrong-result').style.display = 'none';
}

function pkiDecrypt() {
  if (!state.pki.ciphertext || !state.pki.header) {
    alert('Please encrypt a message first');
    return;
  }

  if (!state.pki.bob) {
    alert('Key pairs not available');
    return;
  }

  try {
    // Parse the header
    const header = encryptionHeaderFromJSON(state.pki.header);

    // Create decryption context using Bob's private key
    const decryptCtx = EncryptionContext.forDecryption(
      state.pki.bob.privateKey,
      header,
      'flatbuffers-pki-demo-v1'
    );

    // Decrypt the data
    const decrypted = new Uint8Array(state.pki.ciphertext);
    decryptBytes(decrypted, decryptCtx.key, decryptCtx.nonce);
    state.pki.decrypted = decrypted;

    // Convert back to string
    const decoder = new TextDecoder();
    const decryptedText = decoder.decode(decrypted);

    // Display result
    $('pki-decrypted').textContent = decryptedText;
    $('pki-result-step').style.display = 'flex';
    $('pki-verification').style.display = 'flex';

  } catch (error) {
    console.error('Decryption failed:', error);
    alert('Decryption failed: ' + error.message);
  }
}

function pkiTryWrongKey() {
  if (!state.pki.ciphertext || !state.pki.header) {
    alert('Please encrypt a message first');
    return;
  }

  if (!state.pki.alice) {
    alert('Key pairs not available');
    return;
  }

  try {
    // Parse the header
    const header = encryptionHeaderFromJSON(state.pki.header);

    // Try to decrypt with Alice's private key (WRONG - should fail)
    const decryptCtx = EncryptionContext.forDecryption(
      state.pki.alice.privateKey,
      header,
      'flatbuffers-pki-demo-v1'
    );

    // Attempt decryption
    const attemptedDecrypt = new Uint8Array(state.pki.ciphertext);
    decryptBytes(attemptedDecrypt, decryptCtx.key, decryptCtx.nonce);

    // Check if it matches original (it shouldn't)
    const decoder = new TextDecoder();
    const result = decoder.decode(attemptedDecrypt);
    const original = decoder.decode(state.pki.plaintext);

    if (result === original) {
      // This should never happen!
      alert('WARNING: Decryption succeeded with wrong key - this is a bug!');
    } else {
      // Expected: decryption produces garbage
      $('pki-wrong-result').style.display = 'flex';
    }

  } catch (error) {
    // Expected: decryption might throw an error
    $('pki-wrong-result').style.display = 'flex';
  }
}

// =============================================================================
// Streaming Demo
// =============================================================================

function setupStreamingDemo() {
  // Create a mock WASM module that actually tracks statistics
  // In production, this would use the actual streaming-dispatcher WASM
  const typeRegistry = new Map(); // typeIndex -> { fileId, count, totalReceived, capacity, messageSize }
  let nextTypeIndex = 0;
  const heapMemory = new Uint8Array(4 * 1024 * 1024); // 4MB heap

  const mockWasm = {
    _dispatcher_init: () => {},
    _dispatcher_reset: () => {
      for (const info of typeRegistry.values()) {
        info.count = 0;
        info.totalReceived = 0;
      }
    },
    _dispatcher_register_type: (fileIdPtr, bufferPtr, bufferSize, messageSize) => {
      const fileId = new TextDecoder().decode(heapMemory.slice(fileIdPtr, fileIdPtr + 4));
      const typeIndex = nextTypeIndex++;
      const capacity = Math.floor(bufferSize / messageSize);
      typeRegistry.set(typeIndex, {
        fileId,
        count: 0,
        totalReceived: 0,
        capacity,
        messageSize,
        bufferPtr,
      });
      return typeIndex;
    },
    _dispatcher_push_bytes: (ptr, size) => {
      // Parse size-prefixed messages from the buffer
      let offset = 0;
      let messagesProcessed = 0;

      while (offset + 4 <= size) {
        // Read message size (little-endian)
        const msgSize = heapMemory[ptr + offset] |
                       (heapMemory[ptr + offset + 1] << 8) |
                       (heapMemory[ptr + offset + 2] << 16) |
                       (heapMemory[ptr + offset + 3] << 24);

        if (offset + 4 + msgSize > size) break; // Incomplete message

        // Read file ID (4 bytes after size)
        const fileId = new TextDecoder().decode(heapMemory.slice(ptr + offset + 4, ptr + offset + 8));

        // Find matching type and increment counters
        for (const [, info] of typeRegistry.entries()) {
          if (info.fileId === fileId) {
            info.totalReceived++;
            info.count = Math.min(info.count + 1, info.capacity);
            break;
          }
        }

        offset += 4 + msgSize;
        messagesProcessed++;
      }

      return messagesProcessed;
    },
    _dispatcher_get_message_count: (typeIndex) => {
      const info = typeRegistry.get(typeIndex);
      return info ? info.count : 0;
    },
    _dispatcher_get_total_received: (typeIndex) => {
      const info = typeRegistry.get(typeIndex);
      return info ? info.totalReceived : 0;
    },
    _dispatcher_clear_messages: (typeIndex) => {
      const info = typeRegistry.get(typeIndex);
      if (info) {
        info.count = 0;
        info.totalReceived = 0;
      }
    },
    _malloc: (size) => {
      // Simple bump allocator - find first free spot
      // For demo purposes, just return incrementing addresses
      const addr = mockWasm._nextAlloc || 1024;
      mockWasm._nextAlloc = addr + size + 16; // 16-byte align
      return addr;
    },
    _free: () => {},
    HEAPU8: heapMemory,
  };

  state.streamingDemo = new StreamingDemo(mockWasm);
}

async function startStreaming() {
  const counts = {
    MONS: parseInt($('stream-monster-count').value) || 0,
    WEAP: parseInt($('stream-weapon-count').value) || 0,
    GALX: parseInt($('stream-galaxy-count').value) || 0,
  };
  const batchSize = parseInt($('stream-batch-size').value) || 100;
  const delayMs = parseInt($('stream-delay').value) || 10;

  const totalMessages = counts.MONS + counts.WEAP + counts.GALX;
  if (totalMessages === 0) {
    alert('Please enter at least one message count');
    return;
  }

  // Initialize streaming demo with capacities
  state.streamingDemo.init(counts);

  // Update UI
  $('start-streaming').disabled = true;
  $('stop-streaming').disabled = false;
  $('stream-progress').style.display = 'block';
  $('completion-stats').style.display = 'none';

  // Set ring buffer capacities in UI
  for (const [fileId, count] of Object.entries(counts)) {
    $(`ring-capacity-${fileId}`).textContent = count;
  }

  // Set callbacks
  state.streamingDemo.onStatsUpdate = (stats) => {
    const pct = (stats.processed / stats.total) * 100;
    $('stream-progress-fill').style.width = `${pct}%`;
    $('stream-processed').textContent = stats.processed.toLocaleString();
    $('stream-total').textContent = stats.total.toLocaleString();
    $('stream-bytes').textContent = formatBytes(stats.bytes);

    // Update ring buffer stats
    for (const [fileId, typeStats] of Object.entries(stats.stats)) {
      const count = typeStats.totalReceived || 0;
      const capacity = typeStats.capacity || 1;
      const pctFull = Math.min(100, (count / capacity) * 100);

      $(`ring-fill-${fileId}`).style.width = `${pctFull}%`;
      $(`ring-count-${fileId}`).textContent = Math.min(count, capacity);
      $(`ring-total-${fileId}`).textContent = count.toLocaleString();
    }
  };

  state.streamingDemo.onStreamComplete = (result) => {
    $('start-streaming').disabled = false;
    $('stop-streaming').disabled = true;

    $('completion-stats').style.display = 'block';
    $('complete-messages').textContent = result.totalMessages.toLocaleString();
    $('complete-bytes').textContent = formatBytes(result.totalBytes);
    $('complete-time').textContent = `${result.elapsed.toFixed(0)} ms`;
    $('complete-throughput').textContent = formatThroughput(result.throughput);
  };

  state.streamingDemo.onError = (err) => {
    console.error('Streaming error:', err);
    $('start-streaming').disabled = false;
    $('stop-streaming').disabled = true;
  };

  // Start streaming
  try {
    await state.streamingDemo.startStreaming({
      counts,
      batchSize,
      delayMs,
      shuffle: true,
    });
  } catch (err) {
    console.error('Streaming failed:', err);
    $('start-streaming').disabled = false;
    $('stop-streaming').disabled = true;
  }
}

function stopStreaming() {
  if (state.streamingDemo) {
    state.streamingDemo.stopStreaming();
  }
  $('start-streaming').disabled = false;
  $('stop-streaming').disabled = true;
}

function clearStreaming() {
  if (state.streamingDemo) {
    state.streamingDemo.clearAll();
  }

  $('stream-progress').style.display = 'none';
  $('completion-stats').style.display = 'none';
  $('stream-progress-fill').style.width = '0%';

  for (const fileId of Object.keys(MessageTypes)) {
    $(`ring-fill-${fileId}`).style.width = '0%';
    $(`ring-count-${fileId}`).textContent = '0';
    $(`ring-total-${fileId}`).textContent = '0';
  }
}

// =============================================================================
// vCard Generation
// =============================================================================

function generateVCard(info) {
  const person = {};

  if (info.name) {
    const parts = info.name.split(' ');
    if (parts.length > 1) {
      person.FAMILY_NAME = parts.pop();
      person.GIVEN_NAME = parts.join(' ');
    } else {
      person.GIVEN_NAME = info.name;
    }
  }

  if (info.email) {
    person.CONTACT_POINT = [{ EMAIL: info.email }];
  }

  if (info.org) {
    person.AFFILIATION = { LEGAL_NAME: info.org };
  }

  if (info.title) {
    person.HAS_OCCUPATION = { NAME: info.title };
  }

  if (info.includeKeys && state.wallet.x25519) {
    person.KEY = [
      {
        KEY_TYPE: 'X25519',
        PUBLIC_KEY: toBase64(state.wallet.x25519.publicKey),
      },
      {
        KEY_TYPE: 'Ed25519',
        PUBLIC_KEY: toBase64(state.wallet.ed25519.publicKey),
      },
      {
        KEY_TYPE: 'secp256k1',
        PUBLIC_KEY: toBase64(state.wallet.secp256k1.publicKey),
        CRYPTO_ADDRESS: state.addresses.btc || undefined,
      },
    ];
  }

  const note = info.includeKeys
    ? 'Generated by DA FlatBuffers Encryption Demo'
    : undefined;

  return createV3(person, note);
}

// =============================================================================
// Help Content
// =============================================================================

const helpContent = {
  entropy: {
    title: 'Password Entropy',
    body: `
      <p><strong>Entropy</strong> measures the randomness of your password in bits. Higher entropy means a more secure password.</p>
      <p>The calculation considers:</p>
      <ul style="margin: 12px 0 12px 20px;">
        <li>Password length</li>
        <li>Character variety (lowercase, uppercase, numbers, symbols)</li>
      </ul>
      <p><strong>Recommended minimums:</strong></p>
      <ul style="margin: 12px 0 12px 20px;">
        <li><code>60 bits</code> - Good for most purposes</li>
        <li><code>80 bits</code> - High security</li>
        <li><code>128 bits</code> - Very high security (cryptographic strength)</li>
      </ul>
      <p>A 24-character password with mixed characters typically provides 128+ bits of entropy, which is why we require a minimum of 24 characters.</p>
    `,
  },
};

// =============================================================================
// UI Event Handlers
// =============================================================================

function setupLoginHandlers() {
  document.querySelectorAll('.method-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.method-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.method-content').forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      $(`${tab.dataset.method}-method`).classList.add('active');
    });
  });

  $('wallet-password').addEventListener('input', (e) => {
    updatePasswordStrength(e.target.value);
  });

  $('wallet-username').addEventListener('input', () => {
    updatePasswordStrength($('wallet-password').value);
  });

  $('derive-from-password').addEventListener('click', async () => {
    const username = $('wallet-username').value;
    const password = $('wallet-password').value;
    if (!username || password.length < 24) return;

    const btn = $('derive-from-password');
    btn.disabled = true;
    btn.textContent = 'Logging in...';

    try {
      const keys = await deriveKeysFromPassword(username, password);
      login(keys);
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Login / Create Wallet';
    }
  });

  $('generate-seed').addEventListener('click', () => {
    $('seed-phrase').value = generateSeedPhrase();
    $('derive-from-seed').disabled = false;
  });

  $('validate-seed').addEventListener('click', () => {
    const valid = validateSeedPhrase($('seed-phrase').value);
    if (valid) {
      alert('Valid BIP39 seed phrase!');
      $('derive-from-seed').disabled = false;
    } else {
      alert('Invalid seed phrase');
      $('derive-from-seed').disabled = true;
    }
  });

  $('seed-phrase').addEventListener('input', () => {
    const phrase = $('seed-phrase').value.trim();
    if (phrase.split(/\s+/).length >= 12) {
      $('derive-from-seed').disabled = !validateSeedPhrase(phrase);
    } else {
      $('derive-from-seed').disabled = true;
    }
  });

  $('derive-from-seed').addEventListener('click', async () => {
    const phrase = $('seed-phrase').value;
    if (!validateSeedPhrase(phrase)) return;

    const btn = $('derive-from-seed');
    btn.disabled = true;
    btn.textContent = 'Logging in...';

    try {
      const keys = await deriveKeysFromSeed(phrase);
      login(keys);
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Login with Seed Phrase';
    }
  });
}

function setupMainAppHandlers() {
  // Nav actions
  $('nav-logout').addEventListener('click', logout);
  $('nav-keys').addEventListener('click', () => {
    $('keys-modal').classList.add('active');
  });

  // Modal close handlers
  document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
      if (e.target === modal || e.target.classList.contains('modal-close')) {
        modal.classList.remove('active');
      }
    });
  });

  // Navigation tabs (now links) - only for links with data-tab
  document.querySelectorAll('.nav-link[data-tab]').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      document.querySelectorAll('.nav-link[data-tab]').forEach(l => l.classList.remove('active'));
      document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
      link.classList.add('active');
      const tabEl = $(`${link.dataset.tab}-tab`);
      if (tabEl) {
        tabEl.classList.add('active');
        // Scroll to the main app content area, hiding the hero section
        const mainApp = $('main-app');
        if (mainApp) {
          mainApp.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      }
    });
  });

  // HD Wallet Derivation handlers
  const hdPurpose = $('hd-purpose');
  const hdCoin = $('hd-coin');
  const hdAccount = $('hd-account');
  const hdChange = $('hd-change');
  const hdIndex = $('hd-index');
  const deriveBtn = $('derive-address');

  // Update path display on any change
  [hdPurpose, hdCoin, hdAccount, hdChange, hdIndex].forEach(el => {
    if (el) el.addEventListener('change', updatePathDisplay);
    if (el) el.addEventListener('input', updatePathDisplay);
  });

  // Derive button
  if (deriveBtn) {
    deriveBtn.addEventListener('click', deriveAndDisplayAddress);
  }

  // Quick derive buttons
  document.querySelectorAll('.quick-derive .glass-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const coin = btn.dataset.coin;
      const purpose = btn.dataset.purpose;
      if (coin !== undefined && purpose !== undefined) {
        quickDerive(coin, purpose);
      }
    });
  });

  // Field Encryption Tab
  $('generate-single').addEventListener('click', generateSingleRecord);
  $('toggle-field-decrypt').addEventListener('click', toggleFieldDecrypt);

  // Bulk Generation Tab
  $('generate-buffers').addEventListener('click', generateBulkBuffers);
  $('toggle-encryption').addEventListener('click', toggleEncryption);
  $('clear-buffers').addEventListener('click', clearBufferDisplay);

  // PKI Tab
  $('pki-generate-keys').addEventListener('click', generatePKIKeyPairs);
  $('pki-clear-keys').addEventListener('click', clearPKIKeys);
  $('pki-encrypt').addEventListener('click', pkiEncrypt);
  $('pki-decrypt').addEventListener('click', pkiDecrypt);
  $('pki-wrong-key').addEventListener('click', pkiTryWrongKey);

  // Streaming Tab
  $('start-streaming').addEventListener('click', startStreaming);
  $('stop-streaming').addEventListener('click', stopStreaming);
  $('clear-streaming').addEventListener('click', clearStreaming);

  // vCard
  $('generate-vcard').addEventListener('click', async () => {
    const info = {
      name: $('vcard-name').value,
      email: $('vcard-email').value,
      org: $('vcard-org').value,
      title: $('vcard-title').value,
      includeKeys: $('include-keys').checked,
    };

    if (!info.name) {
      alert('Please enter a name');
      return;
    }

    const vcard = generateVCard(info);
    $('vcard-preview').textContent = vcard;

    try {
      await QRCode.toCanvas($('qr-code'), vcard, {
        width: 256,
        margin: 2,
        color: { dark: '#1e293b', light: '#ffffff' },
      });
      $('vcard-result').style.display = 'block';
    } catch (err) {
      alert('Error generating QR code: ' + err.message);
    }
  });

  $('download-vcard').addEventListener('click', () => {
    const vcard = $('vcard-preview').textContent;
    const blob = new Blob([vcard], { type: 'text/vcard' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'contact.vcf';
    a.click();
    URL.revokeObjectURL(url);
  });

  $('copy-vcard').addEventListener('click', async () => {
    const vcard = $('vcard-preview').textContent;
    try {
      await navigator.clipboard.writeText(vcard);
      const btn = $('copy-vcard');
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = 'Copy vCard'; }, 2000);
    } catch (err) {
      alert('Failed to copy: ' + err.message);
    }
  });
}

function setupHelpModals() {
  document.querySelectorAll('.help-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const helpKey = btn.dataset.help;
      const content = helpContent[helpKey];
      if (content) {
        $('help-title').textContent = content.title;
        $('help-body').innerHTML = content.body;
        $('help-modal').classList.add('active');
      }
    });
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal.active').forEach(m => m.classList.remove('active'));
    }
  });
}

// =============================================================================
// HLS Video Background
// =============================================================================

function initVideoBackground() {
  const video = $('bg-video');
  if (!video) return;

  const videoSrc = video.querySelector('source')?.src;
  if (!videoSrc) return;

  // Check if HLS.js is available and needed
  if (videoSrc.includes('.m3u8')) {
    if (window.Hls && Hls.isSupported()) {
      const hls = new Hls({
        enableWorker: true,
        lowLatencyMode: false,
        backBufferLength: 90,
      });
      hls.loadSource(videoSrc);
      hls.attachMedia(video);
      hls.on(Hls.Events.MANIFEST_PARSED, () => {
        video.play().catch(() => {}); // Ignore autoplay errors
      });
    } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
      // Native HLS support (Safari)
      video.src = videoSrc;
      video.addEventListener('loadedmetadata', () => {
        video.play().catch(() => {});
      });
    }
  }
}

// =============================================================================
// Initialization
// =============================================================================

async function init() {
  const status = $('status');
  const loadingOverlay = $('loading-overlay');

  // Initialize video background immediately
  initVideoBackground();

  try {
    // Load encryption WASM
    status.textContent = 'Loading encryption module...';
    await loadEncryptionWasm(ENCRYPTION_WASM_PATH);

    // Initialize FlatcRunner
    status.textContent = 'Loading FlatBuffers compiler...';
    state.flatcRunner = await FlatcRunner.init();

    // Setup streaming demo
    setupStreamingDemo();

    // Load saved PKI keys if available
    if (loadPKIKeys()) {
      console.log('Loaded PKI keys from localStorage');
    }

    state.initialized = true;

    // Update nav status
    const navStatus = $('nav-status');
    if (navStatus) {
      navStatus.textContent = 'Ready';
      navStatus.className = 'nav-status ready';
    }

    // Hide loading overlay with fade
    loadingOverlay.classList.add('hidden');
    setTimeout(() => {
      loadingOverlay.style.display = 'none';
    }, 500);

    setupLoginHandlers();
    setupMainAppHandlers();
    setupHelpModals();

  } catch (err) {
    console.error('Init failed:', err);
    status.textContent = `Failed to load: ${err.message}`;

    // Show error state in loading overlay
    loadingOverlay.classList.add('error');
  }
}

init();
