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
import { x25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { p256 } from '@noble/curves/p256';
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
  EncryptionContext,
  encryptionHeaderFromJSON,
  encryptBuffer,
  decryptBuffer,
} from '../../src/encryption.mjs';

import { FlatcRunner } from '../../src/runner.mjs';
import { FlatBufferParser, parseWithSchema, Schemas, toHex, toHexCompact } from './flatbuffer-parser.mjs';
import { PaginatedTable } from './virtual-scroller.mjs';
import { StreamingDemo, MessageTypes, formatBytes, formatThroughput } from './streaming-demo.mjs';
import { Builder } from 'flatbuffers';

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
  encryptionHeaders: [], // ECIES headers for each encrypted buffer
  showEncrypted: true,
  encryptionKey: null,
  encryptionIV: null,
  encryptionEnabled: true, // Toggle for encrypted vs plain FlatBuffers
  // Field display state
  currentFieldData: null,
  showFieldDecrypted: false,
  // Virtual table / Paginated table
  virtualTable: null,
  paginatedTable: null,
  selectedRecord: null, // Currently selected record for detail view
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

  // Hide login card, show hero stats and scroll indicator
  $('login-card').style.display = 'none';
  $('hero-stats').style.display = 'flex';
  $('scroll-indicator').style.display = 'flex';

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

  // Always derive PKI keys from HD wallet if available
  // This ensures Alice/Bob keys are deterministically derived from the user's seed
  if (state.hdRoot) {
    generatePKIKeyPairs(); // This will use derivePKIKeysFromHD internally
  } else if (state.pki.alice && state.pki.bob) {
    // Just update the UI since keys are already in state
    // Just update the UI since keys are already in state
    $('alice-public-key').textContent = toHexCompact(state.pki.alice.publicKey);
    $('alice-private-key').textContent = toHexCompact(state.pki.alice.privateKey);
    $('bob-public-key').textContent = toHexCompact(state.pki.bob.publicKey);
    $('bob-private-key').textContent = toHexCompact(state.pki.bob.privateKey);
    // Display algorithm
    const algorithmNames = {
      x25519: 'X25519 (Curve25519)',
      secp256k1: 'secp256k1 (Bitcoin)',
      p256: 'P-256 (NIST)',
    };
    $('pki-algorithm-display').textContent = algorithmNames[state.pki.algorithm] || state.pki.algorithm;
    $('pki-controls').style.display = 'flex';
    $('pki-parties').style.display = 'grid';
    $('encryption-explainer').style.display = 'block';
    $('pki-demo').style.display = 'block';
    $('pki-security').style.display = 'block';
    $('pki-clear-keys').style.display = 'inline-flex';
  } else if (!loadPKIKeys()) {
    generatePKIKeyPairs();
  }

  // Initialize schema viewer
  updateSchemaViewer();
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
  localStorage.clear();
  // Hide main app content
  $('main-app').style.display = 'none';

  // Hide hero stats and scroll indicator, show login card
  $('hero-stats').style.display = 'none';
  $('scroll-indicator').style.display = 'none';
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

  // Reset to first tab (Overview) and scroll to top
  document.querySelectorAll('.nav-link[data-tab]').forEach(l => l.classList.remove('active'));
  const firstLink = document.querySelector('.nav-link[data-tab="overview"]');
  if (firstLink) firstLink.classList.add('active');
  const mainApp = $('main-app');
  if (mainApp) mainApp.scrollTop = 0;
}

// =============================================================================
// FlatBuffer Builder Functions (Direct API - bypasses CLI for performance)
// =============================================================================

/**
 * Build a Monster FlatBuffer using the Builder API directly.
 * This is ~100x faster than the CLI-based approach.
 */
function buildMonster(data) {
  const builder = new Builder(256);

  // Create strings/vectors BEFORE starting table (FlatBuffers requirement)
  const nameOffset = builder.createString(data.name);

  let inventoryOffset = 0;
  if (data.inventory?.length > 0) {
    builder.startVector(1, data.inventory.length, 1);
    for (let i = data.inventory.length - 1; i >= 0; i--) {
      builder.addInt8(data.inventory[i]);
    }
    inventoryOffset = builder.endVector();
  }

  // Monster table: 10 fields (pos, mana, hp, name, friendly, inventory, color, weapons, equipped, path)
  builder.startObject(10);

  // Field 0: pos (Vec3 struct - 12 bytes inline: x, y, z floats)
  if (data.pos) {
    builder.prep(4, 12);
    builder.writeFloat32(data.pos.z);
    builder.writeFloat32(data.pos.y);
    builder.writeFloat32(data.pos.x);
    builder.addFieldStruct(0, builder.offset(), 0);
  }

  // Field 1: mana (short, default 150)
  builder.addFieldInt16(1, data.mana, 150);

  // Field 2: hp (short, default 100)
  builder.addFieldInt16(2, data.hp, 100);

  // Field 3: name (string offset)
  builder.addFieldOffset(3, nameOffset, 0);

  // Field 5: inventory (vector offset) - field 4 is deprecated 'friendly'
  if (inventoryOffset) builder.addFieldOffset(5, inventoryOffset, 0);

  // Field 6: color (byte enum, default 2=Blue)
  builder.addFieldInt8(6, data.color, 2);

  const monster = builder.endObject();
  builder.finish(monster, 'MONS');
  return builder.asUint8Array();
}

/**
 * Build a Weapon FlatBuffer using the Builder API directly.
 */
function buildWeapon(data) {
  const builder = new Builder(64);
  const nameOffset = builder.createString(data.name);

  // Weapon table: 2 fields (name, damage)
  builder.startObject(2);
  builder.addFieldOffset(0, nameOffset, 0);
  builder.addFieldInt16(1, data.damage, 0);

  const weapon = builder.endObject();
  builder.finish(weapon, 'WEAP');
  return builder.asUint8Array();
}

/**
 * Build a Galaxy FlatBuffer using the Builder API directly.
 */
function buildGalaxy(data) {
  const builder = new Builder(32);

  // Galaxy table: 1 field (num_stars as int64)
  builder.startObject(1);
  builder.addFieldInt64(0, data.num_stars, BigInt(0));

  const galaxy = builder.endObject();
  builder.finish(galaxy, 'GALX');
  return builder.asUint8Array();
}

/**
 * Build a FlatBuffer using the direct Builder API (fast path).
 * Use this instead of generateFlatBuffer for bulk operations.
 */
function buildFlatBuffer(schemaType, data) {
  switch (schemaType) {
    case 'monster': return buildMonster(data);
    case 'weapon': return buildWeapon(data);
    case 'galaxy': return buildGalaxy(data);
    default: throw new Error(`Unknown schema for builder: ${schemaType}`);
  }
}

// =============================================================================
// FlatBuffer Generation (CLI-based - kept for JSON conversion tools)
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

/**
 * Encrypt field bytes using Bob's public key (ECIES)
 * Returns { encrypted, header } for later decryption
 */
function encryptFieldBytesWithPKI(bytes, fieldId = 0) {
  if (!state.pki.bob || !state.pki.bob.publicKey) {
    throw new Error('PKI keys not available');
  }

  // Ensure publicKey is a Uint8Array
  const publicKey = ensureUint8Array(state.pki.bob.publicKey);

  const encryptCtx = EncryptionContext.forEncryption(publicKey, {
    algorithm: state.pki.algorithm,
    context: 'flatbuffers-field-encryption-v1',
  });

  // Create a buffer copy and encrypt in-place using the context's method
  const encrypted = new Uint8Array(bytes);
  // Use encryptScalar which properly derives per-field keys from the context
  encryptCtx.encryptScalar(encrypted, 0, encrypted.length, fieldId);

  return {
    encrypted,
    header: encryptCtx.getHeaderJSON(),
  };
}

/**
 * Helper to ensure a value is a Uint8Array
 * Handles localStorage deserialization which produces plain objects
 */
function ensureUint8Array(value) {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (typeof value === 'object' && value !== null) {
    return new Uint8Array(Object.values(value));
  }
  return new Uint8Array(value);
}

/**
 * Decrypt field bytes using Bob's private key
 */
function decryptFieldBytesWithPKI(encrypted, headerJSON, fieldId = 0) {
  if (!state.pki.bob || !state.pki.bob.privateKey) {
    throw new Error('PKI keys not available');
  }

  const privateKey = ensureUint8Array(state.pki.bob.privateKey);

  const header = encryptionHeaderFromJSON(headerJSON);
  const decryptCtx = EncryptionContext.forDecryption(
    privateKey,
    header,
    'flatbuffers-field-encryption-v1'
  );

  // Create a buffer copy and decrypt in-place using the context's method
  // Note: encryptScalar/decryptScalar are the same for CTR mode (symmetric)
  const decrypted = new Uint8Array(encrypted);
  decryptCtx.encryptScalar(decrypted, 0, decrypted.length, fieldId);
  return decrypted;
}

// =============================================================================
// Field-Level Encryption Display
// =============================================================================

async function generateSingleRecord() {
  const schemaType = $('schema-select').value;
  const config = schemaConfig[schemaType];

  // Check if PKI keys are available
  if (!state.pki.bob || !state.pki.bob.publicKey) {
    alert('Please generate PKI key pairs first (in the PKI section above)');
    return;
  }

  try {
    const data = config.sampleData(0);
    const binary = await generateFlatBuffer(schemaType, data);

    const parser = new FlatBufferParser(binary);
    const parsed = parseWithSchema(parser, config.parserSchema.fields);

    // Encrypt each field using Bob's public key (ECIES)
    const encryptedFields = parsed.fields.map(field => {
      if (field.bytes && field.bytes.length > 0) {
        const { encrypted, header } = encryptFieldBytesWithPKI(field.bytes);
        return {
          ...field,
          encryptedBytes: encrypted,
          encryptionHeader: header,
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
    $('toggle-field-decrypt').textContent = 'Bob Decrypts';

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

    // Decrypted hex (decrypt-col) - decrypt using Bob's private key
    const decHexTd = document.createElement('td');
    decHexTd.className = 'hex decrypt-col';
    if (field.encryptedBytes && field.encryptionHeader && state.showFieldDecrypted) {
      try {
        const decrypted = decryptFieldBytesWithPKI(field.encryptedBytes, field.encryptionHeader);
        decHexTd.textContent = toHex(decrypted);
      } catch (e) {
        decHexTd.textContent = '(decrypt failed)';
        decHexTd.title = e.message;
      }
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
  $('toggle-field-decrypt').textContent = state.showFieldDecrypted ? 'Show Encrypted' : 'Bob Decrypts';
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
  const encrypt = state.encryptionEnabled;

  // Check if PKI keys are available when encryption is enabled
  if (encrypt && (!state.pki.bob || !state.pki.bob.publicKey)) {
    alert('Please generate PKI key pairs first (in the PKI section above)');
    return;
  }

  const btn = $('generate-buffers');
  const plainBtn = $('generate-plain');
  btn.disabled = true;
  if (plainBtn) plainBtn.disabled = true;
  btn.textContent = encrypt ? 'Encrypting...' : 'Generating...';

  const startTime = performance.now();

  try {
    // Clear previous data to free memory
    state.buffers = [];
    state.encryptedBuffers = [];
    state.encryptionHeaders = [];

    // === WARM ENCRYPTION CONTEXT: Create ONCE before the loop ===
    // This avoids 1000+ ECDH operations (~500ms overhead) by reusing one context
    let encryptCtx = null;
    let encryptionHeader = null;

    if (encrypt) {
      let publicKey = state.pki.bob.publicKey;
      if (!(publicKey instanceof Uint8Array)) {
        publicKey = new Uint8Array(
          typeof publicKey === 'object' && publicKey !== null
            ? Object.values(publicKey)
            : publicKey
        );
      }

      encryptCtx = EncryptionContext.forEncryption(publicKey, {
        algorithm: state.pki.algorithm,
        context: 'flatbuffers-bulk-encryption-v1',
      });
      encryptionHeader = encryptCtx.getHeaderJSON();
    }

    const batchSize = Math.min(100, count);
    let totalSize = 0;

    for (let i = 0; i < count; i += batchSize) {
      const batchEnd = Math.min(i + batchSize, count);

      for (let j = i; j < batchEnd; j++) {
        const data = config.sampleData(j);

        // Use Builder API directly (fast) instead of CLI-based generateFlatBuffer
        const binary = buildFlatBuffer(schemaType, data);

        if (encrypt) {
          // Use high-performance streaming encryption:
          // - Field keys are cached (HKDF only on first access)
          // - IVs computed via fast XOR (no HKDF per record)
          // This is ~100x faster than encryptScalar() for bulk operations
          const encrypted = new Uint8Array(binary);
          encryptCtx.encryptBuffer(encrypted, j);  // j is the record counter

          state.encryptedBuffers.push(encrypted);
          state.encryptionHeaders.push(encryptionHeader); // Same header for all records
        }

        state.buffers.push({
          index: j,
          data,
          binary: new Uint8Array(binary),
          size: binary.length,
        });
        totalSize += binary.length;
      }

      // Update progress and yield to UI
      const progress = Math.round((batchEnd / count) * 100);
      btn.textContent = encrypt ? `Encrypting... ${progress}%` : `Generating... ${progress}%`;
      await new Promise(r => setTimeout(r, 0));
    }

    const elapsed = performance.now() - startTime;

    // Update stats
    $('stat-count').textContent = count.toLocaleString();
    $('stat-size').textContent = formatSize(totalSize);
    $('stat-time').textContent = `${Math.round(elapsed)} ms`;
    $('stat-memory').textContent = formatSize(performance.memory?.usedJSHeapSize || 0);
    $('stats-bar').style.display = 'flex';

    // Enable/disable buttons based on encryption mode
    if (encrypt) {
      $('toggle-encryption').disabled = false;
      $('toggle-encryption').textContent = 'Bob Decrypts';
    } else {
      $('toggle-encryption').disabled = true;
      $('toggle-encryption').textContent = 'N/A (Plain)';
    }
    $('clear-buffers').disabled = false;
    state.showEncrypted = true;

    // Render paginated table
    renderBulkTable(schemaType);
    $('data-card').style.display = 'block';

  } catch (err) {
    console.error('Failed to generate buffers:', err);
    alert('Error generating buffers: ' + err.message);
  } finally {
    btn.disabled = false;
    if (plainBtn) plainBtn.disabled = false;
    btn.textContent = 'Encrypt for Bob';
  }
}

// =============================================================================
// Streaming Export/Import - Memory-efficient large dataset handling
// =============================================================================

/**
 * File format for encrypted FlatBuffers stream:
 * [4 bytes: magic "EFBS" (Encrypted FlatBuffers Stream)]
 * [4 bytes: version (1)]
 * [4 bytes: record count]
 * [4 bytes: schema type string length]
 * [N bytes: schema type string (e.g., "monster")]
 * [4 bytes: encryption header JSON length (0 if unencrypted)]
 * [N bytes: encryption header JSON]
 * [records...]
 *   [4 bytes: record length]
 *   [N bytes: FlatBuffer data (encrypted or plain)]
 */

const EFBS_MAGIC = 0x53424645; // "EFBS" in little-endian

/**
 * Generate FlatBuffers and download as a streaming file.
 * This avoids storing all records in memory - records are chunked and exported.
 */
async function generateAndDownload(encrypt) {
  const schemaType = $('bulk-schema').value;
  const count = parseInt($('buffer-count').value);
  const config = schemaConfig[schemaType];

  // Check if PKI keys are available when encryption is enabled
  if (encrypt && (!state.pki.bob || !state.pki.bob.publicKey)) {
    alert('Please generate PKI key pairs first (in the PKI section above)');
    return;
  }

  const btn = encrypt ? $('download-encrypted') : $('download-plain');
  const originalText = btn.textContent;
  btn.disabled = true;

  // Show progress bar
  const progressContainer = $('download-progress');
  const progressFill = $('download-progress-fill');
  const progressText = $('download-progress-text');
  progressContainer.style.display = 'block';
  progressFill.style.width = '0%';
  progressText.textContent = 'Preparing...';

  const startTime = performance.now();

  try {
    // Create encryption context once if needed
    let encryptCtx = null;
    let encryptionHeaderJson = '';

    if (encrypt) {
      let publicKey = state.pki.bob.publicKey;
      if (!(publicKey instanceof Uint8Array)) {
        publicKey = new Uint8Array(
          typeof publicKey === 'object' && publicKey !== null
            ? Object.values(publicKey)
            : publicKey
        );
      }

      encryptCtx = EncryptionContext.forEncryption(publicKey, {
        algorithm: state.pki.algorithm,
        context: 'flatbuffers-stream-v1',
      });
      encryptionHeaderJson = encryptCtx.getHeaderJSON();
    }

    // Build file header
    const schemaBytes = new TextEncoder().encode(schemaType);
    const headerJsonBytes = new TextEncoder().encode(encryptionHeaderJson);

    const fileHeaderSize = 4 + 4 + 4 + 4 + schemaBytes.length + 4 + headerJsonBytes.length;
    const fileHeader = new ArrayBuffer(fileHeaderSize);
    const headerView = new DataView(fileHeader);
    let offset = 0;

    // Magic
    headerView.setUint32(offset, EFBS_MAGIC, true);
    offset += 4;
    // Version
    headerView.setUint32(offset, 1, true);
    offset += 4;
    // Record count
    headerView.setUint32(offset, count, true);
    offset += 4;
    // Schema type length + data
    headerView.setUint32(offset, schemaBytes.length, true);
    offset += 4;
    new Uint8Array(fileHeader, offset, schemaBytes.length).set(schemaBytes);
    offset += schemaBytes.length;
    // Encryption header length + data
    headerView.setUint32(offset, headerJsonBytes.length, true);
    offset += 4;
    new Uint8Array(fileHeader, offset, headerJsonBytes.length).set(headerJsonBytes);

    // Collect chunks for final blob
    const chunks = [new Uint8Array(fileHeader)];
    let totalDataSize = fileHeaderSize;

    // Generate records in batches to avoid memory buildup
    const CHUNK_SIZE = 10000;

    for (let i = 0; i < count; i += CHUNK_SIZE) {
      const chunkEnd = Math.min(i + CHUNK_SIZE, count);
      const chunkRecords = [];

      for (let j = i; j < chunkEnd; j++) {
        const data = config.sampleData(j);
        let binary = buildFlatBuffer(schemaType, data);

        if (encrypt) {
          binary = new Uint8Array(binary);
          encryptCtx.encryptBuffer(binary, j);
        }

        // Length-prefix the record
        const recordWithLength = new Uint8Array(4 + binary.length);
        new DataView(recordWithLength.buffer).setUint32(0, binary.length, true);
        recordWithLength.set(binary, 4);

        chunkRecords.push(recordWithLength);
        totalDataSize += recordWithLength.length;
      }

      // Concatenate chunk records and add to chunks array
      const chunkData = concatUint8Arrays(chunkRecords);
      chunks.push(chunkData);

      // Update progress
      const progress = Math.round((chunkEnd / count) * 100);
      progressFill.style.width = `${progress}%`;
      progressText.textContent = `${encrypt ? 'Encrypting' : 'Generating'} ${chunkEnd.toLocaleString()} / ${count.toLocaleString()} records...`;
      btn.textContent = `${progress}%`;

      // Yield to UI
      await new Promise(r => setTimeout(r, 0));
    }

    const elapsed = performance.now() - startTime;
    const throughput = (totalDataSize / 1024 / 1024) / (elapsed / 1000);

    // Create and download blob
    const blob = new Blob(chunks, { type: 'application/octet-stream' });
    const filename = `flatbuffers-${schemaType}-${count}${encrypt ? '-encrypted' : ''}.efbs`;

    downloadBlob(blob, filename);

    // Update stats
    progressText.textContent = `Complete! ${count.toLocaleString()} records, ${formatSize(totalDataSize)}, ${Math.round(elapsed)}ms (${throughput.toFixed(1)} MB/s)`;

    // Show completion stats in the stats bar
    $('stat-count').textContent = count.toLocaleString();
    $('stat-size').textContent = formatSize(totalDataSize);
    $('stat-time').textContent = `${Math.round(elapsed)} ms`;
    $('stat-memory').textContent = `${throughput.toFixed(1)} MB/s`;
    $('stats-bar').style.display = 'flex';

  } catch (err) {
    console.error('Failed to generate/download:', err);
    progressText.textContent = `Error: ${err.message}`;
  } finally {
    btn.disabled = false;
    btn.textContent = originalText;
  }
}

/**
 * Upload and decrypt an .efbs file, showing stats.
 */
async function uploadAndDecrypt(file) {
  const progressContainer = $('upload-progress');
  const progressFill = $('upload-progress-fill');
  const progressText = $('upload-progress-text');
  progressContainer.style.display = 'block';
  progressFill.style.width = '0%';
  progressText.textContent = 'Reading file...';

  const startTime = performance.now();

  try {
    const buffer = await file.arrayBuffer();
    const view = new DataView(buffer);
    let offset = 0;

    // Validate magic
    const magic = view.getUint32(offset, true);
    offset += 4;
    if (magic !== EFBS_MAGIC) {
      throw new Error('Invalid file format (expected EFBS)');
    }

    // Read version
    const version = view.getUint32(offset, true);
    offset += 4;
    if (version !== 1) {
      throw new Error(`Unsupported file version: ${version}`);
    }

    // Read record count
    const recordCount = view.getUint32(offset, true);
    offset += 4;

    // Read schema type
    const schemaTypeLen = view.getUint32(offset, true);
    offset += 4;
    const schemaType = new TextDecoder().decode(new Uint8Array(buffer, offset, schemaTypeLen));
    offset += schemaTypeLen;

    // Read encryption header
    const encHeaderLen = view.getUint32(offset, true);
    offset += 4;
    const encHeaderJson = new TextDecoder().decode(new Uint8Array(buffer, offset, encHeaderLen));
    offset += encHeaderLen;

    const isEncrypted = encHeaderLen > 0;
    let decryptCtx = null;

    if (isEncrypted) {
      // Create decryption context
      if (!state.pki.bob || !state.pki.bob.privateKey) {
        throw new Error('Bob\'s private key not available for decryption');
      }

      let privateKey = state.pki.bob.privateKey;
      if (!(privateKey instanceof Uint8Array)) {
        privateKey = new Uint8Array(
          typeof privateKey === 'object' && privateKey !== null
            ? Object.values(privateKey)
            : privateKey
        );
      }

      const header = encryptionHeaderFromJSON(encHeaderJson);
      decryptCtx = EncryptionContext.forDecryption(privateKey, header, {
        context: 'flatbuffers-stream-v1',
      });
    }

    progressText.textContent = `Processing ${recordCount.toLocaleString()} ${schemaType} records...`;

    // Process records
    let decryptTime = 0;
    let recordsProcessed = 0;
    let sampleRecords = []; // Keep first 10 for display

    while (offset < buffer.byteLength && recordsProcessed < recordCount) {
      const recordLen = view.getUint32(offset, true);
      offset += 4;

      const recordData = new Uint8Array(buffer, offset, recordLen);
      offset += recordLen;

      if (isEncrypted && decryptCtx) {
        const decrypted = new Uint8Array(recordData);
        const t0 = performance.now();
        decryptCtx.decryptBuffer(decrypted, recordsProcessed);
        decryptTime += performance.now() - t0;

        // Store sample for display
        if (recordsProcessed < 10) {
          sampleRecords.push({
            index: recordsProcessed,
            binary: decrypted,
            size: recordLen,
          });
        }
      } else {
        if (recordsProcessed < 10) {
          sampleRecords.push({
            index: recordsProcessed,
            binary: new Uint8Array(recordData),
            size: recordLen,
          });
        }
      }

      recordsProcessed++;

      // Update progress periodically
      if (recordsProcessed % 10000 === 0) {
        const progress = Math.round((offset / buffer.byteLength) * 100);
        progressFill.style.width = `${progress}%`;
        progressText.textContent = `${isEncrypted ? 'Decrypting' : 'Processing'} ${recordsProcessed.toLocaleString()} / ${recordCount.toLocaleString()} records...`;
        await new Promise(r => setTimeout(r, 0));
      }
    }

    const elapsed = performance.now() - startTime;
    const throughput = (buffer.byteLength / 1024 / 1024) / (elapsed / 1000);

    // Display results
    progressFill.style.width = '100%';
    progressText.textContent = `Complete! ${recordsProcessed.toLocaleString()} records verified`;

    // Update stats bar
    $('stat-count').textContent = recordsProcessed.toLocaleString();
    $('stat-size').textContent = formatSize(buffer.byteLength);
    $('stat-time').textContent = `${Math.round(elapsed)} ms`;
    $('stat-memory').textContent = `${throughput.toFixed(1)} MB/s`;
    $('stats-bar').style.display = 'flex';

    // Show upload results
    const resultsContainer = $('upload-results');
    if (resultsContainer) {
      resultsContainer.innerHTML = `
        <div class="upload-stats">
          <div class="stat-item">
            <span class="stat-label">File</span>
            <span class="stat-value">${file.name}</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Schema</span>
            <span class="stat-value">${schemaType}</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Records</span>
            <span class="stat-value">${recordsProcessed.toLocaleString()}</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Encrypted</span>
            <span class="stat-value">${isEncrypted ? 'Yes' : 'No'}</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Total Time</span>
            <span class="stat-value">${Math.round(elapsed)} ms</span>
          </div>
          ${isEncrypted ? `
          <div class="stat-item">
            <span class="stat-label">Decrypt Time</span>
            <span class="stat-value">${Math.round(decryptTime)} ms</span>
          </div>
          ` : ''}
          <div class="stat-item">
            <span class="stat-label">Throughput</span>
            <span class="stat-value">${throughput.toFixed(1)} MB/s</span>
          </div>
        </div>
      `;
      resultsContainer.style.display = 'block';
    }

    // Parse and show sample records
    if (sampleRecords.length > 0) {
      state.buffers = sampleRecords.map((r, i) => {
        const config = schemaConfig[schemaType];
        let data = {};
        try {
          const parsed = parseWithSchema(r.binary, config.parserSchema);
          data = parsed;
        } catch (e) {
          data = { _parseError: e.message };
        }
        return { index: r.index, data, binary: r.binary, size: r.size };
      });
      state.encryptedBuffers = [];
      state.encryptionHeaders = [];
      state.encryptionEnabled = false;
      renderBulkTable(schemaType);
      $('data-card').style.display = 'block';
      $('visible-range').textContent = `(showing first ${sampleRecords.length} of ${recordsProcessed.toLocaleString()})`;
    }

  } catch (err) {
    console.error('Failed to upload/decrypt:', err);
    progressText.textContent = `Error: ${err.message}`;
  }
}

/**
 * Helper to concatenate Uint8Arrays efficiently.
 */
function concatUint8Arrays(arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Trigger file download in browser.
 */
function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function renderBulkTable(schemaType) {
  const container = $('virtual-table-wrapper');

  // Helper to wrap value in span for styling
  const wrapSpan = (text) => {
    const span = document.createElement('span');
    span.textContent = text;
    return span;
  };

  // Define columns based on schema
  let columns;
  if (schemaType === 'monster') {
    columns = [
      { key: 'name', label: 'Name', className: 'col-name' },
      { key: 'hp', label: 'HP', className: 'col-numeric' },
      { key: 'mana', label: 'Mana', className: 'col-numeric' },
      { key: 'pos', label: 'Position', className: 'col-position', format: (v) => v ? wrapSpan(`${v.x.toFixed(1)}, ${v.y.toFixed(1)}, ${v.z.toFixed(1)}`) : '--' },
    ];
  } else if (schemaType === 'weapon') {
    columns = [
      { key: 'name', label: 'Name', className: 'col-name' },
      { key: 'damage', label: 'Damage', className: 'col-numeric' },
    ];
  } else if (schemaType === 'galaxy') {
    columns = [
      { key: 'num_stars', label: 'Stars', className: 'col-numeric', format: (v) => typeof v === 'bigint' ? v.toLocaleString() : String(v) },
    ];
  }

  // Add bytes column based on encryption state
  if (state.encryptionEnabled) {
    columns.push({
      key: 'bytes',
      label: 'Encrypted Bytes',
      className: 'col-hex',
      format: (_, record) => {
        const enc = state.encryptedBuffers[record.index];
        if (!enc) return wrapSpan('--');
        return wrapSpan(toHex(enc.slice(0, 20)) + (enc.length > 20 ? '...' : ''));
      },
    });
  } else {
    columns.push({
      key: 'bytes',
      label: 'FlatBuffer Bytes',
      className: 'col-hex',
      format: (_, record) => {
        const buf = state.buffers[record.index]?.binary;
        if (!buf) return wrapSpan('--');
        return wrapSpan(toHex(buf.slice(0, 20)) + (buf.length > 20 ? '...' : ''));
      },
    });
  }

  // Destroy old paginated table
  if (state.paginatedTable) {
    state.paginatedTable.destroy();
  }

  // Create new paginated table with page size of 10
  state.paginatedTable = new PaginatedTable(container, {
    columns,
    pageSize: 10,
    onRowClick: (record, index) => {
      showRecordDetail(record, index);
    },
    onPageChange: (page, totalPages) => {
      const info = state.paginatedTable.getPageInfo();
      $('visible-range').textContent = `(showing ${info.start + 1}-${info.end} of ${info.total})`;
    },
  });

  // Prepare records
  const records = state.buffers.map(b => ({ ...b.data, index: b.index }));
  state.paginatedTable.setData(records);

  // Update range display
  const info = state.paginatedTable.getPageInfo();
  $('visible-range').textContent = `(showing ${info.start + 1}-${info.end} of ${info.total})`;
}

function toggleEncryption() {
  state.showEncrypted = !state.showEncrypted;
  $('toggle-encryption').textContent = state.showEncrypted ? 'Bob Decrypts' : 'Show Encrypted';

  // Helper to wrap value in span
  const wrapSpan = (text) => {
    const span = document.createElement('span');
    span.textContent = text;
    return span;
  };

  // Update paginated table columns if needed
  if (state.paginatedTable && state.paginatedTable.columns && state.paginatedTable.columns.length > 0) {
    const columns = state.paginatedTable.columns;
    const lastCol = columns[columns.length - 1];

    if (state.showEncrypted) {
      lastCol.label = 'Encrypted (for Bob)';
      lastCol.format = (_, record) => {
        const enc = state.encryptedBuffers[record.index];
        if (!enc) return wrapSpan('--');
        return wrapSpan(toHex(enc.slice(0, 20)) + (enc.length > 20 ? '...' : ''));
      };
    } else {
      lastCol.label = 'Decrypted (by Bob)';
      lastCol.format = (_, record) => {
        const dec = decryptBulkRecord(record.index);
        if (!dec) return wrapSpan('--');
        return wrapSpan(toHex(dec.slice(0, 20)) + (dec.length > 20 ? '...' : ''));
      };
    }

    state.paginatedTable.setColumns(columns);
    state.paginatedTable.render();
  }
}

/**
 * Show detailed view of a record with FlatBuffer <-> JSON conversion
 */
function showRecordDetail(record, index) {
  const binary = state.buffers[index]?.binary;
  if (!binary) return;

  // Store selected record for conversion tools
  state.selectedRecord = { record, index, binary };

  // Show the detail panel
  const detailPanel = $('record-detail-panel');
  if (detailPanel) {
    detailPanel.style.display = 'block';
    $('detail-record-index').textContent = `Record #${index + 1}`;
    $('detail-json').textContent = JSON.stringify(record, (key, value) =>
      typeof value === 'bigint' ? value.toString() : value, 2);
    $('detail-hex').textContent = toHex(binary);
    $('detail-size').textContent = `${binary.length} bytes`;
  }
}

/**
 * Decrypt a bulk record using Bob's private key.
 * Uses high-performance decryptBuffer() method with cached field keys.
 */
function decryptBulkRecord(index) {
  if (!state.pki.bob || !state.pki.bob.privateKey) {
    console.error('Bob\'s private key not available');
    return new Uint8Array(0);
  }

  try {
    const privateKey = ensureUint8Array(state.pki.bob.privateKey);

    const header = encryptionHeaderFromJSON(state.encryptionHeaders[index]);
    const decryptCtx = EncryptionContext.forDecryption(
      privateKey,
      header,
      'flatbuffers-bulk-encryption-v1'
    );

    // Use high-performance decryptBuffer() - uses cached keys and XOR-based IVs
    const decrypted = new Uint8Array(state.encryptedBuffers[index]);
    decryptCtx.decryptBuffer(decrypted, index);  // index is the record counter
    return decrypted;
  } catch (error) {
    console.error('Decryption failed for record', index, error);
    return new Uint8Array(0);
  }
}

function clearBufferDisplay() {
  state.buffers = [];
  state.encryptedBuffers = [];
  state.encryptionHeaders = [];
  state.showEncrypted = true;
  state.selectedRecord = null;

  if (state.paginatedTable) {
    state.paginatedTable.destroy();
    state.paginatedTable = null;
  }

  $('data-card').style.display = 'none';
  $('stats-bar').style.display = 'none';
  $('toggle-encryption').disabled = true;
  $('clear-buffers').disabled = true;
  $('visible-range').textContent = '';

  // Hide detail panel if open
  const detailPanel = $('record-detail-panel');
  if (detailPanel) detailPanel.style.display = 'none';
}

// =============================================================================
// Schema Viewer & JSON Conversion
// =============================================================================

/**
 * Convert FlatBuffers schema to JSON Schema using flatc
 * @param {string} schemaType - The schema type to convert
 * @returns {string} JSON Schema string (or error message)
 */
function fbsToJsonSchema(schemaType) {
  const config = schemaConfig[schemaType];
  if (!config || !state.flatcRunner) {
    return '{"error": "Schema not available or flatc not initialized"}';
  }

  try {
    const jsonSchema = state.flatcRunner.generateJsonSchema(
      { entry: config.entry, files: config.files },
      { includeXFlatbuffers: true }
    );
    return jsonSchema;
  } catch (err) {
    console.error('Failed to generate JSON Schema:', err);
    return JSON.stringify({ error: err.message }, null, 2);
  }
}

/**
 * Update schema viewer with selected schema
 */
function updateSchemaViewer() {
  const schemaType = $('schema-type-select')?.value || 'monster';
  const config = schemaConfig[schemaType];

  // Display .fbs content
  const fbsContent = $('fbs-content');
  if (fbsContent && config) {
    const fbsText = Object.values(config.files)[0] || '';
    fbsContent.textContent = fbsText.trim();
  }

  // Display JSON Schema (fbsToJsonSchema returns a string directly from flatc)
  const jsonSchemaContent = $('json-schema-content');
  if (jsonSchemaContent) {
    const jsonSchema = fbsToJsonSchema(schemaType);
    // Parse and re-stringify for consistent formatting
    try {
      const parsed = JSON.parse(jsonSchema);
      jsonSchemaContent.textContent = JSON.stringify(parsed, null, 2);
    } catch {
      jsonSchemaContent.textContent = jsonSchema;
    }
  }
}

/**
 * Copy text to clipboard
 */
async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    // Brief visual feedback could be added here
  } catch (err) {
    console.error('Failed to copy:', err);
  }
}

/**
 * Convert JSON input to FlatBuffer binary
 */
async function convertJsonToFlatBuffer() {
  const jsonInput = $('json-input')?.value;
  const schemaType = $('convert-schema-select')?.value || 'monster';

  if (!jsonInput) {
    alert('Please enter JSON data');
    return;
  }

  try {
    const data = JSON.parse(jsonInput);
    const binary = await generateFlatBuffer(schemaType, data);

    // Display result
    $('fb-output').textContent = toHex(binary);
    $('fb-output-size').textContent = `${binary.length} bytes`;
    $('conversion-result').style.display = 'block';
  } catch (err) {
    alert('Conversion error: ' + err.message);
  }
}

/**
 * Convert FlatBuffer binary (hex) to JSON
 */
function convertFlatBufferToJson() {
  const hexInput = $('fb-hex-input')?.value?.replace(/\s+/g, '');
  const schemaType = $('convert-schema-select')?.value || 'monster';

  if (!hexInput) {
    alert('Please enter hex data');
    return;
  }

  try {
    // Parse hex to bytes
    const bytes = new Uint8Array(hexInput.match(/.{1,2}/g).map(b => parseInt(b, 16)));

    // Parse using schema
    const config = schemaConfig[schemaType];
    const parser = new FlatBufferParser(bytes);
    const parsed = parseWithSchema(parser, config.parserSchema.fields);

    // Extract values from parsed fields
    const result = {};
    for (const field of parsed.fields) {
      if (field.present && field.value !== null) {
        result[field.name] = field.value;
      }
    }

    // Display result
    $('json-output').textContent = JSON.stringify(result, (key, value) =>
      typeof value === 'bigint' ? value.toString() : value, 2);
    $('conversion-result').style.display = 'block';
  } catch (err) {
    alert('Conversion error: ' + err.message);
  }
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

  // Also save encryption key and IV if available
  if (state.encryptionKey && state.encryptionIV) {
    data.encryptionKey = toHexCompact(state.encryptionKey);
    data.encryptionIV = toHexCompact(state.encryptionIV);
  }

  try {
    localStorage.setItem(PKI_STORAGE_KEY, JSON.stringify(data));
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

    // Restore encryption key and IV if available
    if (data.encryptionKey && data.encryptionIV) {
      state.encryptionKey = hexToBytes(data.encryptionKey);
      state.encryptionIV = hexToBytes(data.encryptionIV);
    }

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
  $('alice-public-key').textContent = '--';
  $('alice-private-key').textContent = '--';
  $('bob-public-key').textContent = '--';
  $('bob-private-key').textContent = '--';
  $('pki-controls').style.display = 'none';
  $('pki-parties').style.display = 'none';
  $('encryption-explainer').style.display = 'none';
  $('pki-demo').style.display = 'none';
  $('pki-security').style.display = 'none';
  $('pki-clear-keys').style.display = 'none';
  $('pki-plaintext').value = '';
  $('pki-ciphertext-step').style.display = 'none';
  $('pki-decrypt-step').style.display = 'none';
  $('pki-result-step').style.display = 'none';
  $('pki-wrong-result').style.display = 'none';
}

/**
 * Derive PKI keys from HD wallet paths
 * Alice: m/44'/0'/0'/0/0 (index 0)
 * Bob: m/44'/0'/0'/0/1 (index 1)
 */
function derivePKIKeysFromHD() {
  if (!state.hdRoot) {
    console.warn('HD wallet not initialized, cannot derive PKI keys');
    return false;
  }

  const algorithm = $('pki-algorithm')?.value || 'x25519';
  state.pki.algorithm = algorithm;

  try {
    // Derive deterministic seeds from HD wallet for Alice (index 0) and Bob (index 1)
    // This ensures consistent keys across sessions while keeping them different
    const alicePath = "m/44'/0'/0'/0/0";
    const bobPath = "m/44'/0'/0'/0/1";

    const aliceSeed = deriveKeyFromPath(alicePath);
    const bobSeed = deriveKeyFromPath(bobPath);

    // Generate key pairs based on algorithm using derived seeds
    switch (algorithm) {
      case 'x25519': {
        state.pki.alice = deriveX25519FromSeed(aliceSeed);
        state.pki.bob = deriveX25519FromSeed(bobSeed);
        break;
      }
      case 'secp256k1': {
        state.pki.alice = deriveSecp256k1FromSeed(aliceSeed);
        state.pki.bob = deriveSecp256k1FromSeed(bobSeed);
        break;
      }
      case 'p256': {
        state.pki.alice = deriveP256FromSeed(aliceSeed);
        state.pki.bob = deriveP256FromSeed(bobSeed);
        break;
      }
      default:
        state.pki.alice = deriveX25519FromSeed(aliceSeed);
        state.pki.bob = deriveX25519FromSeed(bobSeed);
    }

    return true;
  } catch (e) {
    console.error('Failed to derive PKI keys from HD:', e);
    return false;
  }
}

/**
 * Derive a 32-byte key from HD wallet path
 */
function deriveKeyFromPath(path) {
  if (!state.hdRoot) {
    throw new Error('HD wallet not initialized');
  }
  const derived = state.hdRoot.derivePath(path);
  return derived.privateKey;
}

/**
 * Derive X25519 key pair from a seed using @noble/curves (pure JS)
 * Uses the seed as the private key and computes the public key via scalar multiplication
 */
function deriveX25519FromSeed(seed) {
  // Use @noble/curves for deterministic key derivation from HD seed
  // x25519.getPublicKey handles the clamping internally
  const privateKey = new Uint8Array(seed);
  const publicKey = x25519.getPublicKey(privateKey);
  return {
    privateKey,
    publicKey: new Uint8Array(publicKey),
  };
}

/**
 * Derive secp256k1 key pair from a seed using @noble/curves (pure JS)
 */
function deriveSecp256k1FromSeed(seed) {
  // Use @noble/curves for deterministic key derivation
  const privateKey = new Uint8Array(seed);
  const publicKey = secp256k1.getPublicKey(privateKey, true); // compressed
  return {
    privateKey,
    publicKey: new Uint8Array(publicKey),
  };
}

/**
 * Derive P-256 key pair from a seed using @noble/curves (pure JS)
 */
function deriveP256FromSeed(seed) {
  // Use @noble/curves for deterministic key derivation
  const privateKey = new Uint8Array(seed);
  const publicKey = p256.getPublicKey(privateKey, true); // compressed
  return {
    privateKey,
    publicKey: new Uint8Array(publicKey),
  };
}

function generatePKIKeyPairs() {
  // First try to derive from HD wallet
  if (state.hdRoot && derivePKIKeysFromHD()) {
    // PKI keys derived from HD wallet
  } else {
    // Fallback to random generation
    const algorithm = $('pki-algorithm')?.value || 'x25519';
    state.pki.algorithm = algorithm;

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
    } catch (e) {
      console.error('Failed to generate PKI keys:', e);
      alert('Failed to generate keys: ' + e.message);
      return;
    }
  }

  // Save keys to localStorage
  savePKIKeys();

  // Display keys
  $('alice-public-key').textContent = toHexCompact(state.pki.alice.publicKey);
  $('alice-private-key').textContent = toHexCompact(state.pki.alice.privateKey);
  $('bob-public-key').textContent = toHexCompact(state.pki.bob.publicKey);
  $('bob-private-key').textContent = toHexCompact(state.pki.bob.privateKey);

  // Display algorithm
  const algorithmNames = {
    x25519: 'X25519 (Curve25519)',
    secp256k1: 'secp256k1 (Bitcoin)',
    p256: 'P-256 (NIST)',
  };
  $('pki-algorithm-display').textContent = algorithmNames[state.pki.algorithm] || state.pki.algorithm;

  // Show UI sections
  $('pki-controls').style.display = 'flex';
  $('pki-parties').style.display = 'grid';
  $('encryption-explainer').style.display = 'block';
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
  // Ensure publicKey is a Uint8Array (may be plain object from localStorage)
  let publicKey = state.pki.bob.publicKey;
  if (!(publicKey instanceof Uint8Array)) {
    if (typeof publicKey === 'object' && publicKey !== null) {
      publicKey = new Uint8Array(Object.values(publicKey));
    } else {
      publicKey = new Uint8Array(publicKey);
    }
  }

  const encryptCtx = EncryptionContext.forEncryption(publicKey, {
    algorithm: state.pki.algorithm,
    context: 'flatbuffers-pki-demo-v1',
  });

  // Encrypt the data using high-performance method (key caching + XOR IV)
  const ciphertext = new Uint8Array(state.pki.plaintext);
  encryptCtx.encryptBuffer(ciphertext, 0);  // recordCounter=0 for single message
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
    // Ensure privateKey is a Uint8Array (may be plain object from localStorage)
    let privateKey = state.pki.bob.privateKey;
    if (!(privateKey instanceof Uint8Array)) {
      if (typeof privateKey === 'object' && privateKey !== null) {
        privateKey = new Uint8Array(Object.values(privateKey));
      } else {
        privateKey = new Uint8Array(privateKey);
      }
    }

    const decryptCtx = EncryptionContext.forDecryption(
      privateKey,
      header,
      'flatbuffers-pki-demo-v1'
    );

    // Decrypt using high-performance method (AES-CTR is symmetric)
    const decrypted = new Uint8Array(state.pki.ciphertext);
    decryptCtx.decryptBuffer(decrypted, 0);  // recordCounter=0 for single message
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

    // Ensure Alice's private key is a Uint8Array (may be plain object from localStorage)
    let privateKey = state.pki.alice.privateKey;
    if (!(privateKey instanceof Uint8Array)) {
      if (typeof privateKey === 'object' && privateKey !== null) {
        privateKey = new Uint8Array(Object.values(privateKey));
      } else {
        privateKey = new Uint8Array(privateKey);
      }
    }

    // Try to decrypt with Alice's private key (WRONG - should fail)
    const decryptCtx = EncryptionContext.forDecryption(
      privateKey,
      header,
      'flatbuffers-pki-demo-v1'
    );

    // Attempt decryption (will produce garbage since wrong key was used)
    const attemptedDecrypt = new Uint8Array(state.pki.ciphertext);
    decryptCtx.decryptBuffer(attemptedDecrypt, 0);  // recordCounter=0

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

  // Mobile menu toggle
  const mobileMenuBtn = $('nav-menu-btn');
  const mobileMenu = $('nav-mobile-menu');

  if (mobileMenuBtn && mobileMenu) {
    mobileMenuBtn.addEventListener('click', () => {
      mobileMenu.classList.toggle('open');
      // Update hamburger icon to X when open
      const isOpen = mobileMenu.classList.contains('open');
      mobileMenuBtn.innerHTML = isOpen
        ? '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>'
        : '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>';
    });
  }

  // Navigation tabs (now links) - scroll to sections instead of hide/show
  document.querySelectorAll('.nav-link[data-tab]').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      document.querySelectorAll('.nav-link[data-tab]').forEach(l => l.classList.remove('active'));
      link.classList.add('active');
      const tabEl = $(`${link.dataset.tab}-tab`);
      if (tabEl) {
        // Scroll the section into view within the main-app container
        tabEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
      // Close mobile menu if open
      if (mobileMenu) {
        mobileMenu.classList.remove('open');
        if (mobileMenuBtn) {
          mobileMenuBtn.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>';
        }
      }
    });
  });

  // Update active nav link based on scroll position
  const mainApp = $('main-app');
  if (mainApp) {
    const sections = document.querySelectorAll('.content-section');
    const navLinks = document.querySelectorAll('.nav-link[data-tab]');

    mainApp.addEventListener('scroll', () => {
      let currentSection = '';
      const scrollTop = mainApp.scrollTop;

      sections.forEach(section => {
        const sectionTop = section.offsetTop - mainApp.offsetTop;
        const sectionHeight = section.offsetHeight;
        if (scrollTop >= sectionTop - 100 && scrollTop < sectionTop + sectionHeight - 100) {
          currentSection = section.id.replace('-tab', '');
        }
      });

      navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.dataset.tab === currentSection) {
          link.classList.add('active');
        }
      });
    });
  }

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

  // Bulk Generation Tab - Download buttons (memory efficient)
  $('download-encrypted')?.addEventListener('click', () => generateAndDownload(true));
  $('download-plain')?.addEventListener('click', () => generateAndDownload(false));

  // File upload
  $('upload-file')?.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      $('upload-filename').textContent = file.name;
      uploadAndDecrypt(file);
    }
  });

  // In-memory generation (for smaller datasets)
  $('generate-buffers').addEventListener('click', () => {
    state.encryptionEnabled = true;
    generateBulkBuffers();
  });
  $('generate-plain')?.addEventListener('click', () => {
    state.encryptionEnabled = false;
    generateBulkBuffers();
  });
  $('toggle-encryption').addEventListener('click', toggleEncryption);
  $('clear-buffers').addEventListener('click', clearBufferDisplay);

  // Schema Viewer Tab
  $('schema-type-select')?.addEventListener('change', updateSchemaViewer);
  $('copy-fbs')?.addEventListener('click', () => copyToClipboard($('fbs-content')?.textContent || ''));
  $('copy-json-schema')?.addEventListener('click', () => copyToClipboard($('json-schema-content')?.textContent || ''));

  // FlatBuffer <-> JSON Conversion
  $('json-to-fb')?.addEventListener('click', convertJsonToFlatBuffer);
  $('fb-to-json')?.addEventListener('click', convertFlatBufferToJson);
  $('close-detail-panel')?.addEventListener('click', () => {
    const panel = $('record-detail-panel');
    if (panel) panel.style.display = 'none';
  });

  // PKI Tab - Keys are derived from HD wallet automatically on login
  $('pki-clear-keys')?.addEventListener('click', clearPKIKeys);
  $('pki-encrypt')?.addEventListener('click', pkiEncrypt);
  $('pki-decrypt')?.addEventListener('click', pkiDecrypt);
  $('pki-wrong-key')?.addEventListener('click', pkiTryWrongKey);

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

    // Display flatc version
    try {
      const version = state.flatcRunner.version();
      const versionEl = $('flatc-version');
      if (versionEl && version) {
        versionEl.textContent = `flatc ${version.trim()}`;
      }
    } catch (e) {
      console.warn('Could not get flatc version:', e);
    }

    // Setup streaming demo
    setupStreamingDemo();

    // Load saved PKI keys if available
    const hasSavedKeys = loadPKIKeys();

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

    // Auto-login if we have saved PKI keys (skip login screen)
    if (hasSavedKeys) {
      // Generate temporary wallet keys for the session
      const tempKeys = {
        x25519: x25519GenerateKeyPair(),
        ed25519: ed25519GenerateKeyPair(),
        secp256k1: secp256k1GenerateKeyPair(),
        p256: p256GenerateKeyPair(),
      };

      // Generate encryption key and IV if not loaded from storage
      if (!state.encryptionKey || !state.encryptionIV) {
        const encoder = new TextEncoder();
        // Use a random seed for session-based encryption
        const randomSeed = new Uint8Array(32);
        crypto.getRandomValues(randomSeed);
        state.encryptionKey = hkdf(randomSeed, new Uint8Array(0), encoder.encode('buffer-encryption-key'), 32);
        state.encryptionIV = hkdf(randomSeed, new Uint8Array(0), encoder.encode('buffer-encryption-iv'), 16);
        // Save the keys so they persist
        savePKIKeys();
      }

      login(tempKeys);
    }

  } catch (err) {
    console.error('Init failed:', err);
    status.textContent = `Failed to load: ${err.message}`;

    // Show error state in loading overlay
    loadingOverlay.classList.add('error');
  }

  // Initialize Studio functionality
  initStudio();
}

// =============================================================================
// Studio Functionality
// =============================================================================

const studioState = {
  schemaType: 'fbs',
  parsedSchema: null,
  tables: [],
  enums: [],
  structs: [],
  currentBuffer: null,
};

// Schema Editor File System State
const schemaFiles = {
  files: {},           // Map of path -> { content, modified }
  currentFile: null,   // Currently selected file path
  entryPoint: null,    // Main entry point for compilation (usually main.fbs or schema.fbs)
};

// localStorage key for persistence
const SCHEMA_FILES_STORAGE_KEY = 'flatbuffers_studio_files';

// Schema Builder State
const schemaBuilder = {
  namespace: '',
  rootType: '',
  fileIdentifier: '',  // 4-character file identifier
  fileExtension: '',   // file extension (without dot)
  includes: [],        // List of include file paths
  attributes: [],      // Custom attribute declarations
  services: [],        // RPC service definitions
  items: [],
  selectedIndex: -1,
  previewFormat: 'fbs',
  validationError: null,  // Last validation error from flatc
};

// Canonical FlatBuffers scalar types (per grammar.md)
// Note: int8/uint8/etc. are aliases but we use the canonical names
const SCALAR_TYPES = [
  'bool', 'byte', 'ubyte', 'short', 'ushort', 'int', 'uint',
  'long', 'ulong', 'float', 'double', 'string'
];

// Mapping from aliases to canonical names (for parsing imported schemas)
const TYPE_ALIASES = {
  'int8': 'byte',
  'uint8': 'ubyte',
  'int16': 'short',
  'uint16': 'ushort',
  'int32': 'int',
  'uint32': 'uint',
  'int64': 'long',
  'uint64': 'ulong',
  'float32': 'float',
  'float64': 'double',
};

// All scalar types including aliases (for validation)
const ALL_SCALAR_TYPES = [
  ...SCALAR_TYPES,
  'int8', 'uint8', 'int16', 'uint16', 'int32', 'uint32', 'int64', 'uint64',
  'float32', 'float64'
];

const INTEGER_TYPES = ['byte', 'ubyte', 'short', 'ushort', 'int', 'uint', 'long', 'ulong'];
const FLOAT_TYPES = ['float', 'double'];
const ENUM_BASE_TYPES = ['byte', 'ubyte', 'short', 'ushort', 'int', 'uint', 'long', 'ulong'];

// Integer type ranges for validation
const INTEGER_RANGES = {
  'byte': { min: -128n, max: 127n },
  'ubyte': { min: 0n, max: 255n },
  'short': { min: -32768n, max: 32767n },
  'ushort': { min: 0n, max: 65535n },
  'int': { min: -2147483648n, max: 2147483647n },
  'uint': { min: 0n, max: 4294967295n },
  'long': { min: -9223372036854775808n, max: 9223372036854775807n },
  'ulong': { min: 0n, max: 18446744073709551615n },
};

/**
 * Validate a default value against its field type
 * @param {string} value - The default value string
 * @param {string} fieldType - The field type (e.g., 'int', 'bool', 'MyEnum')
 * @returns {{ valid: boolean, error?: string }}
 */
function validateDefaultValue(value, fieldType) {
  // Empty value is always valid (no default)
  if (value === '' || value === undefined || value === null) {
    return { valid: true };
  }

  // 'null' is valid for optional scalars
  if (value === 'null') {
    return { valid: true };
  }

  // Bool type
  if (fieldType === 'bool') {
    if (value === 'true' || value === 'false') {
      return { valid: true };
    }
    return { valid: false, error: 'Must be "true" or "false"' };
  }

  // Integer types
  if (INTEGER_TYPES.includes(fieldType)) {
    const range = INTEGER_RANGES[fieldType];
    // Check if it's a valid integer (decimal or hex)
    const isHex = /^[-+]?0[xX][0-9a-fA-F]+$/.test(value);
    const isDec = /^[-+]?[0-9]+$/.test(value);

    if (!isHex && !isDec) {
      return { valid: false, error: 'Must be an integer' };
    }

    try {
      const num = BigInt(value);
      if (num < range.min || num > range.max) {
        return { valid: false, error: `Out of range (${range.min} to ${range.max})` };
      }
      return { valid: true };
    } catch {
      return { valid: false, error: 'Invalid integer' };
    }
  }

  // Float types
  if (FLOAT_TYPES.includes(fieldType)) {
    // Special float values
    if (/^[-+]?(nan|inf|infinity)$/i.test(value)) {
      return { valid: true };
    }
    // Decimal float
    if (/^[-+]?(([.][0-9]+)|([0-9]+[.][0-9]*)|([0-9]+))([eE][-+]?[0-9]+)?$/.test(value)) {
      return { valid: true };
    }
    // Hex float
    if (/^[-+]?0[xX](([.][0-9a-fA-F]+)|([0-9a-fA-F]+[.][0-9a-fA-F]*)|([0-9a-fA-F]+))([pP][-+]?[0-9]+)?$/.test(value)) {
      return { valid: true };
    }
    return { valid: false, error: 'Must be a number (e.g., 1.5, -3.14, nan, inf)' };
  }

  // Check if it's an enum type
  const enumItem = schemaBuilder.items.find(i => i.type === 'enum' && i.name === fieldType);
  if (enumItem) {
    // Value must be a valid enum member name
    const validNames = enumItem.values.map(v => v.name);
    if (validNames.includes(value)) {
      return { valid: true };
    }
    return { valid: false, error: `Must be one of: ${validNames.join(', ')}` };
  }

  // For other types (custom tables, structs, etc.), can't have defaults
  // This should be caught earlier by disabling the input
  return { valid: true };
}

const SAMPLE_FBS_SCHEMA = `// Sample FlatBuffers Schema
namespace MyGame.Sample;

enum Color : byte { Red = 0, Green, Blue = 2 }

struct Vec3 {
  x: float;
  y: float;
  z: float;
}

table Monster {
  pos: Vec3;
  mana: short = 150;
  hp: short = 100;
  name: string;
  friendly: bool = false;
  inventory: [ubyte];
  color: Color = Blue;
}

table Weapon {
  name: string;
  damage: short;
}

root_type Monster;
`;

// Sample multi-file project
const SAMPLE_PROJECT_FILES = {
  'schema.fbs': `// Main schema file
include "types/common.fbs";
include "types/monster.fbs";

namespace MyGame;

root_type Monster;
file_identifier "GAME";
`,
  'types/common.fbs': `// Common types
namespace MyGame.Types;

enum Color : byte { Red = 0, Green, Blue }

struct Vec3 {
  x: float;
  y: float;
  z: float;
}
`,
  'types/monster.fbs': `// Monster definitions
include "common.fbs";

namespace MyGame;

table Weapon {
  name: string;
  damage: short;
}

table Monster {
  pos: Types.Vec3;
  mana: short = 150;
  hp: short = 100;
  name: string (required);
  friendly: bool = false;
  inventory: [ubyte];
  color: Types.Color = Blue;
  weapons: [Weapon];
}
`
};

// ============================================================================
// Schema File System Functions
// ============================================================================

function loadSchemaFilesFromStorage() {
  try {
    const saved = localStorage.getItem(SCHEMA_FILES_STORAGE_KEY);
    if (saved) {
      const data = JSON.parse(saved);
      schemaFiles.files = data.files || {};
      schemaFiles.entryPoint = data.entryPoint || null;
      // Mark all as unmodified on load
      for (const path in schemaFiles.files) {
        schemaFiles.files[path].modified = false;
      }
      return true;
    }
  } catch (e) {
    console.warn('Failed to load schema files from storage:', e);
  }
  return false;
}

function saveSchemaFilesToStorage() {
  try {
    const data = {
      files: schemaFiles.files,
      entryPoint: schemaFiles.entryPoint,
    };
    localStorage.setItem(SCHEMA_FILES_STORAGE_KEY, JSON.stringify(data));
  } catch (e) {
    console.warn('Failed to save schema files to storage:', e);
  }
}

function createSchemaFile(path, content = '') {
  // Normalize path
  path = path.replace(/\\/g, '/').replace(/^\//, '');

  // Ensure .fbs extension
  if (!path.endsWith('.fbs') && !path.endsWith('.json')) {
    path += '.fbs';
  }

  schemaFiles.files[path] = { content, modified: true };

  // Set as entry point if it's the first file or named schema/main
  if (!schemaFiles.entryPoint || path === 'schema.fbs' || path === 'main.fbs') {
    schemaFiles.entryPoint = path;
  }

  saveSchemaFilesToStorage();
  renderSchemaFileTree();
  selectSchemaFile(path);
}

function deleteSchemaFile(path) {
  if (!schemaFiles.files[path]) return;

  if (!confirm(`Delete "${path}"?`)) return;

  delete schemaFiles.files[path];

  // Update entry point if deleted
  if (schemaFiles.entryPoint === path) {
    const remaining = Object.keys(schemaFiles.files);
    schemaFiles.entryPoint = remaining.length > 0 ? remaining[0] : null;
  }

  // Clear editor if current file was deleted
  if (schemaFiles.currentFile === path) {
    schemaFiles.currentFile = null;
    const editor = $('studio-schema-input');
    if (editor) {
      editor.value = '';
      editor.placeholder = '// Select or create a file to begin editing...';
    }
    updateCurrentFileIndicator();
  }

  saveSchemaFilesToStorage();
  renderSchemaFileTree();
}

function renameSchemaFile(oldPath, newPath) {
  if (!schemaFiles.files[oldPath]) return;

  // Normalize new path
  newPath = newPath.replace(/\\/g, '/').replace(/^\//, '');
  if (!newPath.endsWith('.fbs') && !newPath.endsWith('.json')) {
    newPath += '.fbs';
  }

  if (oldPath === newPath) return;
  if (schemaFiles.files[newPath]) {
    alert(`File "${newPath}" already exists`);
    return;
  }

  schemaFiles.files[newPath] = schemaFiles.files[oldPath];
  delete schemaFiles.files[oldPath];

  if (schemaFiles.entryPoint === oldPath) {
    schemaFiles.entryPoint = newPath;
  }

  if (schemaFiles.currentFile === oldPath) {
    schemaFiles.currentFile = newPath;
  }

  saveSchemaFilesToStorage();
  renderSchemaFileTree();
  updateCurrentFileIndicator();
}

function selectSchemaFile(path) {
  // Save current file content first
  if (schemaFiles.currentFile && schemaFiles.files[schemaFiles.currentFile]) {
    const editor = $('studio-schema-input');
    if (editor) {
      schemaFiles.files[schemaFiles.currentFile].content = editor.value;
    }
  }

  schemaFiles.currentFile = path;

  const editor = $('studio-schema-input');
  if (editor && schemaFiles.files[path]) {
    editor.value = schemaFiles.files[path].content;
    editor.placeholder = '// Enter your FlatBuffers schema here...';
  }

  updateCurrentFileIndicator();
  renderSchemaFileTree(); // Update selection
}

function updateCurrentFileIndicator() {
  const indicator = $('schema-current-file');
  const title = $('schema-editor-title');

  if (schemaFiles.currentFile) {
    if (indicator) indicator.textContent = schemaFiles.currentFile;
    if (title) title.textContent = schemaFiles.currentFile.split('/').pop();
  } else {
    if (indicator) indicator.textContent = '';
    if (title) title.textContent = 'Schema Definition';
  }
}

function renderSchemaFileTree() {
  const container = $('schema-file-tree');
  if (!container) return;

  const paths = Object.keys(schemaFiles.files).sort();

  if (paths.length === 0) {
    container.innerHTML = '<div class="empty-state small">No files yet</div>';
    return;
  }

  // Build folder structure
  const tree = {};
  for (const path of paths) {
    const parts = path.split('/');
    let current = tree;
    for (let i = 0; i < parts.length - 1; i++) {
      const folder = parts[i];
      if (!current[folder]) {
        current[folder] = { _isFolder: true, _children: {} };
      }
      current = current[folder]._children;
    }
    current[parts[parts.length - 1]] = { _isFile: true, _path: path };
  }

  container.innerHTML = renderTreeNode(tree, '');
  attachFileTreeListeners();
}

function renderTreeNode(node, prefix) {
  let html = '';

  // Sort: folders first, then files
  const entries = Object.entries(node).sort((a, b) => {
    const aIsFolder = a[1]._isFolder;
    const bIsFolder = b[1]._isFolder;
    if (aIsFolder && !bIsFolder) return -1;
    if (!aIsFolder && bIsFolder) return 1;
    return a[0].localeCompare(b[0]);
  });

  for (const [name, item] of entries) {
    if (item._isFolder) {
      const folderPath = prefix ? `${prefix}/${name}` : name;
      html += `
        <div class="file-tree-folder" data-folder="${escapeHtml(folderPath)}">
          <div class="file-tree-item folder-item">
            <span class="folder-toggle">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="6 9 12 15 18 9"></polyline>
              </svg>
            </span>
            <svg class="file-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
            </svg>
            <span class="file-name">${escapeHtml(name)}</span>
            <div class="file-actions">
              <button class="file-action-btn delete" data-action="delete-folder" title="Delete folder">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <line x1="18" y1="6" x2="6" y2="18"></line>
                  <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
              </button>
            </div>
          </div>
          <div class="file-tree-folder-children">
            ${renderTreeNode(item._children, folderPath)}
          </div>
        </div>
      `;
    } else if (item._isFile) {
      const isSelected = schemaFiles.currentFile === item._path;
      const isModified = schemaFiles.files[item._path]?.modified;
      const isEntry = schemaFiles.entryPoint === item._path;
      html += `
        <div class="file-tree-item${isSelected ? ' selected' : ''}${isModified ? ' modified' : ''}" data-path="${escapeHtml(item._path)}">
          <svg class="file-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
            <polyline points="14 2 14 8 20 8"></polyline>
          </svg>
          <span class="file-name">${escapeHtml(name)}${isEntry ? ' ★' : ''}</span>
          <div class="file-actions">
            <button class="file-action-btn" data-action="set-entry" title="Set as entry point">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon>
              </svg>
            </button>
            <button class="file-action-btn" data-action="rename" title="Rename">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"></path>
              </svg>
            </button>
            <button class="file-action-btn delete" data-action="delete" title="Delete">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
              </svg>
            </button>
          </div>
        </div>
      `;
    }
  }

  return html;
}

function attachFileTreeListeners() {
  // File selection
  document.querySelectorAll('.file-tree-item[data-path]').forEach(item => {
    item.addEventListener('click', (e) => {
      if (e.target.closest('.file-action-btn')) return; // Don't select when clicking actions
      const path = item.dataset.path;
      selectSchemaFile(path);
    });
  });

  // Folder toggle
  document.querySelectorAll('.file-tree-folder > .file-tree-item').forEach(item => {
    item.addEventListener('click', (e) => {
      if (e.target.closest('.file-action-btn')) return;
      const folder = item.closest('.file-tree-folder');
      folder.classList.toggle('collapsed');
    });
  });

  // File actions
  document.querySelectorAll('.file-action-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const action = btn.dataset.action;
      const fileItem = btn.closest('.file-tree-item');
      const path = fileItem?.dataset.path;

      if (action === 'delete' && path) {
        deleteSchemaFile(path);
      } else if (action === 'rename' && path) {
        const newName = prompt('New filename:', path);
        if (newName) renameSchemaFile(path, newName);
      } else if (action === 'set-entry' && path) {
        schemaFiles.entryPoint = path;
        saveSchemaFilesToStorage();
        renderSchemaFileTree();
        setStudioStatus(`Entry point set to ${path}`, 'success');
      } else if (action === 'delete-folder') {
        const folder = btn.closest('.file-tree-folder');
        const folderPath = folder?.dataset.folder;
        if (folderPath) {
          const filesToDelete = Object.keys(schemaFiles.files).filter(p => p.startsWith(folderPath + '/'));
          if (filesToDelete.length === 0) return;
          if (!confirm(`Delete folder "${folderPath}" and ${filesToDelete.length} file(s)?`)) return;
          filesToDelete.forEach(p => delete schemaFiles.files[p]);
          saveSchemaFilesToStorage();
          renderSchemaFileTree();
        }
      }
    });
  });
}

function loadSampleProject() {
  if (Object.keys(schemaFiles.files).length > 0) {
    if (!confirm('This will replace all current files. Continue?')) return;
  }

  schemaFiles.files = {};
  for (const [path, content] of Object.entries(SAMPLE_PROJECT_FILES)) {
    schemaFiles.files[path] = { content, modified: false };
  }
  schemaFiles.entryPoint = 'schema.fbs';
  schemaFiles.currentFile = 'schema.fbs';

  saveSchemaFilesToStorage();
  renderSchemaFileTree();
  selectSchemaFile('schema.fbs');
  setStudioStatus('Sample project loaded', 'success');
}

function initStudio() {
  // Studio tab switching
  document.querySelectorAll('.studio-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const tabId = tab.dataset.studioTab;
      document.querySelectorAll('.studio-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.studio-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      const panel = document.getElementById(`studio-${tabId}`);
      if (panel) panel.classList.add('active');
    });
  });

  // Initialize file tree - load from storage or start empty
  loadSchemaFilesFromStorage();
  renderSchemaFileTree();
  if (schemaFiles.currentFile) {
    selectSchemaFile(schemaFiles.currentFile);
  } else if (schemaFiles.entryPoint) {
    selectSchemaFile(schemaFiles.entryPoint);
  }

  // Load sample project button
  $('studio-load-sample')?.addEventListener('click', loadSampleProject);

  // New file button
  $('schema-new-file')?.addEventListener('click', () => {
    const name = prompt('File name (e.g., types/monster.fbs):');
    if (name) createSchemaFile(name);
  });

  // New folder button - just prompts for a file in the folder
  $('schema-new-folder')?.addEventListener('click', () => {
    const folder = prompt('Folder name:');
    if (folder) {
      const fileName = prompt('First file name in this folder:', 'schema.fbs');
      if (fileName) {
        createSchemaFile(`${folder}/${fileName}`);
      }
    }
  });

  // Upload schema files (multiple)
  $('studio-upload-schema')?.addEventListener('change', async (e) => {
    const files = Array.from(e.target.files || []);
    if (files.length === 0) return;

    for (const file of files) {
      const content = await file.text();
      // Preserve folder structure if webkitRelativePath is available
      const path = file.webkitRelativePath || file.name;
      schemaFiles.files[path] = { content, modified: false };
    }

    // Set entry point to first .fbs file if not already set
    if (!schemaFiles.entryPoint) {
      const fbsFile = files.find(f => f.name.endsWith('.fbs'));
      if (fbsFile) {
        schemaFiles.entryPoint = fbsFile.webkitRelativePath || fbsFile.name;
      }
    }

    saveSchemaFilesToStorage();
    renderSchemaFileTree();

    // Select first uploaded file
    const firstPath = files[0].webkitRelativePath || files[0].name;
    selectSchemaFile(firstPath);
    setStudioStatus(`Uploaded ${files.length} file(s)`, 'success');

    // Reset file input
    e.target.value = '';
  });

  // Editor content change - mark file as modified
  const schemaInput = $('studio-schema-input');
  if (schemaInput) {
    schemaInput.addEventListener('input', () => {
      if (schemaFiles.currentFile && schemaFiles.files[schemaFiles.currentFile]) {
        schemaFiles.files[schemaFiles.currentFile].content = schemaInput.value;
        schemaFiles.files[schemaFiles.currentFile].modified = true;
        renderSchemaFileTree(); // Update modified indicator
      }
    });

    // Auto-save on blur
    schemaInput.addEventListener('blur', () => {
      saveSchemaFilesToStorage();
    });
  }

  // Parse schema
  $('studio-parse-schema')?.addEventListener('click', parseStudioSchema);

  // Code generation
  $('studio-generate-code')?.addEventListener('click', generateStudioCode);
  $('studio-copy-code')?.addEventListener('click', () => {
    const code = $('studio-generated-code')?.value || '';
    navigator.clipboard.writeText(code);
  });
  $('studio-download-code')?.addEventListener('click', async () => {
    const lang = $('studio-codegen-lang')?.value || 'ts';

    if (!lastGeneratedFiles || Object.keys(lastGeneratedFiles).length === 0) {
      alert('No code generated yet. Click "Generate Code" first.');
      return;
    }

    const fileList = Object.keys(lastGeneratedFiles);

    if (fileList.length === 1) {
      // Single file - download directly
      const filename = fileList[0];
      downloadTextFile(lastGeneratedFiles[filename], filename);
    } else {
      // Multiple files - create ZIP
      try {
        const zip = await createZipFromFiles(lastGeneratedFiles);
        const blob = new Blob([zip], { type: 'application/zip' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `generated_${lang}.zip`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } catch (err) {
        console.error('ZIP creation failed:', err);
        // Fallback to single concatenated file
        const code = $('studio-generated-code')?.value || '';
        const extMap = {
          ts: 'ts', python: 'py', cpp: 'h', rust: 'rs', go: 'go',
          java: 'java', csharp: 'cs', kotlin: 'kt', swift: 'swift', jsonschema: 'json'
        };
        const ext = extMap[lang] || 'txt';
        downloadTextFile(code, `generated.${ext}`);
      }
    }
  });

  // Builder
  $('studio-builder-table')?.addEventListener('change', (e) => {
    if (e.target.value) buildStudioForm(e.target.value);
  });
  $('studio-build-buffer')?.addEventListener('click', buildStudioBuffer);
  $('studio-clear-form')?.addEventListener('click', clearStudioForm);
  $('studio-download-buffer')?.addEventListener('click', downloadStudioBuffer);

  // Downloads
  $('studio-download-flatc-wasm')?.addEventListener('click', () => {
    downloadFile('../../dist/flatc.wasm', 'flatc.wasm');
  });
  $('studio-download-flatc-js')?.addEventListener('click', () => {
    downloadFile('../../src/runner.mjs', 'flatc-runner.mjs');
  });
  $('studio-download-enc-wasm')?.addEventListener('click', () => {
    downloadFile('../../dist/flatc-encryption.wasm', 'flatc-encryption.wasm');
  });
  $('studio-download-enc-js')?.addEventListener('click', () => {
    downloadFile('../../src/encryption.mjs', 'encryption.mjs');
  });

  // Initialize Schema Builder
  initSchemaBuilder();
}

function setStudioStatus(message, type) {
  const status = $('studio-schema-status');
  if (status) {
    status.textContent = message;
    status.className = 'status-text';
    if (type) status.classList.add(type);
  }
}

function parseStudioSchema() {
  // Save current editor content first
  if (schemaFiles.currentFile && schemaFiles.files[schemaFiles.currentFile]) {
    const editor = $('studio-schema-input');
    if (editor) {
      schemaFiles.files[schemaFiles.currentFile].content = editor.value;
    }
  }
  saveSchemaFilesToStorage();

  // Get all files for parsing
  const files = {};
  for (const [path, data] of Object.entries(schemaFiles.files)) {
    files[path] = data.content;
  }

  // If no files, check if there's content in the editor as a single file
  if (Object.keys(files).length === 0) {
    const schemaInput = $('studio-schema-input');
    const content = schemaInput?.value || '';
    if (!content.trim()) {
      setStudioStatus('No schema files to parse', 'error');
      return;
    }
    files['schema.fbs'] = content;
    schemaFiles.entryPoint = 'schema.fbs';
  }

  const entryPoint = schemaFiles.entryPoint || Object.keys(files)[0];

  try {
    // Parse the entry point file for display
    const entryContent = files[entryPoint] || '';
    const schema = parseFBSSchemaContent(entryContent);

    // Also parse all other files to get a combined view
    for (const [path, content] of Object.entries(files)) {
      if (path !== entryPoint) {
        const subSchema = parseFBSSchemaContent(content);
        schema.tables.push(...subSchema.tables);
        schema.enums.push(...subSchema.enums);
        schema.structs.push(...subSchema.structs);
        schema.unions.push(...subSchema.unions);
        schema.services.push(...subSchema.services);
      }
    }

    studioState.parsedSchema = schema;
    studioState.tables = schema.tables;
    studioState.enums = schema.enums;
    studioState.structs = schema.structs;

    // Validate with WASM if available
    if (state.flatcRunner) {
      try {
        state.flatcRunner.generateJsonSchema({ entry: entryPoint, files }, { includeXFlatbuffers: true });
        setStudioStatus(`Parsed ${Object.keys(files).length} file(s) - Valid`, 'success');
      } catch (wasmErr) {
        setStudioStatus(`Parsed but validation failed: ${wasmErr.message}`, 'warning');
      }
    } else {
      setStudioStatus(`Parsed ${Object.keys(files).length} file(s)`, 'success');
    }

    updateStudioParsedView(schema);
    updateStudioTableSelectors();
  } catch (err) {
    console.error('Parse error:', err);
    setStudioStatus(err.message, 'error');
  }
}

function parseFBSSchemaContent(content) {
  const schema = {
    namespace: '',
    tables: [],
    structs: [],
    enums: [],
    unions: [],
    services: [],
    includes: [],
    attributes: [],
    rootType: '',
    fileIdentifier: '',
    fileExtension: '',
  };

  // Remove single-line comments (// ...) but preserve /// doc comments
  const lines = content.split('\n');
  const processedLines = [];
  let pendingDoc = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('///')) {
      // Documentation comment - collect it
      pendingDoc.push(trimmed.slice(3).trim());
    } else if (trimmed.startsWith('//')) {
      // Regular comment - skip
      continue;
    } else {
      // If we have pending docs, they apply to this line's declaration
      if (pendingDoc.length > 0) {
        processedLines.push(`/*DOC:${pendingDoc.join('\\n')}*/`);
        pendingDoc = [];
      }
      processedLines.push(line);
    }
  }
  const cleanContent = processedLines.join('\n');

  // Parse includes
  const includeRegex = /include\s+"([^"]+)"\s*;/g;
  let match;
  while ((match = includeRegex.exec(cleanContent)) !== null) {
    schema.includes.push(match[1]);
  }

  // Parse namespace
  const nsMatch = cleanContent.match(/namespace\s+([\w.]+)\s*;/);
  if (nsMatch) schema.namespace = nsMatch[1];

  // Parse custom attributes
  const attrRegex = /attribute\s+"([^"]+)"\s*;/g;
  while ((match = attrRegex.exec(cleanContent)) !== null) {
    schema.attributes.push(match[1]);
  }

  // Parse root_type
  const rootMatch = cleanContent.match(/root_type\s+(\w+)\s*;/);
  if (rootMatch) schema.rootType = rootMatch[1];

  // Parse file_identifier
  const fidMatch = cleanContent.match(/file_identifier\s+"([^"]+)"\s*;/);
  if (fidMatch) schema.fileIdentifier = fidMatch[1];

  // Parse file_extension
  const fextMatch = cleanContent.match(/file_extension\s+"([^"]+)"\s*;/);
  if (fextMatch) schema.fileExtension = fextMatch[1];

  // Parse enums (including doc comments before)
  const enumRegex = /(?:\/\*DOC:([^*]*)\*\/\s*)?enum\s+(\w+)\s*:\s*(\w+)\s*(?:\([^)]*\))?\s*\{([^}]+)\}/g;
  while ((match = enumRegex.exec(cleanContent)) !== null) {
    const doc = match[1] ? match[1].replace(/\\n/g, '\n') : '';
    const values = match[4].split(',').map(v => {
      // Handle value with optional doc
      const vTrimmed = v.trim();
      const parts = vTrimmed.split('=');
      const name = parts[0].trim().replace(/\/\*DOC:[^*]*\*\/\s*/, '');
      return { name: name.trim(), value: parts[1] ? parseInt(parts[1].trim()) : null, doc: '' };
    }).filter(v => v.name);
    schema.enums.push({ name: match[2], type: match[3], values, doc });
  }

  // Parse unions
  const unionRegex = /(?:\/\*DOC:([^*]*)\*\/\s*)?union\s+(\w+)\s*\{([^}]+)\}/g;
  while ((match = unionRegex.exec(cleanContent)) !== null) {
    const doc = match[1] ? match[1].replace(/\\n/g, '\n') : '';
    const members = match[3].split(',').map(m => m.trim()).filter(m => m);
    schema.unions.push({ name: match[2], members, doc });
  }

  // Parse structs (with optional metadata)
  const structRegex = /(?:\/\*DOC:([^*]*)\*\/\s*)?struct\s+(\w+)\s*(?:\(([^)]*)\))?\s*\{([^}]+)\}/g;
  while ((match = structRegex.exec(cleanContent)) !== null) {
    const doc = match[1] ? match[1].replace(/\\n/g, '\n') : '';
    const metadata = match[3] || '';
    const forceAlign = metadata.match(/force_align:\s*(\d+)/)?.[1];
    const fields = parseSchemaFields(match[4]);
    schema.structs.push({
      name: match[2],
      fields,
      doc,
      forceAlign: forceAlign ? parseInt(forceAlign) : null
    });
  }

  // Parse tables
  const tableRegex = /(?:\/\*DOC:([^*]*)\*\/\s*)?table\s+(\w+)\s*(?:\([^)]*\))?\s*\{([^}]+)\}/g;
  while ((match = tableRegex.exec(cleanContent)) !== null) {
    const doc = match[1] ? match[1].replace(/\\n/g, '\n') : '';
    const fields = parseSchemaFields(match[3]);
    schema.tables.push({ name: match[2], fields, doc });
  }

  // Parse RPC services
  const serviceRegex = /(?:\/\*DOC:([^*]*)\*\/\s*)?rpc_service\s+(\w+)\s*\{([^}]+)\}/g;
  while ((match = serviceRegex.exec(cleanContent)) !== null) {
    const doc = match[1] ? match[1].replace(/\\n/g, '\n') : '';
    const methods = parseRPCMethods(match[3]);
    schema.services.push({ name: match[2], methods, doc });
  }

  return schema;
}

function parseSchemaFields(fieldsStr) {
  const fields = [];
  // Split by semicolons but handle attributes in parentheses
  const fieldStatements = fieldsStr.split(';').filter(l => l.trim());

  for (const stmt of fieldStatements) {
    const trimmed = stmt.trim();
    // Skip doc comment markers
    if (trimmed.startsWith('/*DOC:')) continue;

    // Parse field: name: type = default (attributes);
    // Using a more robust regex that handles attributes
    const fieldMatch = trimmed.match(/^(?:\/\*DOC:([^*]*)\*\/\s*)?(\w+)\s*:\s*(\[[^\]]+\]|\w+)(?:\s*=\s*([^(]+?))?(?:\s*\(([^)]+)\))?\s*$/);
    if (fieldMatch) {
      const doc = fieldMatch[1] ? fieldMatch[1].replace(/\\n/g, '\n') : '';
      const name = fieldMatch[2];
      const type = fieldMatch[3].trim();
      const defaultVal = fieldMatch[4]?.trim() || '';
      const attrs = fieldMatch[5] || '';

      // Parse attributes
      const field = { name, type, default: defaultVal, doc };
      if (attrs) {
        if (attrs.includes('key')) field.key = true;
        if (attrs.includes('required')) field.required = true;
        if (attrs.includes('deprecated')) field.deprecated = true;
        if (attrs.includes('flexbuffer')) field.flexbuffer = true;
        const idMatch = attrs.match(/id:\s*(\d+)/);
        if (idMatch) field.id = parseInt(idMatch[1]);
        const nestedMatch = attrs.match(/nested_flatbuffer:\s*"([^"]+)"/);
        if (nestedMatch) field.nestedFlatbuffer = nestedMatch[1];
        const forceAlignMatch = attrs.match(/force_align:\s*(\d+)/);
        if (forceAlignMatch) field.forceAlign = parseInt(forceAlignMatch[1]);
      }

      fields.push(field);
    }
  }
  return fields;
}

function parseRPCMethods(methodsStr) {
  const methods = [];
  const lines = methodsStr.split(';').filter(l => l.trim());

  for (const line of lines) {
    const trimmed = line.trim();
    // Parse: MethodName(RequestType): ResponseType (attributes);
    const methodMatch = trimmed.match(/^(?:\/\*DOC:([^*]*)\*\/\s*)?(\w+)\s*\(\s*(\w+)\s*\)\s*:\s*(\w+)(?:\s*\(([^)]+)\))?\s*$/);
    if (methodMatch) {
      const doc = methodMatch[1] ? methodMatch[1].replace(/\\n/g, '\n') : '';
      const attrs = methodMatch[5] || '';
      methods.push({
        name: methodMatch[2],
        request: methodMatch[3],
        response: methodMatch[4],
        streaming: attrs.includes('streaming'),
        doc
      });
    }
  }
  return methods;
}

function updateStudioParsedView(schema) {
  const container = $('studio-parsed-view');
  if (!container) return;

  let html = '';

  if (schema.namespace) {
    html += `<div class="tree-node"><strong>namespace:</strong> ${schema.namespace}</div>`;
  }

  if (schema.includes?.length) {
    html += '<div class="tree-section">Includes</div>';
    for (const inc of schema.includes) {
      html += `<div class="tree-node"><span class="tree-icon include">I</span>"${escapeHtml(inc)}"</div>`;
    }
  }

  if (schema.enums?.length) {
    html += '<div class="tree-section">Enums</div>';
    for (const e of schema.enums) {
      html += `<div class="tree-node"><span class="tree-icon enum">E</span><span class="tree-name">${escapeHtml(e.name)}</span><span class="tree-type">: ${escapeHtml(e.type)}</span></div>`;
      html += '<div class="tree-children">';
      for (const v of e.values) {
        html += `<div class="tree-node"><span class="tree-icon field">=</span>${escapeHtml(v.name)}${v.value !== null ? ` = ${v.value}` : ''}</div>`;
      }
      html += '</div>';
    }
  }

  if (schema.unions?.length) {
    html += '<div class="tree-section">Unions</div>';
    for (const u of schema.unions) {
      html += `<div class="tree-node"><span class="tree-icon union">U</span><span class="tree-name">${escapeHtml(u.name)}</span></div>`;
      html += '<div class="tree-children">';
      for (const m of u.members) {
        html += `<div class="tree-node"><span class="tree-icon field">|</span>${escapeHtml(m)}</div>`;
      }
      html += '</div>';
    }
  }

  if (schema.structs?.length) {
    html += '<div class="tree-section">Structs</div>';
    for (const s of schema.structs) {
      const meta = s.forceAlign ? ` <span class="tree-type">(force_align: ${s.forceAlign})</span>` : '';
      html += `<div class="tree-node"><span class="tree-icon struct">S</span><span class="tree-name">${escapeHtml(s.name)}</span>${meta}</div>`;
      html += '<div class="tree-children">';
      for (const f of s.fields) {
        html += `<div class="tree-node"><span class="tree-icon field">-</span>${escapeHtml(f.name)}<span class="tree-type">: ${escapeHtml(f.type)}</span></div>`;
      }
      html += '</div>';
    }
  }

  if (schema.tables?.length) {
    html += '<div class="tree-section">Tables</div>';
    for (const t of schema.tables) {
      const isRoot = schema.rootType === t.name;
      html += `<div class="tree-node"><span class="tree-icon table">T</span><span class="tree-name">${escapeHtml(t.name)}</span>${isRoot ? ' <span class="tree-type">(root)</span>' : ''}</div>`;
      html += '<div class="tree-children">';
      for (const f of t.fields) {
        let attrs = [];
        if (f.id !== undefined) attrs.push(`id: ${f.id}`);
        if (f.key) attrs.push('key');
        if (f.required) attrs.push('required');
        if (f.deprecated) attrs.push('deprecated');
        const attrStr = attrs.length ? ` <span class="tree-attr">(${attrs.join(', ')})</span>` : '';
        html += `<div class="tree-node"><span class="tree-icon field">-</span>${escapeHtml(f.name)}<span class="tree-type">: ${escapeHtml(f.type)}</span>${f.default ? ` = ${escapeHtml(f.default)}` : ''}${attrStr}</div>`;
      }
      html += '</div>';
    }
  }

  if (schema.services?.length) {
    html += '<div class="tree-section">RPC Services</div>';
    for (const svc of schema.services) {
      html += `<div class="tree-node"><span class="tree-icon rpc">R</span><span class="tree-name">${escapeHtml(svc.name)}</span></div>`;
      html += '<div class="tree-children">';
      for (const m of svc.methods || []) {
        const stream = m.streaming ? ' <span class="tree-attr">(streaming)</span>' : '';
        html += `<div class="tree-node"><span class="tree-icon field">→</span>${escapeHtml(m.name)}(${escapeHtml(m.request)}): ${escapeHtml(m.response)}${stream}</div>`;
      }
      html += '</div>';
    }
  }

  if (schema.fileIdentifier || schema.fileExtension) {
    html += '<div class="tree-section">File Info</div>';
    if (schema.fileIdentifier) {
      html += `<div class="tree-node"><strong>file_identifier:</strong> "${escapeHtml(schema.fileIdentifier)}"</div>`;
    }
    if (schema.fileExtension) {
      html += `<div class="tree-node"><strong>file_extension:</strong> "${escapeHtml(schema.fileExtension)}"</div>`;
    }
  }

  container.innerHTML = html || '<div class="empty-state">No schema parsed</div>';
}

function updateStudioTableSelectors() {
  const tables = studioState.tables || [];
  const options = tables.map(t => `<option value="${t.name}">${t.name}</option>`).join('');
  const builderSelect = $('studio-builder-table');
  if (builderSelect) {
    builderSelect.innerHTML = '<option value="">Select Table</option>' + options;
  }
}

// Store last generated files for download
let lastGeneratedFiles = null;

async function generateStudioCode() {
  // Save current editor content first
  if (schemaFiles.currentFile && schemaFiles.files[schemaFiles.currentFile]) {
    const editor = $('studio-schema-input');
    if (editor) {
      schemaFiles.files[schemaFiles.currentFile].content = editor.value;
    }
  }

  // Get all files
  const files = {};
  for (const [path, data] of Object.entries(schemaFiles.files)) {
    files[path] = data.content;
  }

  // If no files, check if there's content in the editor as a single file
  if (Object.keys(files).length === 0) {
    const editorInput = $('studio-schema-input');
    const content = editorInput?.value || '';
    if (!content.trim()) {
      alert('No schema files. Create a file or enter schema content.');
      return;
    }
    files['schema.fbs'] = content;
    schemaFiles.entryPoint = 'schema.fbs';
  }

  const entryPoint = schemaFiles.entryPoint || Object.keys(files)[0];

  const lang = $('studio-codegen-lang')?.value || 'ts';
  const codeOutput = $('studio-generated-code');
  const genMutable = $('studio-opt-mutable')?.checked ?? true;
  const genObjectApi = $('studio-opt-object-api')?.checked ?? true;

  // Reset stored files
  lastGeneratedFiles = null;

  // Check if WASM flatc is available
  if (!state.flatcRunner) {
    if (codeOutput) codeOutput.value = '// Error: FlatBuffers WASM not initialized\n// Please wait for initialization to complete.';
    return;
  }

  try {
    const schemaInput = { entry: entryPoint, files };
    const options = {
      genMutable,
      genObjectApi,
    };

    let code = '';

    if (lang === 'jsonschema') {
      // Use generateJsonSchema for JSON Schema output
      code = state.flatcRunner.generateJsonSchema(schemaInput, { includeXFlatbuffers: true });
      lastGeneratedFiles = { 'schema.json': code };
    } else {
      // Use generateCode for all other languages
      const generatedFiles = state.flatcRunner.generateCode(schemaInput, lang, options);
      lastGeneratedFiles = generatedFiles;

      // Combine all generated files into output
      const fileList = Object.keys(generatedFiles);
      if (fileList.length === 0) {
        code = '// No code generated. Check your schema for errors.';
        lastGeneratedFiles = null;
      } else if (fileList.length === 1) {
        // Single file output
        code = generatedFiles[fileList[0]];
      } else {
        // Multiple files - show each with a header
        code = fileList.map(filename => {
          return `// ===== ${filename} =====\n\n${generatedFiles[filename]}`;
        }).join('\n\n');
      }
    }

    if (codeOutput) codeOutput.value = code;
  } catch (err) {
    console.error('Code generation error:', err);
    lastGeneratedFiles = null;
    if (codeOutput) {
      codeOutput.value = `// Error generating code:\n// ${err.message}\n\n// Make sure your schema is valid FlatBuffers IDL.`;
    }
  }
}

function fbsTypeToTS(type) {
  const map = {
    'bool': 'boolean',
    'byte': 'number',
    'ubyte': 'number',
    'short': 'number',
    'ushort': 'number',
    'int': 'number',
    'uint': 'number',
    'long': 'bigint',
    'ulong': 'bigint',
    'float': 'number',
    'double': 'number',
    'string': 'string',
  };
  if (type.startsWith('[') && type.endsWith(']')) {
    return fbsTypeToTS(type.slice(1, -1)) + '[]';
  }
  return map[type.toLowerCase()] || type;
}

function fbsTypeToJSONSchema(type) {
  const map = {
    'bool': 'boolean',
    'byte': 'integer',
    'ubyte': 'integer',
    'short': 'integer',
    'ushort': 'integer',
    'int': 'integer',
    'uint': 'integer',
    'long': 'integer',
    'ulong': 'integer',
    'float': 'number',
    'double': 'number',
    'string': 'string',
  };
  if (type.startsWith('[') && type.endsWith(']')) {
    return 'array';
  }
  return map[type.toLowerCase()] || 'object';
}

function buildStudioForm(tableName) {
  const table = studioState.tables.find(t => t.name === tableName);
  if (!table) return;

  const container = $('studio-builder-form');
  if (!container) return;

  let html = '';
  for (const field of table.fields) {
    html += `<div class="field-group">
      <div class="field-label">
        <span class="field-name">${field.name}</span>
        <span class="field-type">${field.type}</span>
      </div>
      ${getStudioFieldInput(field)}
    </div>`;
  }

  container.innerHTML = html;
}

function getStudioFieldInput(field) {
  const type = field.type.toLowerCase();
  const id = `studio-field-${field.name}`;

  if (type.startsWith('[') && type.endsWith(']')) {
    return `<textarea id="${id}" class="glass-input" rows="2" placeholder="One value per line"></textarea>`;
  }

  const enumType = studioState.enums.find(e => e.name === field.type);
  if (enumType) {
    const options = enumType.values.map(v => `<option value="${v.name}">${v.name}</option>`).join('');
    return `<select id="${id}" class="glass-select">${options}</select>`;
  }

  switch (type) {
    case 'bool':
      return `<select id="${id}" class="glass-select"><option value="false">false</option><option value="true">true</option></select>`;
    case 'string':
      return `<input type="text" id="${id}" class="glass-input" value="${field.default || ''}">`;
    default:
      return `<input type="number" id="${id}" class="glass-input" value="${field.default || ''}" step="any">`;
  }
}

function buildStudioBuffer() {
  const tableName = $('studio-builder-table')?.value;
  if (!tableName) {
    alert('Please select a table');
    return;
  }

  const table = studioState.tables.find(t => t.name === tableName);
  if (!table) return;

  const data = {};
  for (const field of table.fields) {
    const input = $(`studio-field-${field.name}`);
    if (input) data[field.name] = input.value;
  }

  const json = JSON.stringify(data, null, 2);
  const encoder = new TextEncoder();
  const buffer = encoder.encode(json);

  studioState.currentBuffer = buffer;
  displayStudioHexView(buffer);

  const decodedView = $('studio-decoded-view');
  if (decodedView) decodedView.textContent = json;

  const downloadBtn = $('studio-download-buffer');
  if (downloadBtn) downloadBtn.disabled = false;
}

function displayStudioHexView(buffer) {
  const container = $('studio-hex-view');
  if (!container) return;

  let html = '';
  for (let i = 0; i < buffer.length; i += 16) {
    const offset = i.toString(16).padStart(8, '0');
    const bytes = [];
    const ascii = [];

    for (let j = 0; j < 16; j++) {
      if (i + j < buffer.length) {
        bytes.push(buffer[i + j].toString(16).padStart(2, '0'));
        const char = buffer[i + j];
        ascii.push(char >= 32 && char < 127 ? String.fromCharCode(char) : '.');
      } else {
        bytes.push('  ');
        ascii.push(' ');
      }
    }

    html += `<div class="hex-line">
      <span class="hex-offset">${offset}</span>
      <span class="hex-bytes">${bytes.join(' ')}</span>
      <span class="hex-ascii">${ascii.join('')}</span>
    </div>`;
  }

  container.innerHTML = html || '<div class="empty-state">Build a buffer to see output</div>';
}

function clearStudioForm() {
  const container = $('studio-builder-form');
  if (container) {
    const inputs = container.querySelectorAll('input, select, textarea');
    inputs.forEach(input => { input.value = ''; });
  }
  studioState.currentBuffer = null;

  const hexView = $('studio-hex-view');
  if (hexView) hexView.innerHTML = '<div class="empty-state">Build a buffer to see output</div>';

  const decodedView = $('studio-decoded-view');
  if (decodedView) decodedView.innerHTML = '<div class="empty-state">Build or upload a buffer</div>';

  const downloadBtn = $('studio-download-buffer');
  if (downloadBtn) downloadBtn.disabled = true;
}

function downloadStudioBuffer() {
  if (!studioState.currentBuffer) return;
  const blob = new Blob([studioState.currentBuffer]);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'flatbuffer.bin';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function downloadTextFile(content, filename) {
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Simple ZIP file creator (no compression, store only)
async function createZipFromFiles(files) {
  const encoder = new TextEncoder();
  const fileEntries = [];
  let offset = 0;

  // Build file entries
  for (const [filename, content] of Object.entries(files)) {
    const nameBytes = encoder.encode(filename);
    const contentBytes = encoder.encode(content);
    const crc = crc32(contentBytes);

    fileEntries.push({
      name: nameBytes,
      content: contentBytes,
      crc,
      offset,
    });

    // Local file header (30 bytes + name + content)
    offset += 30 + nameBytes.length + contentBytes.length;
  }

  // Calculate total size
  const centralDirOffset = offset;
  let centralDirSize = 0;
  for (const entry of fileEntries) {
    centralDirSize += 46 + entry.name.length;
  }
  const totalSize = offset + centralDirSize + 22;

  // Create buffer
  const buffer = new ArrayBuffer(totalSize);
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);
  let pos = 0;

  // Write local file headers and content
  for (const entry of fileEntries) {
    // Local file header signature
    view.setUint32(pos, 0x04034b50, true); pos += 4;
    view.setUint16(pos, 20, true); pos += 2; // Version needed
    view.setUint16(pos, 0, true); pos += 2;  // Flags
    view.setUint16(pos, 0, true); pos += 2;  // Compression (store)
    view.setUint16(pos, 0, true); pos += 2;  // Mod time
    view.setUint16(pos, 0, true); pos += 2;  // Mod date
    view.setUint32(pos, entry.crc, true); pos += 4;
    view.setUint32(pos, entry.content.length, true); pos += 4; // Compressed size
    view.setUint32(pos, entry.content.length, true); pos += 4; // Uncompressed size
    view.setUint16(pos, entry.name.length, true); pos += 2;
    view.setUint16(pos, 0, true); pos += 2; // Extra field length

    bytes.set(entry.name, pos); pos += entry.name.length;
    bytes.set(entry.content, pos); pos += entry.content.length;
  }

  // Write central directory
  for (const entry of fileEntries) {
    view.setUint32(pos, 0x02014b50, true); pos += 4; // Central dir signature
    view.setUint16(pos, 20, true); pos += 2; // Version made by
    view.setUint16(pos, 20, true); pos += 2; // Version needed
    view.setUint16(pos, 0, true); pos += 2;  // Flags
    view.setUint16(pos, 0, true); pos += 2;  // Compression
    view.setUint16(pos, 0, true); pos += 2;  // Mod time
    view.setUint16(pos, 0, true); pos += 2;  // Mod date
    view.setUint32(pos, entry.crc, true); pos += 4;
    view.setUint32(pos, entry.content.length, true); pos += 4;
    view.setUint32(pos, entry.content.length, true); pos += 4;
    view.setUint16(pos, entry.name.length, true); pos += 2;
    view.setUint16(pos, 0, true); pos += 2; // Extra field length
    view.setUint16(pos, 0, true); pos += 2; // Comment length
    view.setUint16(pos, 0, true); pos += 2; // Disk number
    view.setUint16(pos, 0, true); pos += 2; // Internal attrs
    view.setUint32(pos, 0, true); pos += 4;  // External attrs
    view.setUint32(pos, entry.offset, true); pos += 4;

    bytes.set(entry.name, pos); pos += entry.name.length;
  }

  // End of central directory
  view.setUint32(pos, 0x06054b50, true); pos += 4;
  view.setUint16(pos, 0, true); pos += 2; // Disk number
  view.setUint16(pos, 0, true); pos += 2; // Central dir disk
  view.setUint16(pos, fileEntries.length, true); pos += 2;
  view.setUint16(pos, fileEntries.length, true); pos += 2;
  view.setUint32(pos, centralDirSize, true); pos += 4;
  view.setUint32(pos, centralDirOffset, true); pos += 4;
  view.setUint16(pos, 0, true); // Comment length

  return buffer;
}

// CRC32 for ZIP
function crc32(data) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
    }
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

async function downloadFile(path, filename) {
  try {
    const response = await fetch(path);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (err) {
    console.error('Download failed:', err);
    alert('Download failed: ' + err.message);
  }
}

// =============================================================================
// Schema Builder Functions
// =============================================================================

function initSchemaBuilder() {
  // Add button dropdown toggle
  const addBtn = $('builder-add-btn');
  const addMenu = $('builder-add-menu');

  if (addBtn && addMenu) {
    addBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      addMenu.style.display = addMenu.style.display === 'none' ? 'block' : 'none';
    });

    // Close menu when clicking outside
    document.addEventListener('click', () => {
      addMenu.style.display = 'none';
    });

    // Add item buttons
    addMenu.querySelectorAll('button').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const itemType = btn.dataset.itemType;
        addSchemaItem(itemType);
        addMenu.style.display = 'none';
      });
    });
  }

  // Namespace input
  const namespaceInput = $('builder-namespace');
  if (namespaceInput) {
    namespaceInput.addEventListener('input', (e) => {
      schemaBuilder.namespace = e.target.value;
      renderBuilderPreview();
    });
  }

  // Root type selector
  const rootTypeSelect = $('builder-root-type');
  if (rootTypeSelect) {
    rootTypeSelect.addEventListener('change', (e) => {
      schemaBuilder.rootType = e.target.value;
      renderBuilderPreview();
    });
  }

  // File identifier input (4 characters exactly)
  const fileIdentifierInput = $('builder-file-identifier');
  if (fileIdentifierInput) {
    fileIdentifierInput.addEventListener('input', (e) => {
      // Limit to 4 characters
      let val = e.target.value.slice(0, 4);
      e.target.value = val;
      schemaBuilder.fileIdentifier = val;
      renderBuilderPreview();
    });
  }

  // File extension input
  const fileExtensionInput = $('builder-file-extension');
  if (fileExtensionInput) {
    fileExtensionInput.addEventListener('input', (e) => {
      // Remove leading dot if present
      let val = e.target.value.replace(/^\./, '');
      e.target.value = val;
      schemaBuilder.fileExtension = val;
      renderBuilderPreview();
    });
  }

  // Includes textarea
  const includesInput = $('builder-includes');
  if (includesInput) {
    includesInput.addEventListener('input', (e) => {
      // Split by newlines, filter empty lines
      schemaBuilder.includes = e.target.value.split('\n').filter(line => line.trim());
      renderBuilderPreview();
    });
  }

  // Custom attributes textarea
  const attributesInput = $('builder-attributes');
  if (attributesInput) {
    attributesInput.addEventListener('input', (e) => {
      // Split by newlines, filter empty lines
      schemaBuilder.attributes = e.target.value.split('\n').filter(line => line.trim());
      renderBuilderPreview();
    });
  }

  // Preview format toggle
  const fbsToggle = $('builder-preview-fbs');
  const jsonToggle = $('builder-preview-json');

  if (fbsToggle) {
    fbsToggle.addEventListener('click', () => {
      schemaBuilder.previewFormat = 'fbs';
      fbsToggle.classList.add('active');
      jsonToggle?.classList.remove('active');
      renderBuilderPreview();
    });
  }

  if (jsonToggle) {
    jsonToggle.addEventListener('click', () => {
      schemaBuilder.previewFormat = 'json';
      jsonToggle.classList.add('active');
      fbsToggle?.classList.remove('active');
      renderBuilderPreview();
    });
  }

  // Copy button
  const copyBtn = $('builder-copy-code');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      const preview = $('builder-preview-code');
      if (preview) {
        navigator.clipboard.writeText(preview.textContent);
        copyBtn.textContent = 'Copied!';
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
      }
    });
  }

  // Export to Editor button
  const exportBtn = $('builder-export-editor');
  if (exportBtn) {
    exportBtn.addEventListener('click', exportToSchemaEditor);
  }
}

function addSchemaItem(type) {
  let name = `New${type.charAt(0).toUpperCase() + type.slice(1)}`;
  let counter = 1;
  while (schemaBuilder.items.some(i => i.name === name)) {
    name = `New${type.charAt(0).toUpperCase() + type.slice(1)}${counter++}`;
  }

  const item = { type, name, doc: '' };  // All items can have documentation

  if (type === 'table') {
    item.fields = [];
  } else if (type === 'enum') {
    item.baseType = 'int';  // Use canonical FlatBuffers type name
    item.values = [{ name: 'Value0', value: 0, doc: '' }];
  } else if (type === 'struct') {
    item.fields = [];
    item.forceAlign = null;  // Optional force_align for structs
  } else if (type === 'union') {
    item.members = [];
  } else if (type === 'rpc') {
    item.methods = [];
  }

  schemaBuilder.items.push(item);
  schemaBuilder.selectedIndex = schemaBuilder.items.length - 1;

  // Auto-set root_type to first table if not already set
  if (type === 'table' && !schemaBuilder.rootType) {
    schemaBuilder.rootType = item.name;
  }

  renderBuilderItemList();
  renderBuilderEditor();
  renderBuilderPreview();
  updateRootTypeSelector();
}

function deleteSchemaItem(index) {
  const item = schemaBuilder.items[index];
  if (!confirm(`Delete ${item.type} "${item.name}"?`)) return;

  schemaBuilder.items.splice(index, 1);

  if (schemaBuilder.selectedIndex === index) {
    schemaBuilder.selectedIndex = -1;
  } else if (schemaBuilder.selectedIndex > index) {
    schemaBuilder.selectedIndex--;
  }

  // Clear root type if deleted
  if (schemaBuilder.rootType === item.name) {
    schemaBuilder.rootType = '';
  }

  renderBuilderItemList();
  renderBuilderEditor();
  renderBuilderPreview();
  updateRootTypeSelector();
}

function selectSchemaItem(index) {
  schemaBuilder.selectedIndex = index;
  renderBuilderItemList();
  renderBuilderEditor();
}

function renderBuilderItemList() {
  const container = $('builder-item-list');
  if (!container) return;

  if (schemaBuilder.items.length === 0) {
    container.innerHTML = '<div class="empty-state">Add a table, enum, or struct to begin</div>';
    return;
  }

  container.innerHTML = schemaBuilder.items.map((item, index) => `
    <div class="builder-item ${index === schemaBuilder.selectedIndex ? 'selected' : ''}" data-index="${index}">
      <span class="builder-item-icon ${item.type}">${item.type.charAt(0).toUpperCase()}</span>
      <span class="builder-item-name">${item.name}</span>
      <button class="builder-item-delete" data-index="${index}" title="Delete">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="18" y1="6" x2="6" y2="18"></line>
          <line x1="6" y1="6" x2="18" y2="18"></line>
        </svg>
      </button>
    </div>
  `).join('');

  // Add click handlers
  container.querySelectorAll('.builder-item').forEach(el => {
    el.addEventListener('click', (e) => {
      if (!e.target.closest('.builder-item-delete')) {
        selectSchemaItem(parseInt(el.dataset.index));
      }
    });
  });

  container.querySelectorAll('.builder-item-delete').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      deleteSchemaItem(parseInt(btn.dataset.index));
    });
  });
}

function renderBuilderEditor() {
  const container = $('builder-editor-content');
  const title = $('builder-editor-title');
  if (!container) return;

  if (schemaBuilder.selectedIndex < 0 || schemaBuilder.selectedIndex >= schemaBuilder.items.length) {
    container.innerHTML = '<div class="empty-state">Select an item to edit</div>';
    if (title) title.textContent = 'Item Editor';
    return;
  }

  const item = schemaBuilder.items[schemaBuilder.selectedIndex];
  if (title) title.textContent = `Edit ${item.type.charAt(0).toUpperCase() + item.type.slice(1)}`;

  let html = `
    <div class="builder-item-header">
      <input type="text" class="glass-input" id="builder-item-name" value="${escapeHtml(item.name)}" placeholder="Name">
      <span class="builder-item-type-badge ${item.type}">${item.type}</span>
    </div>
    <div class="builder-item-doc">
      <textarea class="glass-input builder-doc-input" id="builder-item-doc" placeholder="Documentation comment (/// in FBS)" rows="2">${escapeHtml(item.doc || '')}</textarea>
    </div>
  `;

  if (item.type === 'table' || item.type === 'struct') {
    html += renderFieldEditor(item);
  } else if (item.type === 'enum') {
    html += renderEnumEditor(item);
  } else if (item.type === 'union') {
    html += renderUnionEditor(item);
  } else if (item.type === 'rpc') {
    html += renderRPCEditor(item);
  }

  container.innerHTML = html;
  attachEditorListeners(item);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function renderFieldEditor(item) {
  const isStruct = item.type === 'struct';
  const availableTypes = getAvailableTypes(isStruct);

  let html = '<div class="builder-field-list">';

  if (item.fields.length === 0) {
    html += '<div class="empty-state" style="min-height: 100px;">No fields yet. Add a field below.</div>';
  } else {
    html += item.fields.map((field, index) => {
      // Normalize field type first (convert aliases to canonical names if needed)
      if (TYPE_ALIASES[field.fieldType]) {
        field.fieldType = TYPE_ALIASES[field.fieldType];
      }
      // If type is not in available types, default to 'int'
      if (!availableTypes.includes(field.fieldType)) {
        field.fieldType = 'int';
      }

      // Now determine field characteristics based on normalized type
      const isVector = field.fieldType.startsWith('[') && field.fieldType.endsWith(']');
      const isString = field.fieldType === 'string';
      const isReference = schemaBuilder.items.some(i => i.name === field.fieldType && (i.type === 'table' || i.type === 'struct'));
      // Scalars can have defaults; use "null" for optional scalars
      const canHaveDefault = !isVector && !isString && !isReference;

      return `
      <div class="builder-field-row" data-field-index="${index}">
        <div class="builder-field-cell">
          <input type="text" class="glass-input builder-field-name" value="${escapeHtml(field.name)}" placeholder="Field name">
          <span class="field-label">name</span>
        </div>
        <div class="builder-field-cell">
          <select class="glass-select builder-field-type">
            ${availableTypes.map(t => `<option value="${escapeHtml(t)}" ${field.fieldType === t ? 'selected' : ''}>${escapeHtml(t)}</option>`).join('')}
          </select>
          <span class="field-label">type</span>
        </div>
        ${!isStruct ? `
          <div class="builder-field-cell">
            <input type="text" class="glass-input builder-field-default" value="${escapeHtml(field.default || '')}" placeholder="${canHaveDefault ? '0' : 'N/A'}" ${canHaveDefault ? '' : 'disabled'}>
            <span class="field-label">default</span>
          </div>
          <div class="builder-field-cell">
            <input type="number" class="glass-input builder-field-id" value="${field.id !== undefined && field.id !== null ? field.id : ''}" placeholder="#" min="0">
            <span class="field-label">id</span>
          </div>
          <div class="builder-field-attrs">
            <label class="builder-field-attr" title="Mark field as key (sorting)">
              <input type="checkbox" ${field.key ? 'checked' : ''} data-prop="key">
              key
            </label>
            <label class="builder-field-attr" title="Field is required (non-scalar only)">
              <input type="checkbox" ${field.required ? 'checked' : ''} data-prop="required">
              req
            </label>
            <label class="builder-field-attr" title="Field is deprecated">
              <input type="checkbox" ${field.deprecated ? 'checked' : ''} data-prop="deprecated">
              dep
            </label>
          </div>
        ` : `
          <div class="builder-field-cell">
            <input type="number" class="glass-input builder-field-force-align" value="${field.forceAlign || ''}" placeholder="1" min="1">
            <span class="field-label">align</span>
          </div>
          <div></div>
          <div></div>
        `}
        <button class="builder-field-delete" data-field-index="${index}" title="Delete field">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18"></line>
            <line x1="6" y1="6" x2="18" y2="18"></line>
          </svg>
        </button>
      </div>
      <div class="builder-field-doc-row" data-field-index="${index}">
        <input type="text" class="glass-input builder-field-doc" value="${escapeHtml(field.doc || '')}" placeholder="Field documentation (optional)">
      </div>
    `}).join('');
  }

  html += '</div>';
  html += `
    <button class="glass-btn small builder-add-field">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <line x1="12" y1="5" x2="12" y2="19"></line>
        <line x1="5" y1="12" x2="19" y2="12"></line>
      </svg>
      Add Field
    </button>
  `;

  return html;
}

function renderEnumEditor(item) {
  let html = `
    <div class="builder-enum-config">
      <div class="glass-input-group">
        <label>Base Type</label>
        <select class="glass-select" id="builder-enum-base-type">
          ${ENUM_BASE_TYPES.map(t => `<option value="${t}" ${item.baseType === t ? 'selected' : ''}>${t}</option>`).join('')}
        </select>
      </div>
    </div>
    <label style="display: block; margin-bottom: 8px; font-size: 13px; color: var(--white-60);">Values</label>
    <div class="builder-enum-values">
  `;

  if (item.values.length === 0) {
    html += '<div class="empty-state" style="min-height: 80px;">No values yet. Add a value below.</div>';
  } else {
    html += item.values.map((val, index) => `
      <div class="builder-enum-row" data-value-index="${index}">
        <input type="text" class="glass-input" value="${val.name}" placeholder="Name" data-prop="name">
        <input type="number" class="glass-input" value="${val.value}" placeholder="Value" data-prop="value">
        <button class="builder-field-delete" data-value-index="${index}" title="Delete value">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18"></line>
            <line x1="6" y1="6" x2="18" y2="18"></line>
          </svg>
        </button>
      </div>
    `).join('');
  }

  html += '</div>';
  html += `
    <button class="glass-btn small builder-add-field" style="margin-top: 12px;">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <line x1="12" y1="5" x2="12" y2="19"></line>
        <line x1="5" y1="12" x2="19" y2="12"></line>
      </svg>
      Add Value
    </button>
  `;

  return html;
}

function renderUnionEditor(item) {
  const tables = schemaBuilder.items.filter(i => i.type === 'table');

  let html = `
    <label style="display: block; margin-bottom: 8px; font-size: 13px; color: var(--white-60);">Member Tables</label>
    <div class="builder-union-members">
  `;

  if (item.members.length === 0) {
    html += '<div class="empty-state" style="min-height: 80px;">No members yet. Add a table reference below.</div>';
  } else {
    html += item.members.map((member, index) => `
      <div class="builder-union-row" data-member-index="${index}">
        <select class="glass-select" data-prop="member">
          <option value="">Select table...</option>
          ${tables.map(t => `<option value="${t.name}" ${member === t.name ? 'selected' : ''}>${t.name}</option>`).join('')}
        </select>
        <button class="builder-field-delete" data-member-index="${index}" title="Delete member">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18"></line>
            <line x1="6" y1="6" x2="18" y2="18"></line>
          </svg>
        </button>
      </div>
    `).join('');
  }

  html += '</div>';
  html += `
    <button class="glass-btn small builder-add-field" style="margin-top: 12px;" ${tables.length === 0 ? 'disabled' : ''}>
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <line x1="12" y1="5" x2="12" y2="19"></line>
        <line x1="5" y1="12" x2="19" y2="12"></line>
      </svg>
      Add Member
    </button>
    ${tables.length === 0 ? '<p style="font-size: 12px; color: var(--white-40); margin-top: 8px;">Create a table first to add union members.</p>' : ''}
  `;

  return html;
}

function renderRPCEditor(item) {
  const tables = schemaBuilder.items.filter(i => i.type === 'table');

  let html = `
    <label style="display: block; margin-bottom: 8px; font-size: 13px; color: var(--white-60);">RPC Methods</label>
    <div class="builder-rpc-methods">
  `;

  if (!item.methods || item.methods.length === 0) {
    html += '<div class="empty-state" style="min-height: 80px;">No methods yet. Add an RPC method below.</div>';
  } else {
    html += item.methods.map((method, index) => `
      <div class="builder-rpc-row" data-method-index="${index}">
        <div class="builder-rpc-method-line">
          <input type="text" class="glass-input builder-rpc-name" value="${escapeHtml(method.name || '')}" placeholder="MethodName" data-prop="name">
          <span class="rpc-syntax">(</span>
          <select class="glass-select builder-rpc-request" data-prop="request">
            <option value="">Request...</option>
            ${tables.map(t => `<option value="${t.name}" ${method.request === t.name ? 'selected' : ''}>${t.name}</option>`).join('')}
          </select>
          <span class="rpc-syntax">):</span>
          <select class="glass-select builder-rpc-response" data-prop="response">
            <option value="">Response...</option>
            ${tables.map(t => `<option value="${t.name}" ${method.response === t.name ? 'selected' : ''}>${t.name}</option>`).join('')}
          </select>
          <label class="builder-field-attr" title="Enable server-side streaming">
            <input type="checkbox" ${method.streaming ? 'checked' : ''} data-prop="streaming">
            stream
          </label>
          <button class="builder-field-delete" data-method-index="${index}" title="Delete method">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>
        <input type="text" class="glass-input builder-rpc-doc" value="${escapeHtml(method.doc || '')}" placeholder="Method documentation (optional)">
      </div>
    `).join('');
  }

  html += '</div>';
  html += `
    <button class="glass-btn small builder-add-field" style="margin-top: 12px;" ${tables.length === 0 ? 'disabled' : ''}>
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <line x1="12" y1="5" x2="12" y2="19"></line>
        <line x1="5" y1="12" x2="19" y2="12"></line>
      </svg>
      Add Method
    </button>
    ${tables.length === 0 ? '<p style="font-size: 12px; color: var(--white-40); margin-top: 8px;">Create request/response tables first.</p>' : ''}
  `;

  return html;
}

function attachEditorListeners(item) {
  const index = schemaBuilder.selectedIndex;

  // Item name
  const nameInput = $('builder-item-name');
  if (nameInput) {
    nameInput.addEventListener('input', (e) => {
      item.name = e.target.value;
      renderBuilderItemList();
      renderBuilderPreview();
      updateRootTypeSelector();
    });
  }

  // Item documentation
  const docInput = $('builder-item-doc');
  if (docInput) {
    docInput.addEventListener('input', (e) => {
      item.doc = e.target.value;
      renderBuilderPreview();
    });
  }

  // Add field/value/member button
  const addBtn = document.querySelector('.builder-add-field');
  if (addBtn) {
    addBtn.addEventListener('click', () => {
      if (item.type === 'table' || item.type === 'struct') {
        item.fields.push({
          name: `field${item.fields.length}`,
          fieldType: 'int',  // Use canonical FlatBuffers type name
          default: '',       // Use "null" for optional scalars
          id: null,         // Field ID for explicit ordering
          key: false,       // Sorting key
          required: false,
          deprecated: false,
          doc: '',          // Documentation comment (///)
          forceAlign: null, // Force alignment (structs only)
          flexbuffer: false, // FlexBuffer attribute
          nestedFlatbuffer: '', // Nested flatbuffer type name
        });
      } else if (item.type === 'enum') {
        const nextVal = item.values.length > 0 ? Math.max(...item.values.map(v => v.value)) + 1 : 0;
        item.values.push({ name: `Value${item.values.length}`, value: nextVal, doc: '' });
      } else if (item.type === 'union') {
        item.members.push('');
      } else if (item.type === 'rpc') {
        item.methods.push({
          name: `Method${item.methods.length}`,
          request: '',
          response: '',
          streaming: false,
          doc: '',
        });
      }
      renderBuilderEditor();
      renderBuilderPreview();
    });
  }

  // Field inputs
  document.querySelectorAll('.builder-field-row').forEach(row => {
    const fieldIndex = parseInt(row.dataset.fieldIndex);
    const field = item.fields[fieldIndex];
    if (!field) return;

    const nameInput = row.querySelector('input.builder-field-name');
    const typeSelect = row.querySelector('select.builder-field-type');
    const defaultInput = row.querySelector('input.builder-field-default');

    // Name input handler
    if (nameInput) {
      nameInput.addEventListener('input', () => {
        field.name = nameInput.value;
        renderBuilderPreview();
      });
    }

    // Type select handler
    if (typeSelect) {
      typeSelect.addEventListener('change', () => {
        field.fieldType = typeSelect.value;
        // Update default input state based on new type
        if (defaultInput) {
          const isVector = field.fieldType.startsWith('[') && field.fieldType.endsWith(']');
          const isString = field.fieldType === 'string';
          const isReference = schemaBuilder.items.some(i => i.name === field.fieldType && (i.type === 'table' || i.type === 'struct'));
          const canHaveDefault = !isVector && !isString && !isReference;
          defaultInput.disabled = !canHaveDefault;
          if (!canHaveDefault) {
            defaultInput.value = '';
            defaultInput.placeholder = 'N/A';
            defaultInput.classList.remove('input-error');
            defaultInput.title = 'N/A';
            field.default = '';
          } else {
            defaultInput.placeholder = 'Default';
            // Re-validate existing default value against new type
            if (field.default) {
              const validation = validateDefaultValue(field.default, field.fieldType);
              if (!validation.valid) {
                defaultInput.classList.add('input-error');
                defaultInput.title = validation.error || 'Invalid default value';
              } else {
                defaultInput.classList.remove('input-error');
                defaultInput.title = 'Default value';
              }
            }
          }
        }
        renderBuilderPreview();
      });
    }

    // Default input handler with type validation
    if (defaultInput) {
      defaultInput.addEventListener('input', () => {
        field.default = defaultInput.value;

        // Validate the default value against the field type
        const validation = validateDefaultValue(defaultInput.value, field.fieldType);
        if (!validation.valid) {
          defaultInput.classList.add('input-error');
          defaultInput.title = validation.error || 'Invalid default value';
        } else {
          defaultInput.classList.remove('input-error');
          defaultInput.title = 'Default value';
        }

        renderBuilderPreview();
      });
    }

    // Field ID input handler
    const idInput = row.querySelector('input.builder-field-id');
    if (idInput) {
      idInput.addEventListener('input', () => {
        const val = idInput.value.trim();
        const newId = val === '' ? null : parseInt(val, 10);

        // Check for duplicate ID
        if (newId !== null) {
          const duplicate = item.fields.some((f, i) => i !== fieldIndex && f.id === newId);
          if (duplicate) {
            idInput.classList.add('input-error');
            idInput.title = `ID ${newId} is already used by another field`;
            return; // Don't update the field
          }
        }

        idInput.classList.remove('input-error');
        idInput.title = 'Field ID (for explicit ordering)';
        field.id = newId;
        renderBuilderPreview();
      });
    }

    // Checkbox handlers (key, required, deprecated, optional)
    row.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
      const prop = checkbox.dataset.prop;
      if (!prop) return;
      checkbox.addEventListener('change', () => {
        field[prop] = checkbox.checked;
        renderBuilderPreview();
      });
    });

    // Force align input for struct fields
    const forceAlignInput = row.querySelector('input.builder-field-force-align');
    if (forceAlignInput) {
      forceAlignInput.addEventListener('input', () => {
        const val = forceAlignInput.value.trim();
        field.forceAlign = val === '' ? null : parseInt(val, 10);
        renderBuilderPreview();
      });
    }
  });

  // Field documentation inputs
  document.querySelectorAll('.builder-field-doc-row').forEach(row => {
    const fieldIndex = parseInt(row.dataset.fieldIndex);
    const field = item.fields?.[fieldIndex];
    if (!field) return;

    const docInput = row.querySelector('input.builder-field-doc');
    if (docInput) {
      docInput.addEventListener('input', () => {
        field.doc = docInput.value;
        renderBuilderPreview();
      });
    }
  });

  // Field delete buttons
  document.querySelectorAll('.builder-field-row .builder-field-delete').forEach(btn => {
    btn.addEventListener('click', () => {
      const fieldIndex = parseInt(btn.dataset.fieldIndex);
      item.fields.splice(fieldIndex, 1);
      renderBuilderEditor();
      renderBuilderPreview();
    });
  });

  // Enum base type
  const enumBaseType = $('builder-enum-base-type');
  if (enumBaseType) {
    enumBaseType.addEventListener('change', (e) => {
      item.baseType = e.target.value;
      renderBuilderPreview();
    });
  }

  // Enum value inputs
  document.querySelectorAll('.builder-enum-row').forEach(row => {
    const valueIndex = parseInt(row.dataset.valueIndex);

    row.querySelectorAll('input').forEach(input => {
      const prop = input.dataset.prop;
      if (!prop) return;

      input.addEventListener('input', () => {
        if (prop === 'value') {
          item.values[valueIndex][prop] = parseInt(input.value) || 0;
        } else {
          item.values[valueIndex][prop] = input.value;
        }
        renderBuilderPreview();
      });
    });
  });

  // Enum value delete buttons
  document.querySelectorAll('.builder-enum-row .builder-field-delete').forEach(btn => {
    btn.addEventListener('click', () => {
      const valueIndex = parseInt(btn.dataset.valueIndex);
      item.values.splice(valueIndex, 1);
      renderBuilderEditor();
      renderBuilderPreview();
    });
  });

  // Union member selects
  document.querySelectorAll('.builder-union-row select').forEach(select => {
    const memberIndex = parseInt(select.closest('.builder-union-row').dataset.memberIndex);
    select.addEventListener('change', () => {
      item.members[memberIndex] = select.value;
      renderBuilderPreview();
    });
  });

  // Union member delete buttons
  document.querySelectorAll('.builder-union-row .builder-field-delete').forEach(btn => {
    btn.addEventListener('click', () => {
      const memberIndex = parseInt(btn.dataset.memberIndex);
      item.members.splice(memberIndex, 1);
      renderBuilderEditor();
      renderBuilderPreview();
    });
  });

  // RPC method inputs
  document.querySelectorAll('.builder-rpc-row').forEach(row => {
    const methodIndex = parseInt(row.dataset.methodIndex);
    const method = item.methods?.[methodIndex];
    if (!method) return;

    // Name input
    const nameInput = row.querySelector('input.builder-rpc-name');
    if (nameInput) {
      nameInput.addEventListener('input', () => {
        method.name = nameInput.value;
        renderBuilderPreview();
      });
    }

    // Request select
    const requestSelect = row.querySelector('select.builder-rpc-request');
    if (requestSelect) {
      requestSelect.addEventListener('change', () => {
        method.request = requestSelect.value;
        renderBuilderPreview();
      });
    }

    // Response select
    const responseSelect = row.querySelector('select.builder-rpc-response');
    if (responseSelect) {
      responseSelect.addEventListener('change', () => {
        method.response = responseSelect.value;
        renderBuilderPreview();
      });
    }

    // Streaming checkbox
    const streamCheckbox = row.querySelector('input[data-prop="streaming"]');
    if (streamCheckbox) {
      streamCheckbox.addEventListener('change', () => {
        method.streaming = streamCheckbox.checked;
        renderBuilderPreview();
      });
    }

    // Documentation input
    const docInput = row.querySelector('input.builder-rpc-doc');
    if (docInput) {
      docInput.addEventListener('input', () => {
        method.doc = docInput.value;
        renderBuilderPreview();
      });
    }
  });

  // RPC method delete buttons
  document.querySelectorAll('.builder-rpc-row .builder-field-delete').forEach(btn => {
    btn.addEventListener('click', () => {
      const methodIndex = parseInt(btn.dataset.methodIndex);
      item.methods.splice(methodIndex, 1);
      renderBuilderEditor();
      renderBuilderPreview();
    });
  });
}

function getAvailableTypes(structOnly = false) {
  const types = [...SCALAR_TYPES];

  // Add defined enums, structs, and tables
  for (const item of schemaBuilder.items) {
    if (item.type === 'enum' || item.type === 'struct') {
      types.push(item.name);
    } else if (item.type === 'table' && !structOnly) {
      types.push(item.name);
    }
  }

  // Add vector types (only for tables, not structs)
  if (!structOnly) {
    const vectorTypes = [...SCALAR_TYPES];
    for (const item of schemaBuilder.items) {
      if (item.type === 'enum' || item.type === 'struct' || item.type === 'table') {
        vectorTypes.push(item.name);
      }
    }
    vectorTypes.forEach(t => types.push(`[${t}]`));
  }

  return types;
}

function updateRootTypeSelector() {
  const select = $('builder-root-type');
  const group = $('builder-root-type-group');
  if (!select) return;

  const tables = schemaBuilder.items.filter(i => i.type === 'table');

  // Show/hide the root type selector based on whether tables exist
  if (group) {
    group.style.display = tables.length > 0 ? 'block' : 'none';
  }

  select.innerHTML = '<option value="">Select root type...</option>' +
    tables.map(t => `<option value="${t.name}" ${schemaBuilder.rootType === t.name ? 'selected' : ''}>${t.name}</option>`).join('');
}

// Helper to format documentation comments
function formatDoc(doc, indent = '') {
  if (!doc) return '';
  return doc.split('\n').map(line => `${indent}/// ${line}`).join('\n') + '\n';
}

function generateFBSFromBuilder() {
  const { namespace, rootType, fileIdentifier, fileExtension, includes, attributes, services, items } = schemaBuilder;
  let output = '';

  // Include statements first
  if (includes && includes.length > 0) {
    for (const inc of includes) {
      if (inc.trim()) {
        output += `include "${inc.trim()}";\n`;
      }
    }
    output += '\n';
  }

  // Namespace
  if (namespace) {
    output += `namespace ${namespace};\n\n`;
  }

  // Custom attribute declarations
  if (attributes && attributes.length > 0) {
    for (const attr of attributes) {
      if (attr.trim()) {
        output += `attribute "${attr.trim()}";\n`;
      }
    }
    output += '\n';
  }

  // Enums first
  for (const item of items.filter(i => i.type === 'enum')) {
    if (item.doc) output += formatDoc(item.doc);
    output += `enum ${item.name} : ${item.baseType} {\n`;
    output += item.values.map(v => {
      let line = '';
      if (v.doc) line += formatDoc(v.doc, '  ');
      line += `  ${v.name} = ${v.value}`;
      return line;
    }).join(',\n');
    output += '\n}\n\n';
  }

  // Structs (fields use "name: type;" format with space after colon)
  for (const item of items.filter(i => i.type === 'struct')) {
    if (item.doc) output += formatDoc(item.doc);
    // Struct metadata (force_align)
    let structMeta = '';
    if (item.forceAlign && item.forceAlign > 1) {
      structMeta = ` (force_align: ${item.forceAlign})`;
    }
    output += `struct ${item.name}${structMeta} {\n`;
    for (const f of item.fields) {
      if (f.doc) output += formatDoc(f.doc, '  ');
      let line = `  ${f.name}: ${f.fieldType}`;
      // Struct field can have force_align
      if (f.forceAlign && f.forceAlign > 1) {
        line += ` (force_align: ${f.forceAlign})`;
      }
      line += ';';
      output += line + '\n';
    }
    output += '}\n\n';
  }

  // Unions
  for (const item of items.filter(i => i.type === 'union')) {
    if (item.doc) output += formatDoc(item.doc);
    const validMembers = item.members.filter(m => m);
    if (validMembers.length > 0) {
      output += `union ${item.name} { ${validMembers.join(', ')} }\n\n`;
    }
  }

  // Tables
  for (const item of items.filter(i => i.type === 'table')) {
    if (item.doc) output += formatDoc(item.doc);
    output += `table ${item.name} {\n`;
    for (const f of item.fields) {
      if (f.doc) output += formatDoc(f.doc, '  ');
      let line = `  ${f.name}: ${f.fieldType}`;
      // Only scalar types and enums can have defaults (not vectors, strings, tables, or structs)
      // Per FlatBuffers spec: "Only scalar values can have explicit defaults"
      const isVector = f.fieldType.startsWith('[') && f.fieldType.endsWith(']');
      const isFixedArray = /^\[.+:\d+\]$/.test(f.fieldType);  // [type:N] syntax
      const isString = f.fieldType === 'string';
      const isReference = schemaBuilder.items.some(i => i.name === f.fieldType && (i.type === 'table' || i.type === 'struct'));
      const isEnum = schemaBuilder.items.some(i => i.name === f.fieldType && i.type === 'enum');

      if (f.default && !isVector && !isFixedArray && !isString && !isReference) {
        // Validate the default value based on type
        const val = f.default.trim();
        let validDefault = null;

        if (isEnum) {
          // Enum defaults are identifiers (e.g., Blue, Red)
          if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(val)) {
            validDefault = val;
          }
        } else if (f.fieldType === 'bool') {
          if (val === 'true' || val === 'false') {
            validDefault = val;
          }
        } else if (f.fieldType === 'float' || f.fieldType === 'double' ||
                   f.fieldType === 'float32' || f.fieldType === 'float64') {
          if (/^-?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(val) || val === 'inf' || val === '-inf' || val === 'nan') {
            validDefault = val;
          }
        } else {
          // Integer types (canonical and aliases)
          if (/^-?\d+$/.test(val)) {
            validDefault = val;
          }
        }

        if (validDefault !== null) {
          line += ` = ${validDefault}`;
        }
      }

      // Handle "= null" for optional scalars (user types "null" in default field)
      if (f.default && f.default.trim().toLowerCase() === 'null' && !isVector && !isFixedArray && !isString && !isReference) {
        line += ` = null`;
      }

      // Build field attributes (only valid FlatBuffers attributes)
      const attrs = [];
      if (typeof f.id === 'number') attrs.push(`id: ${f.id}`);
      if (f.key) attrs.push('key');
      if (f.required) attrs.push('required');
      if (f.deprecated) attrs.push('deprecated');
      if (f.flexbuffer) attrs.push('flexbuffer');
      if (f.nestedFlatbuffer) attrs.push(`nested_flatbuffer: "${f.nestedFlatbuffer}"`);
      if (attrs.length > 0) line += ` (${attrs.join(', ')})`;
      line += ';';
      output += line + '\n';
    }
    output += '}\n\n';
  }

  // RPC Services
  if (services && services.length > 0) {
    for (const svc of services) {
      if (!svc.name) continue;
      if (svc.doc) output += formatDoc(svc.doc);
      output += `rpc_service ${svc.name} {\n`;
      for (const method of (svc.methods || [])) {
        if (!method.name || !method.request || !method.response) continue;
        if (method.doc) output += formatDoc(method.doc, '  ');
        let methodAttrs = '';
        if (method.streaming) {
          methodAttrs = ' (streaming: "server")';
        }
        output += `  ${method.name}(${method.request}): ${method.response}${methodAttrs};\n`;
      }
      output += '}\n\n';
    }
  }

  // root_type is required for valid FlatBuffers schema
  // Default to first table if not explicitly set
  const tables = items.filter(i => i.type === 'table');
  const effectiveRootType = rootType || (tables.length > 0 ? tables[0].name : '');
  if (effectiveRootType) {
    output += `root_type ${effectiveRootType};\n`;
  }

  // File identifier (must be exactly 4 characters)
  if (fileIdentifier && fileIdentifier.length === 4) {
    output += `file_identifier "${fileIdentifier}";\n`;
  }

  // File extension (without leading dot)
  if (fileExtension) {
    output += `file_extension "${fileExtension}";\n`;
  }

  return output || '// Add tables, enums, or structs to generate schema';
}

function generateJSONSchemaFromBuilder() {
  // Generate FBS first, then use the official WASM to convert to JSON Schema
  const fbs = generateFBSFromBuilder();

  // If no valid FBS content, return placeholder
  if (!fbs || fbs.startsWith('//')) {
    return '// Add tables, enums, or structs to generate JSON Schema';
  }

  // Check if flatcRunner is available
  if (!state.flatcRunner) {
    return JSON.stringify({ error: 'FlatBuffers WASM not initialized' }, null, 2);
  }

  try {
    const jsonSchema = state.flatcRunner.generateJsonSchema(
      { entry: 'schema.fbs', files: { 'schema.fbs': fbs } },
      { includeXFlatbuffers: true }
    );
    return jsonSchema;
  } catch (err) {
    // If WASM fails (e.g., invalid FBS syntax), show the error
    return JSON.stringify({ error: err.message }, null, 2);
  }
}

function renderBuilderPreview() {
  const preview = $('builder-preview-code');
  const statusEl = $('builder-validation-status');
  if (!preview) return;

  const fbs = generateFBSFromBuilder();

  if (schemaBuilder.previewFormat === 'fbs') {
    preview.textContent = fbs;
  } else {
    preview.textContent = generateJSONSchemaFromBuilder();
  }

  // Sync to Schema Editor so Code Generator can use it
  const schemaInput = $('studio-schema-input');
  if (schemaInput && fbs && !fbs.startsWith('//')) {
    schemaInput.value = fbs;
  }

  // Validate the schema using WASM flatc
  validateSchemaWithWasm(fbs, statusEl);
}

// Debounced validation to avoid excessive WASM calls
let validationTimeout = null;
function validateSchemaWithWasm(fbs, statusEl) {
  if (validationTimeout) {
    clearTimeout(validationTimeout);
  }

  validationTimeout = setTimeout(() => {
    if (!state.flatcRunner) {
      schemaBuilder.validationError = 'WASM not initialized';
      if (statusEl) {
        statusEl.textContent = 'WASM not ready';
        statusEl.className = 'builder-validation-status warning';
      }
      return;
    }

    // If no content yet, don't validate
    if (!fbs || fbs.startsWith('//')) {
      schemaBuilder.validationError = null;
      if (statusEl) {
        statusEl.textContent = '';
        statusEl.className = 'builder-validation-status';
      }
      return;
    }

    try {
      // Use generateJsonSchema to validate - if it succeeds, schema is valid
      state.flatcRunner.generateJsonSchema(
        { entry: 'schema.fbs', files: { 'schema.fbs': fbs } },
        { includeXFlatbuffers: true }
      );
      schemaBuilder.validationError = null;
      if (statusEl) {
        statusEl.textContent = 'Valid';
        statusEl.className = 'builder-validation-status success';
      }
    } catch (err) {
      schemaBuilder.validationError = err.message;
      if (statusEl) {
        // Extract the error message (usually "error: ...")
        const errorMsg = err.message.split('\n')[0] || err.message;
        statusEl.textContent = errorMsg;
        statusEl.className = 'builder-validation-status error';
        statusEl.title = err.message; // Full error on hover
      }
    }
  }, 300); // 300ms debounce
}

function exportToSchemaEditor() {
  const fbs = generateFBSFromBuilder();

  // Set the schema editor content
  const schemaInput = $('studio-schema-input');
  if (schemaInput) {
    schemaInput.value = fbs;
  }

  // Switch to schema editor tab
  document.querySelectorAll('.studio-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.studio-panel').forEach(p => p.classList.remove('active'));

  const editorTab = document.querySelector('[data-studio-tab="schema-editor"]');
  const editorPanel = $('studio-schema-editor');

  if (editorTab) editorTab.classList.add('active');
  if (editorPanel) editorPanel.classList.add('active');

  // Update schema type selector
  const schemaTypeSelect = $('studio-schema-type');
  if (schemaTypeSelect) schemaTypeSelect.value = 'fbs';
}

init();
