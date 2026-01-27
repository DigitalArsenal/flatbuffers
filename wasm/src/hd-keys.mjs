/**
 * HD Key Derivation Module
 *
 * Industry-standard hierarchical deterministic key derivation following BIP-32/BIP-44
 * with enforced separation between signing and encryption keys.
 *
 * This module wraps hd-wallet-wasm for the underlying key derivation.
 *
 * Key Separation Pattern:
 * - External chain (change=0) → Signing keys (public-facing, verifiable)
 * - Internal chain (change=1) → Encryption keys (private communications)
 *
 * @module hd-keys
 */

import initHDWallet from 'hd-wallet-wasm';

// Cached module instance
let hdWalletModule = null;

/**
 * Get or initialize the hd-wallet-wasm module
 */
async function getModule() {
  if (!hdWalletModule) {
    hdWalletModule = await initHDWallet();
  }
  return hdWalletModule;
}

// =============================================================================
// Constants
// =============================================================================

/**
 * BIP-44 Purpose constant (hardened)
 */
export const BIP44_PURPOSE = 44;

/**
 * Chain indices for key separation
 */
export const Chain = {
  /** External chain - used for signing (signatures are public) */
  EXTERNAL: 0,
  /** Internal chain - used for encryption (encrypted content is private) */
  INTERNAL: 1,
  /** Alias for clarity */
  SIGNING: 0,
  /** Alias for clarity */
  ENCRYPTION: 1
};

/**
 * Standard SLIP-44 coin types
 * https://github.com/satoshilabs/slips/blob/master/slip-0044.md
 */
export const CoinType = {
  // secp256k1 curves
  BITCOIN: 0,
  TESTNET: 1,
  LITECOIN: 2,
  DOGECOIN: 3,
  ETHEREUM: 60,
  ETHEREUM_CLASSIC: 61,
  ROOTSTOCK: 137,
  BITCOIN_CASH: 145,
  BINANCE: 714,

  // Ed25519 curves
  SOLANA: 501,
  STELLAR: 148,
  CARDANO: 1815,
  POLKADOT: 354,
  KUSAMA: 434,
  TEZOS: 1729,

  // P-256 (NIST) - no official coin type, using reserved range
  NIST_P256: 0x100, // 256 - custom

  // P-384 (NIST) - no official coin type, using reserved range
  NIST_P384: 0x180, // 384 - custom

  // X25519 (key exchange only, not signing)
  X25519: 0x7919, // Custom: 0x7919 = "y25" in hex-ish
};

/**
 * Supported elliptic curves
 */
export const Curve = {
  SECP256K1: 'secp256k1',
  ED25519: 'ed25519',
  P256: 'p256',
  P384: 'p384',
  X25519: 'x25519'
};

/**
 * Mapping from coin type to curve
 */
export const CoinTypeToCurve = {
  [CoinType.BITCOIN]: Curve.SECP256K1,
  [CoinType.TESTNET]: Curve.SECP256K1,
  [CoinType.LITECOIN]: Curve.SECP256K1,
  [CoinType.DOGECOIN]: Curve.SECP256K1,
  [CoinType.ETHEREUM]: Curve.SECP256K1,
  [CoinType.ETHEREUM_CLASSIC]: Curve.SECP256K1,
  [CoinType.ROOTSTOCK]: Curve.SECP256K1,
  [CoinType.BITCOIN_CASH]: Curve.SECP256K1,
  [CoinType.BINANCE]: Curve.SECP256K1,
  [CoinType.SOLANA]: Curve.ED25519,
  [CoinType.STELLAR]: Curve.ED25519,
  [CoinType.CARDANO]: Curve.ED25519,
  [CoinType.POLKADOT]: Curve.ED25519,
  [CoinType.KUSAMA]: Curve.ED25519,
  [CoinType.TEZOS]: Curve.ED25519,
  [CoinType.NIST_P256]: Curve.P256,
  [CoinType.NIST_P384]: Curve.P384,
  [CoinType.X25519]: Curve.X25519,
};

/**
 * Default coin types for each curve (most common use case)
 */
export const DefaultCoinType = {
  [Curve.SECP256K1]: CoinType.ETHEREUM, // Most common for secp256k1
  [Curve.ED25519]: CoinType.SOLANA,     // Most common for Ed25519
  [Curve.P256]: CoinType.NIST_P256,
  [Curve.P384]: CoinType.NIST_P384,
  [Curve.X25519]: CoinType.X25519,
};

/**
 * Human-readable names for coin types
 */
export const CoinTypeName = {
  [CoinType.BITCOIN]: 'Bitcoin',
  [CoinType.TESTNET]: 'Bitcoin Testnet',
  [CoinType.LITECOIN]: 'Litecoin',
  [CoinType.DOGECOIN]: 'Dogecoin',
  [CoinType.ETHEREUM]: 'Ethereum',
  [CoinType.ETHEREUM_CLASSIC]: 'Ethereum Classic',
  [CoinType.ROOTSTOCK]: 'RSK',
  [CoinType.BITCOIN_CASH]: 'Bitcoin Cash',
  [CoinType.BINANCE]: 'BNB Chain',
  [CoinType.SOLANA]: 'Solana',
  [CoinType.STELLAR]: 'Stellar',
  [CoinType.CARDANO]: 'Cardano',
  [CoinType.POLKADOT]: 'Polkadot',
  [CoinType.KUSAMA]: 'Kusama',
  [CoinType.TEZOS]: 'Tezos',
  [CoinType.NIST_P256]: 'NIST P-256',
  [CoinType.NIST_P384]: 'NIST P-384',
  [CoinType.X25519]: 'X25519',
};

// =============================================================================
// Key Purpose Enum
// =============================================================================

/**
 * Key purpose - determines which chain to use
 */
export const KeyPurpose = {
  /** For creating digital signatures (uses external chain) */
  SIGNING: 'signing',
  /** For encrypting data (uses internal chain) */
  ENCRYPTION: 'encryption'
};

// =============================================================================
// Path Utilities
// =============================================================================

/**
 * Build a BIP-44 derivation path
 *
 * @param {Object} options - Path options
 * @param {number} [options.purpose=44] - BIP purpose (usually 44)
 * @param {number} options.coinType - SLIP-44 coin type
 * @param {number} [options.account=0] - Account index
 * @param {number} options.chain - Chain index (0=external/signing, 1=internal/encryption)
 * @param {number} [options.index=0] - Address index
 * @returns {string} BIP-44 path string
 */
export function buildPath({ purpose = BIP44_PURPOSE, coinType, account = 0, chain, index = 0 }) {
  if (coinType === undefined) throw new Error('coinType is required');
  if (chain === undefined) throw new Error('chain is required');

  return `m/${purpose}'/${coinType}'/${account}'/${chain}/${index}`;
}

/**
 * Build a signing key path (external chain)
 *
 * @param {number} coinType - SLIP-44 coin type
 * @param {number} [account=0] - Account index
 * @param {number} [index=0] - Address index
 * @returns {string} BIP-44 path for signing
 */
export function buildSigningPath(coinType, account = 0, index = 0) {
  return buildPath({ coinType, account, chain: Chain.SIGNING, index });
}

/**
 * Build an encryption key path (internal chain)
 *
 * @param {number} coinType - SLIP-44 coin type
 * @param {number} [account=0] - Account index
 * @param {number} [index=0] - Address index
 * @returns {string} BIP-44 path for encryption
 */
export function buildEncryptionPath(coinType, account = 0, index = 0) {
  return buildPath({ coinType, account, chain: Chain.ENCRYPTION, index });
}

/**
 * Parse a BIP-44 path string into components
 *
 * @param {string} path - BIP-44 path string
 * @returns {Object} Parsed path components
 */
export function parsePath(path) {
  const match = path.match(/^m\/(\d+)'\/(\d+)'\/(\d+)'\/(\d+)\/(\d+)$/);
  if (!match) {
    throw new Error(`Invalid BIP-44 path: ${path}`);
  }

  return {
    purpose: parseInt(match[1], 10),
    coinType: parseInt(match[2], 10),
    account: parseInt(match[3], 10),
    chain: parseInt(match[4], 10),
    index: parseInt(match[5], 10)
  };
}

// =============================================================================
// HD Key Manager Class
// =============================================================================

/**
 * HD Key Manager - manages hierarchical deterministic key derivation
 * with enforced separation between signing and encryption keys.
 *
 * Uses hd-wallet-wasm internally for key derivation.
 */
export class HDKeyManager {
  #root;
  #masterSeed;
  #module;

  /**
   * Create an HD Key Manager from a master seed
   *
   * @param {Uint8Array} masterSeed - 64-byte master seed (from BIP-39 or password derivation)
   * @param {Object} module - The initialized hd-wallet-wasm module
   */
  constructor(masterSeed, module) {
    if (!(masterSeed instanceof Uint8Array) || masterSeed.length < 32) {
      throw new Error('Master seed must be a Uint8Array of at least 32 bytes');
    }
    this.#masterSeed = masterSeed;
    this.#module = module;
    this.#root = module.hdkey.fromSeed(masterSeed);
  }

  /**
   * Get the master seed (for backup purposes)
   * @returns {Uint8Array}
   */
  getMasterSeed() {
    return new Uint8Array(this.#masterSeed);
  }

  /**
   * Derive a key at a specific path
   *
   * @param {string} path - BIP-44 path
   * @returns {Object} Derived HD key
   */
  deriveKey(path) {
    return this.#root.derivePath(path);
  }

  /**
   * Derive a signing key (enforces external chain)
   *
   * @param {Object} options - Derivation options
   * @param {number} options.coinType - SLIP-44 coin type
   * @param {number} [options.account=0] - Account index
   * @param {number} [options.index=0] - Address index
   * @returns {Object} Derived key with path info
   */
  deriveSigningKey({ coinType, account = 0, index = 0 }) {
    const path = buildSigningPath(coinType, account, index);
    const derived = this.deriveKey(path);

    return {
      path,
      purpose: KeyPurpose.SIGNING,
      coinType,
      curve: CoinTypeToCurve[coinType] || Curve.SECP256K1,
      account,
      index,
      privateKey: derived.privateKey(),
      publicKey: derived.publicKey(),
      chainCode: derived.chainCode()
    };
  }

  /**
   * Derive an encryption key (enforces internal chain)
   *
   * @param {Object} options - Derivation options
   * @param {number} options.coinType - SLIP-44 coin type
   * @param {number} [options.account=0] - Account index
   * @param {number} [options.index=0] - Address index
   * @returns {Object} Derived key with path info
   */
  deriveEncryptionKey({ coinType, account = 0, index = 0 }) {
    const path = buildEncryptionPath(coinType, account, index);
    const derived = this.deriveKey(path);

    return {
      path,
      purpose: KeyPurpose.ENCRYPTION,
      coinType,
      curve: CoinTypeToCurve[coinType] || Curve.SECP256K1,
      account,
      index,
      privateKey: derived.privateKey(),
      publicKey: derived.publicKey(),
      chainCode: derived.chainCode()
    };
  }

  /**
   * Derive a key pair for a specific purpose
   *
   * @param {Object} options - Derivation options
   * @param {string} options.purpose - KeyPurpose.SIGNING or KeyPurpose.ENCRYPTION
   * @param {number} options.coinType - SLIP-44 coin type
   * @param {number} [options.account=0] - Account index
   * @param {number} [options.index=0] - Address index
   * @returns {Object} Derived key with path info
   */
  deriveKeyForPurpose({ purpose, coinType, account = 0, index = 0 }) {
    if (purpose === KeyPurpose.SIGNING) {
      return this.deriveSigningKey({ coinType, account, index });
    } else if (purpose === KeyPurpose.ENCRYPTION) {
      return this.deriveEncryptionKey({ coinType, account, index });
    } else {
      throw new Error(`Invalid purpose: ${purpose}. Use KeyPurpose.SIGNING or KeyPurpose.ENCRYPTION`);
    }
  }

  /**
   * Derive both signing and encryption keys for a coin type
   * This is useful for applications that need both capabilities
   *
   * @param {Object} options - Derivation options
   * @param {number} options.coinType - SLIP-44 coin type
   * @param {number} [options.account=0] - Account index
   * @param {number} [options.index=0] - Address index
   * @returns {Object} Object with signing and encryption keys
   */
  deriveKeyPair({ coinType, account = 0, index = 0 }) {
    return {
      signing: this.deriveSigningKey({ coinType, account, index }),
      encryption: this.deriveEncryptionKey({ coinType, account, index })
    };
  }

  /**
   * Get available coin types for a specific curve
   *
   * @param {string} curve - Curve type from Curve enum
   * @returns {Array<{coinType: number, name: string}>}
   */
  static getCoinTypesForCurve(curve) {
    const coinTypes = [];
    for (const [coinTypeStr, curveName] of Object.entries(CoinTypeToCurve)) {
      if (curveName === curve) {
        const coinType = parseInt(coinTypeStr, 10);
        coinTypes.push({
          coinType,
          name: CoinTypeName[coinType] || `Unknown (${coinType})`
        });
      }
    }
    return coinTypes;
  }

  /**
   * Get the curve for a coin type
   *
   * @param {number} coinType - SLIP-44 coin type
   * @returns {string} Curve name
   */
  static getCurveForCoinType(coinType) {
    return CoinTypeToCurve[coinType];
  }

  /**
   * Get the default coin type for a curve
   *
   * @param {string} curve - Curve type
   * @returns {number} Default coin type
   */
  static getDefaultCoinType(curve) {
    return DefaultCoinType[curve];
  }
}

// =============================================================================
// Convenience Functions
// =============================================================================

/**
 * Create an HD Key Manager from a BIP-39 seed phrase
 *
 * @param {string} mnemonic - BIP-39 mnemonic phrase
 * @param {string} [passphrase=''] - Optional passphrase
 * @returns {Promise<HDKeyManager>}
 */
export async function createFromMnemonic(mnemonic, passphrase = '') {
  const module = await getModule();
  const seed = module.mnemonic.toSeed(mnemonic, passphrase);
  return new HDKeyManager(new Uint8Array(seed), module);
}

/**
 * Create an HD Key Manager from a raw seed
 *
 * @param {Uint8Array} seed - Master seed
 * @returns {Promise<HDKeyManager>}
 */
export async function createFromSeed(seed) {
  const module = await getModule();
  return new HDKeyManager(seed, module);
}

// =============================================================================
// Validation Helpers
// =============================================================================

/**
 * Validate that a key was derived for signing
 *
 * @param {Object} derivedKey - Key object from deriveSigningKey or deriveKeyForPurpose
 * @throws {Error} If key was not derived for signing
 */
export function validateSigningKey(derivedKey) {
  const parsed = parsePath(derivedKey.path);
  if (parsed.chain !== Chain.SIGNING) {
    throw new Error(
      `Key at path ${derivedKey.path} was not derived for signing. ` +
      `Expected chain=${Chain.SIGNING} (external), got chain=${parsed.chain}`
    );
  }
}

/**
 * Validate that a key was derived for encryption
 *
 * @param {Object} derivedKey - Key object from deriveEncryptionKey or deriveKeyForPurpose
 * @throws {Error} If key was not derived for encryption
 */
export function validateEncryptionKey(derivedKey) {
  const parsed = parsePath(derivedKey.path);
  if (parsed.chain !== Chain.ENCRYPTION) {
    throw new Error(
      `Key at path ${derivedKey.path} was not derived for encryption. ` +
      `Expected chain=${Chain.ENCRYPTION} (internal), got chain=${parsed.chain}`
    );
  }
}

// =============================================================================
// Export default object for convenience
// =============================================================================

export default {
  // Constants
  BIP44_PURPOSE,
  Chain,
  CoinType,
  Curve,
  CoinTypeToCurve,
  DefaultCoinType,
  CoinTypeName,
  KeyPurpose,

  // Path utilities
  buildPath,
  buildSigningPath,
  buildEncryptionPath,
  parsePath,

  // Manager class
  HDKeyManager,

  // Factory functions
  createFromMnemonic,
  createFromSeed,

  // Validation
  validateSigningKey,
  validateEncryptionKey
};
