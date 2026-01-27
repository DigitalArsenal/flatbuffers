/**
 * HD Key Derivation Module TypeScript Definitions
 *
 * Industry-standard hierarchical deterministic key derivation following BIP-32/BIP-44
 * with enforced separation between signing and encryption keys.
 */

import { HDKey } from '@scure/bip32';

/** BIP-44 Purpose constant (hardened) */
export const BIP44_PURPOSE: 44;

/** Chain indices for key separation */
export const Chain: {
  /** External chain - used for signing (signatures are public) */
  readonly EXTERNAL: 0;
  /** Internal chain - used for encryption (encrypted content is private) */
  readonly INTERNAL: 1;
  /** Alias for clarity */
  readonly SIGNING: 0;
  /** Alias for clarity */
  readonly ENCRYPTION: 1;
};

/** Standard SLIP-44 coin types */
export const CoinType: {
  readonly BITCOIN: 0;
  readonly TESTNET: 1;
  readonly LITECOIN: 2;
  readonly DOGECOIN: 3;
  readonly ETHEREUM: 60;
  readonly ETHEREUM_CLASSIC: 61;
  readonly ROOTSTOCK: 137;
  readonly BITCOIN_CASH: 145;
  readonly BINANCE: 714;
  readonly SOLANA: 501;
  readonly STELLAR: 148;
  readonly CARDANO: 1815;
  readonly POLKADOT: 354;
  readonly KUSAMA: 434;
  readonly TEZOS: 1729;
  readonly NIST_P256: 256;
  readonly NIST_P384: 384;
  readonly X25519: 31001;
};

/** Supported elliptic curves */
export const Curve: {
  readonly SECP256K1: 'secp256k1';
  readonly ED25519: 'ed25519';
  readonly P256: 'p256';
  readonly P384: 'p384';
  readonly X25519: 'x25519';
};

/** Mapping from coin type to curve */
export const CoinTypeToCurve: Record<number, string>;

/** Default coin types for each curve */
export const DefaultCoinType: Record<string, number>;

/** Human-readable names for coin types */
export const CoinTypeName: Record<number, string>;

/** Key purpose - determines which chain to use */
export const KeyPurpose: {
  /** For creating digital signatures (uses external chain) */
  readonly SIGNING: 'signing';
  /** For encrypting data (uses internal chain) */
  readonly ENCRYPTION: 'encryption';
};

/** Path building options */
export interface PathOptions {
  purpose?: number;
  coinType: number;
  account?: number;
  chain: number;
  index?: number;
}

/** Key derivation options */
export interface DeriveOptions {
  coinType: number;
  account?: number;
  index?: number;
}

/** Purpose-based derivation options */
export interface DeriveForPurposeOptions extends DeriveOptions {
  purpose: 'signing' | 'encryption';
}

/** Derived key result */
export interface DerivedKey {
  path: string;
  purpose: 'signing' | 'encryption';
  coinType: number;
  curve: string;
  account: number;
  index: number;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  chainCode: Uint8Array;
}

/** Derived key pair result */
export interface DerivedKeyPair {
  signing: DerivedKey;
  encryption: DerivedKey;
}

/** Parsed path components */
export interface ParsedPath {
  purpose: number;
  coinType: number;
  account: number;
  chain: number;
  index: number;
}

/** Coin type info */
export interface CoinTypeInfo {
  coinType: number;
  name: string;
}

/**
 * Build a BIP-44 derivation path
 */
export function buildPath(options: PathOptions): string;

/**
 * Build a signing key path (external chain)
 */
export function buildSigningPath(coinType: number, account?: number, index?: number): string;

/**
 * Build an encryption key path (internal chain)
 */
export function buildEncryptionPath(coinType: number, account?: number, index?: number): string;

/**
 * Parse a BIP-44 path string into components
 */
export function parsePath(path: string): ParsedPath;

/**
 * HD Key Manager - manages hierarchical deterministic key derivation
 * with enforced separation between signing and encryption keys.
 */
export class HDKeyManager {
  /**
   * Create an HD Key Manager from a master seed
   * @param masterSeed - 64-byte master seed (from BIP-39 or password derivation)
   */
  constructor(masterSeed: Uint8Array);

  /**
   * Get the master seed (for backup purposes)
   */
  getMasterSeed(): Uint8Array;

  /**
   * Derive a key at a specific path
   */
  deriveKey(path: string): HDKey;

  /**
   * Derive a signing key (enforces external chain)
   */
  deriveSigningKey(options: DeriveOptions): DerivedKey;

  /**
   * Derive an encryption key (enforces internal chain)
   */
  deriveEncryptionKey(options: DeriveOptions): DerivedKey;

  /**
   * Derive a key pair for a specific purpose
   */
  deriveKeyForPurpose(options: DeriveForPurposeOptions): DerivedKey;

  /**
   * Derive both signing and encryption keys for a coin type
   */
  deriveKeyPair(options: DeriveOptions): DerivedKeyPair;

  /**
   * Get available coin types for a specific curve
   */
  static getCoinTypesForCurve(curve: string): CoinTypeInfo[];

  /**
   * Get the curve for a coin type
   */
  static getCurveForCoinType(coinType: number): string;

  /**
   * Get the default coin type for a curve
   */
  static getDefaultCoinType(curve: string): number;
}

/**
 * Create an HD Key Manager from a BIP-39 seed phrase
 */
export function createFromMnemonic(mnemonic: string, passphrase?: string): Promise<HDKeyManager>;

/**
 * Create an HD Key Manager from a raw seed
 */
export function createFromSeed(seed: Uint8Array): HDKeyManager;

/**
 * Validate that a key was derived for signing
 * @throws If key was not derived for signing
 */
export function validateSigningKey(derivedKey: DerivedKey): void;

/**
 * Validate that a key was derived for encryption
 * @throws If key was not derived for encryption
 */
export function validateEncryptionKey(derivedKey: DerivedKey): void;

declare const _default: {
  BIP44_PURPOSE: typeof BIP44_PURPOSE;
  Chain: typeof Chain;
  CoinType: typeof CoinType;
  Curve: typeof Curve;
  CoinTypeToCurve: typeof CoinTypeToCurve;
  DefaultCoinType: typeof DefaultCoinType;
  CoinTypeName: typeof CoinTypeName;
  KeyPurpose: typeof KeyPurpose;
  buildPath: typeof buildPath;
  buildSigningPath: typeof buildSigningPath;
  buildEncryptionPath: typeof buildEncryptionPath;
  parsePath: typeof parsePath;
  HDKeyManager: typeof HDKeyManager;
  createFromMnemonic: typeof createFromMnemonic;
  createFromSeed: typeof createFromSeed;
  validateSigningKey: typeof validateSigningKey;
  validateEncryptionKey: typeof validateEncryptionKey;
};

export default _default;
