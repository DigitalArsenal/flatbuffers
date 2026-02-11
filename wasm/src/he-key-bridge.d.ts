/**
 * HE Key Bridge: HD Wallet → Deterministic Homomorphic Encryption Keys
 */

import { HEContext } from './he-context.js';
import { HDKeyManager, DerivedKey } from './hd-keys.js';

/** HKDF function signature */
export type HkdfFunction = (
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number
) => Promise<Uint8Array>;

/** Options for HE context derivation */
export interface DeriveHEOptions {
  /** Polynomial modulus degree (default: 4096) */
  polyDegree?: number;
  /** Custom HKDF function (defaults to Web Crypto) */
  hkdfFn?: HkdfFunction;
}

/** Options for key derivation from HDKeyManager */
export interface KeyDerivationOptions {
  /** BIP-44 coin type */
  coinType?: number;
  /** Account index (default: 0) */
  account?: number;
  /** Key index (default: 0) */
  index?: number;
}

/** Public bundle for sharing with recipients */
export interface HEPublicBundle {
  publicKey: Uint8Array;
  relinKeys: Uint8Array;
}

/**
 * Derive a deterministic HE context from an HD wallet encryption key.
 */
export function deriveHEContext(
  hdEncryptionKey: DerivedKey,
  options?: DeriveHEOptions
): Promise<HEContext>;

/**
 * Extract the public bundle from an HE context for sharing with recipients.
 */
export function getHEPublicBundle(heContext: HEContext): HEPublicBundle;

/**
 * Derive an HE context directly from an HDKeyManager instance.
 */
export function deriveHEContextFromManager(
  hdKeyManager: HDKeyManager,
  keyOptions?: KeyDerivationOptions,
  heOptions?: DeriveHEOptions
): Promise<HEContext>;
