/**
 * Wallet Storage Module
 *
 * Industry-standard implementation for securely storing wallet credentials
 * using WebAuthn PRF extension or PIN-based encryption.
 *
 * Based on best practices from:
 * - Yubico WebAuthn PRF Developer Guide
 * - wwWallet FUNKE implementation
 * - W3C WebAuthn PRF Extension specification
 *
 * @module wallet-storage
 */

// =============================================================================
// Storage Keys
// =============================================================================

const STORAGE_PREFIX = 'wallet_storage_';
const METADATA_KEY = `${STORAGE_PREFIX}metadata`;
const ENCRYPTED_DATA_KEY = `${STORAGE_PREFIX}encrypted`;
const PASSKEY_CREDENTIAL_KEY = `${STORAGE_PREFIX}passkey_credential`;

// Version for future migrations
const STORAGE_VERSION = 2;

// =============================================================================
// Storage Method Enum
// =============================================================================

export const StorageMethod = {
  NONE: 'none',
  PIN: 'pin',
  PASSKEY: 'passkey'
};

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Convert ArrayBuffer to base64 string
 */
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert base64 string to Uint8Array
 */
function base64ToUint8Array(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Generate cryptographically secure random bytes
 */
function generateRandomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

// =============================================================================
// Key Derivation (HKDF - Industry Standard)
// =============================================================================

/**
 * Derive encryption key using HKDF (HMAC-based Key Derivation Function)
 * This is the industry-standard approach recommended by Yubico and others.
 *
 * @param {Uint8Array} inputKeyMaterial - The input key material (from PRF or PIN hash)
 * @param {Uint8Array} salt - Salt for HKDF
 * @param {string} info - Context info string
 * @param {number} length - Desired key length in bytes
 * @returns {Promise<Uint8Array>} Derived key
 */
async function hkdfDerive(inputKeyMaterial, salt, info, length) {
  const encoder = new TextEncoder();

  // Import the input key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    inputKeyMaterial,
    'HKDF',
    false,
    ['deriveBits']
  );

  // Derive bits using HKDF
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt,
      info: encoder.encode(info)
    },
    keyMaterial,
    length * 8
  );

  return new Uint8Array(derivedBits);
}

/**
 * Derive encryption key and IV from key material
 */
async function deriveKeyAndIV(keyMaterial, context) {
  const salt = new TextEncoder().encode(`wallet-storage-v${STORAGE_VERSION}`);

  const encryptionKey = await hkdfDerive(
    keyMaterial,
    salt,
    `${context}-encryption-key`,
    32
  );

  const iv = await hkdfDerive(
    keyMaterial,
    salt,
    `${context}-encryption-iv`,
    12 // AES-GCM standard IV size
  );

  return { encryptionKey, iv };
}

// =============================================================================
// PIN-Based Encryption
// =============================================================================

/**
 * Derive key material from a 6-digit PIN
 * Uses PBKDF2 for additional security against brute-force attacks
 */
async function deriveKeyFromPIN(pin, storedSalt) {
  if (!/^\d{6}$/.test(pin)) {
    throw new Error('PIN must be exactly 6 digits');
  }

  const encoder = new TextEncoder();
  const pinBytes = encoder.encode(pin);

  // Use stored salt or generate new one
  const salt = storedSalt || generateRandomBytes(16);

  // Import PIN as key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    pinBytes,
    'PBKDF2',
    false,
    ['deriveBits']
  );

  // Use PBKDF2 with high iteration count for PIN (since PINs have low entropy)
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: salt,
      iterations: 100000 // High iteration count for brute-force resistance
    },
    keyMaterial,
    256
  );

  return {
    keyMaterial: new Uint8Array(derivedBits),
    salt
  };
}

// =============================================================================
// WebAuthn PRF Extension
// =============================================================================

/**
 * Check if WebAuthn/Passkeys are supported
 */
export function isPasskeySupported() {
  return !!(
    window.PublicKeyCredential &&
    typeof window.PublicKeyCredential === 'function'
  );
}

/**
 * Check if PRF extension is likely supported
 * Note: Full support detection requires actually creating a credential
 */
export async function isPRFLikelySupported() {
  if (!isPasskeySupported()) return false;

  try {
    // Check if platform authenticator is available
    const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    return available;
  } catch {
    return false;
  }
}

/**
 * Generate WebAuthn challenge
 */
function generateChallenge() {
  return generateRandomBytes(32);
}

/**
 * Create PRF input salts for key derivation
 * Following the recommended pattern from Yubico for key rotation support
 */
function createPRFInputs() {
  const encoder = new TextEncoder();
  return {
    // Primary key derivation salt
    first: encoder.encode('wallet-storage-prf-v2-primary'),
    // Secondary salt for future key rotation support
    second: encoder.encode('wallet-storage-prf-v2-secondary')
  };
}

/**
 * Register a new passkey and derive encryption key material
 *
 * @param {Object} options - Registration options
 * @param {string} options.rpName - Relying party name (e.g., 'My App')
 * @param {string} options.userName - User identifier
 * @param {string} options.userDisplayName - User display name
 * @returns {Promise<{credentialId: string, keyMaterial: Uint8Array, hasPRF: boolean}>}
 */
export async function registerPasskey(options = {}) {
  if (!isPasskeySupported()) {
    throw new Error('Passkeys are not supported on this device');
  }

  const {
    rpName = 'Wallet Storage',
    userName = 'wallet-user',
    userDisplayName = 'Wallet User'
  } = options;

  const challenge = generateChallenge();
  const userId = generateRandomBytes(16);
  const prfInputs = createPRFInputs();

  const publicKeyCredentialCreationOptions = {
    challenge,
    rp: {
      name: rpName,
      id: window.location.hostname
    },
    user: {
      id: userId,
      name: userName,
      displayName: userDisplayName
    },
    pubKeyCredParams: [
      { alg: -7, type: 'public-key' },   // ES256 (P-256)
      { alg: -257, type: 'public-key' }  // RS256
    ],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required',
      residentKey: 'preferred' // Changed from 'required' for broader compatibility
    },
    timeout: 60000,
    attestation: 'none',
    extensions: {
      prf: {
        eval: {
          first: prfInputs.first
        }
      }
    }
  };

  const credential = await navigator.credentials.create({
    publicKey: publicKeyCredentialCreationOptions
  });

  // Extract PRF result or fall back to credential ID
  const extensionResults = credential.getClientExtensionResults();
  const prfResult = extensionResults?.prf?.results?.first;

  let keyMaterial;
  let hasPRF = false;

  if (prfResult && prfResult.byteLength > 0) {
    // PRF is supported - use the PRF output
    keyMaterial = new Uint8Array(prfResult);
    hasPRF = true;
  } else {
    // PRF not supported - derive key from credential ID
    // This is less secure but provides fallback functionality
    const rawId = new Uint8Array(credential.rawId);
    const hash = await crypto.subtle.digest('SHA-256', rawId);
    keyMaterial = new Uint8Array(hash);
  }

  return {
    credentialId: arrayBufferToBase64(credential.rawId),
    keyMaterial,
    hasPRF
  };
}

/**
 * Authenticate with existing passkey and derive encryption key material
 *
 * @param {string} credentialId - Base64-encoded credential ID
 * @returns {Promise<{keyMaterial: Uint8Array, hasPRF: boolean}>}
 */
export async function authenticatePasskey(credentialId) {
  if (!isPasskeySupported()) {
    throw new Error('Passkeys are not supported on this device');
  }

  const challenge = generateChallenge();
  const prfInputs = createPRFInputs();
  const credentialIdBytes = base64ToUint8Array(credentialId);

  const publicKeyCredentialRequestOptions = {
    challenge,
    allowCredentials: [{
      id: credentialIdBytes,
      type: 'public-key',
      transports: ['internal', 'hybrid'] // Support both platform and cross-device
    }],
    userVerification: 'required',
    timeout: 60000,
    extensions: {
      prf: {
        eval: {
          first: prfInputs.first
        }
      }
    }
  };

  const assertion = await navigator.credentials.get({
    publicKey: publicKeyCredentialRequestOptions
  });

  // Extract PRF result or fall back to credential ID
  const extensionResults = assertion.getClientExtensionResults();
  const prfResult = extensionResults?.prf?.results?.first;

  let keyMaterial;
  let hasPRF = false;

  if (prfResult && prfResult.byteLength > 0) {
    keyMaterial = new Uint8Array(prfResult);
    hasPRF = true;
  } else {
    // Fallback: derive from credential ID
    const rawId = new Uint8Array(assertion.rawId);
    const hash = await crypto.subtle.digest('SHA-256', rawId);
    keyMaterial = new Uint8Array(hash);
  }

  return { keyMaterial, hasPRF };
}

// =============================================================================
// Encryption/Decryption
// =============================================================================

/**
 * Encrypt data using AES-256-GCM
 */
async function encryptData(data, encryptionKey, iv) {
  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(data));

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    encryptionKey,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    plaintext
  );

  return new Uint8Array(ciphertext);
}

/**
 * Decrypt data using AES-256-GCM
 */
async function decryptData(ciphertext, encryptionKey, iv) {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    encryptionKey,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    ciphertext
  );

  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(plaintext));
}

// =============================================================================
// High-Level Storage API
// =============================================================================

/**
 * Get storage metadata
 * @returns {Object|null} Storage metadata or null if no wallet stored
 */
export function getStorageMetadata() {
  try {
    const metadataJson = localStorage.getItem(METADATA_KEY);
    if (!metadataJson) return null;

    const metadata = JSON.parse(metadataJson);
    return {
      method: metadata.method || StorageMethod.NONE,
      timestamp: metadata.timestamp,
      date: new Date(metadata.timestamp).toLocaleDateString(),
      version: metadata.version,
      hasPRF: metadata.hasPRF || false
    };
  } catch {
    return null;
  }
}

/**
 * Check if a wallet is stored
 * @returns {boolean}
 */
export function hasStoredWallet() {
  return getStorageMetadata() !== null;
}

/**
 * Get the storage method used
 * @returns {string} StorageMethod value
 */
export function getStorageMethod() {
  const metadata = getStorageMetadata();
  return metadata?.method || StorageMethod.NONE;
}

/**
 * Store wallet data with PIN encryption
 *
 * @param {string} pin - 6-digit PIN
 * @param {Object} walletData - Data to encrypt and store
 * @returns {Promise<boolean>}
 */
export async function storeWithPIN(pin, walletData) {
  // Derive key from PIN
  const { keyMaterial, salt } = await deriveKeyFromPIN(pin);
  const { encryptionKey, iv } = await deriveKeyAndIV(keyMaterial, 'pin');

  // Encrypt wallet data
  const ciphertext = await encryptData(walletData, encryptionKey, iv);

  // Store encrypted data
  const encryptedData = {
    ciphertext: arrayBufferToBase64(ciphertext),
    salt: arrayBufferToBase64(salt)
  };
  localStorage.setItem(ENCRYPTED_DATA_KEY, JSON.stringify(encryptedData));

  // Store metadata
  const metadata = {
    method: StorageMethod.PIN,
    timestamp: Date.now(),
    version: STORAGE_VERSION
  };
  localStorage.setItem(METADATA_KEY, JSON.stringify(metadata));

  return true;
}

/**
 * Retrieve wallet data with PIN
 *
 * @param {string} pin - 6-digit PIN
 * @returns {Promise<Object>} Decrypted wallet data
 */
export async function retrieveWithPIN(pin) {
  const metadata = getStorageMetadata();
  if (!metadata || metadata.method !== StorageMethod.PIN) {
    throw new Error('No PIN-encrypted wallet found');
  }

  const encryptedJson = localStorage.getItem(ENCRYPTED_DATA_KEY);
  if (!encryptedJson) {
    throw new Error('Encrypted data not found');
  }

  const encryptedData = JSON.parse(encryptedJson);
  const salt = base64ToUint8Array(encryptedData.salt);
  const ciphertext = base64ToUint8Array(encryptedData.ciphertext);

  // Derive key from PIN with stored salt
  const { keyMaterial } = await deriveKeyFromPIN(pin, salt);
  const { encryptionKey, iv } = await deriveKeyAndIV(keyMaterial, 'pin');

  try {
    return await decryptData(ciphertext, encryptionKey, iv);
  } catch (e) {
    throw new Error('Invalid PIN or corrupted data');
  }
}

/**
 * Store wallet data with passkey encryption
 *
 * @param {Object} walletData - Data to encrypt and store
 * @param {Object} options - Passkey options
 * @returns {Promise<boolean>}
 */
export async function storeWithPasskey(walletData, options = {}) {
  // Register passkey and get key material
  const { credentialId, keyMaterial, hasPRF } = await registerPasskey(options);

  // Derive encryption key
  const { encryptionKey, iv } = await deriveKeyAndIV(keyMaterial, 'passkey');

  // Encrypt wallet data
  const ciphertext = await encryptData(walletData, encryptionKey, iv);

  // Store credential info
  const credentialData = {
    id: credentialId,
    hasPRF
  };
  localStorage.setItem(PASSKEY_CREDENTIAL_KEY, JSON.stringify(credentialData));

  // Store encrypted data
  const encryptedData = {
    ciphertext: arrayBufferToBase64(ciphertext)
  };
  localStorage.setItem(ENCRYPTED_DATA_KEY, JSON.stringify(encryptedData));

  // Store metadata
  const metadata = {
    method: StorageMethod.PASSKEY,
    timestamp: Date.now(),
    version: STORAGE_VERSION,
    hasPRF
  };
  localStorage.setItem(METADATA_KEY, JSON.stringify(metadata));

  return true;
}

/**
 * Retrieve wallet data with passkey
 *
 * @returns {Promise<Object>} Decrypted wallet data
 */
export async function retrieveWithPasskey() {
  const metadata = getStorageMetadata();
  if (!metadata || metadata.method !== StorageMethod.PASSKEY) {
    throw new Error('No passkey-encrypted wallet found');
  }

  const credentialJson = localStorage.getItem(PASSKEY_CREDENTIAL_KEY);
  if (!credentialJson) {
    throw new Error('Passkey credential not found');
  }

  const credentialData = JSON.parse(credentialJson);

  const encryptedJson = localStorage.getItem(ENCRYPTED_DATA_KEY);
  if (!encryptedJson) {
    throw new Error('Encrypted data not found');
  }

  const encryptedData = JSON.parse(encryptedJson);
  const ciphertext = base64ToUint8Array(encryptedData.ciphertext);

  // Authenticate with passkey and get key material
  const { keyMaterial } = await authenticatePasskey(credentialData.id);

  // Derive encryption key
  const { encryptionKey, iv } = await deriveKeyAndIV(keyMaterial, 'passkey');

  try {
    return await decryptData(ciphertext, encryptionKey, iv);
  } catch (e) {
    throw new Error('Passkey authentication failed or data corrupted');
  }
}

/**
 * Clear all stored wallet data
 */
export function clearStorage() {
  localStorage.removeItem(METADATA_KEY);
  localStorage.removeItem(ENCRYPTED_DATA_KEY);
  localStorage.removeItem(PASSKEY_CREDENTIAL_KEY);
}

/**
 * Migrate from old storage format (v1) to new format (v2)
 * Call this on app initialization
 */
export function migrateStorage() {
  // Check for old v1 keys
  const oldPinWallet = localStorage.getItem('encrypted_wallet');
  const oldPasskeyCredential = localStorage.getItem('passkey_credential');
  const oldPasskeyWallet = localStorage.getItem('passkey_wallet');

  // Already migrated or no old data
  if (getStorageMetadata() !== null) return;
  if (!oldPinWallet && !oldPasskeyCredential) return;

  console.log('Migrating wallet storage from v1 to v2...');

  if (oldPasskeyCredential && oldPasskeyWallet) {
    // Migrate passkey storage
    try {
      const credential = JSON.parse(oldPasskeyCredential);
      const wallet = JSON.parse(oldPasskeyWallet);

      localStorage.setItem(PASSKEY_CREDENTIAL_KEY, JSON.stringify({
        id: credential.id,
        hasPRF: credential.hasPRF || false
      }));

      localStorage.setItem(ENCRYPTED_DATA_KEY, JSON.stringify({
        ciphertext: wallet.ciphertext
      }));

      localStorage.setItem(METADATA_KEY, JSON.stringify({
        method: StorageMethod.PASSKEY,
        timestamp: credential.timestamp || wallet.timestamp || Date.now(),
        version: STORAGE_VERSION,
        hasPRF: credential.hasPRF || false
      }));

      // Clean up old keys
      localStorage.removeItem('passkey_credential');
      localStorage.removeItem('passkey_wallet');

      console.log('Passkey storage migrated successfully');
    } catch (e) {
      console.error('Failed to migrate passkey storage:', e);
    }
  } else if (oldPinWallet) {
    // Migrate PIN storage - can't fully migrate since we need the salt
    // User will need to re-enter their wallet
    console.log('PIN storage detected but cannot be migrated - user will need to re-login');
    localStorage.removeItem('encrypted_wallet');
  }
}

// =============================================================================
// Export default object for convenience
// =============================================================================

export default {
  StorageMethod,
  isPasskeySupported,
  isPRFLikelySupported,
  getStorageMetadata,
  hasStoredWallet,
  getStorageMethod,
  storeWithPIN,
  retrieveWithPIN,
  storeWithPasskey,
  retrieveWithPasskey,
  clearStorage,
  migrateStorage
};
