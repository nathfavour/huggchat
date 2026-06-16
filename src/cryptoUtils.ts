import { argon2id } from "hash-wasm";

// Helper utilities to encode and decode hex/base64
export function bufToHex(buffer: Uint8Array): string {
  return Array.from(buffer)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexToBuf(hexString: string): Uint8Array {
  const cleanHex = hexString.replace(/\s+/g, "");
  if (cleanHex.length % 2 !== 0) throw new Error("Invalid hex string length");
  const result = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < result.length; i++) {
    result[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
  }
  return result;
}

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// Global detection of cryptographic curves
let CRYPTO_ALGO = "X25519";
let ECDH_CURVE = "X25519";

export async function detectCryptoCapabilities() {
  try {
    await window.crypto.subtle.generateKey(
      { name: "X25519" },
      true,
      ["deriveBits"]
    );
    CRYPTO_ALGO = "X25519";
    ECDH_CURVE = "X25519";
  } catch (e) {
    // Fallback to P-256 for older runtimes/iframes failing to load X25519
    CRYPTO_ALGO = "ECDH";
    ECDH_CURVE = "P-256";
    console.warn("WebCrypto X25519 not supported. Falling back to P-256 ECDH.");
  }
}

// 1. Generate identity and DH keypair
export interface CipherKeyPair {
  publicKeyHex: string;
  privateKeyJwk: string;
}

export async function generateIdentityKeypair(): Promise<CipherKeyPair> {
  await detectCryptoCapabilities();
  const keyType = CRYPTO_ALGO === "X25519" ? { name: "X25519" } : { name: "ECDH", curve: ECDH_CURVE };
  
  const keyPair = (await window.crypto.subtle.generateKey(
    keyType,
    true,
    ["deriveKey", "deriveBits"]
  )) as CryptoKeyPair;

  const rawPub = await window.crypto.subtle.exportKey("raw", keyPair.publicKey);
  const jwkPriv = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);

  return {
    publicKeyHex: bufToHex(new Uint8Array(rawPub)),
    privateKeyJwk: JSON.stringify(jwkPriv),
  };
}

// 2. Perform Diffie-Hellman Key Agreement
export async function computeSharedSecret(myPrivJwk: string, counterpartyPubHex: string): Promise<Uint8Array> {
  await detectCryptoCapabilities();
  const keyType = CRYPTO_ALGO === "X25519" ? { name: "X25519" } : { name: "ECDH", curve: ECDH_CURVE };

  const privKey = await window.crypto.subtle.importKey(
    "jwk",
    JSON.parse(myPrivJwk),
    keyType,
    false,
    ["deriveBits"]
  );

  const pubKey = await window.crypto.subtle.importKey(
    "raw",
    hexToBuf(counterpartyPubHex),
    keyType,
    true,
    []
  );

  const sharedBits = await window.crypto.subtle.deriveBits(
    {
      name: CRYPTO_ALGO,
      public: pubKey,
    } as any,
    privKey,
    256
  );

  return new Uint8Array(sharedBits);
}

// 3. HKDF-SHA256 Multiplier
export async function ratchetChainKey(chainKeyBytes: Uint8Array): Promise<{ nextChainKey: Uint8Array; messageDek: Uint8Array }> {
  const baseKey = await window.crypto.subtle.importKey(
    "raw",
    chainKeyBytes,
    { name: "HKDF" },
    false,
    ["deriveBits"]
  );

  const derivedBits = await window.crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: new TextEncoder().encode("huggchat-msg-chain"),
    },
    baseKey,
    512 // 512 bits = 64 bytes total
  );

  const derivedBytes = new Uint8Array(derivedBits);
  return {
    nextChainKey: derivedBytes.slice(0, 32),
    messageDek: derivedBytes.slice(32, 64),
  };
}

// 4. AES-GCM-256 Encryption
export async function encryptPayload(plaintext: Uint8Array, keyBytes: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await window.crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
      tagLength: 128,
    },
    cryptoKey,
    plaintext
  );

  // Prepend IV to ciphertext
  const result = new Uint8Array(iv.length + ciphertext.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(ciphertext), iv.length);
  return result;
}

// 5. AES-GCM-256 Decryption
export async function decryptPayload(ciphertextWithIv: Uint8Array, keyBytes: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await window.crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const iv = ciphertextWithIv.slice(0, 12);
  const ciphertext = ciphertextWithIv.slice(12);

  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
      tagLength: 128,
    },
    cryptoKey,
    ciphertext
  );

  return new Uint8Array(decrypted);
}

// 6. Master Encryption Key (MEK) Wrapping
export async function deriveKeyFromPrf(prfSeedBytes: Uint8Array): Promise<Uint8Array> {
  // Use PRF seed (32 bytes) as high-entropy source to derive AES-GCM wrap-key
  const prfHash = await window.crypto.subtle.digest("SHA-256", prfSeedBytes);
  return new Uint8Array(prfHash);
}

export async function wrapMek(mek: Uint8Array, prfSeedBytes: Uint8Array): Promise<string> {
  const wrappingKeyBytes = await deriveKeyFromPrf(prfSeedBytes);
  const wrapped = await encryptPayload(mek, wrappingKeyBytes);
  return bufToHex(wrapped);
}

export async function unwrapMek(wrappedMekHex: string, prfSeedBytes: Uint8Array): Promise<Uint8Array> {
  const wrappingKeyBytes = await deriveKeyFromPrf(prfSeedBytes);
  const wrapped = hexToBuf(wrappedMekHex);
  return await decryptPayload(wrapped, wrappingKeyBytes);
}

// 7. Argon2id recovery calculation
export async function deriveRecoveryKeyFromPass(password: string, saltHex: string): Promise<Uint8Array> {
  const saltBytes = hexToBuf(saltHex);
  const derived = await argon2id({
    password: password,
    salt: saltBytes,
    parallelism: 1,
    iterations: 3,
    memorySize: 4096, // 4MB - friendly brower limits
    hashLength: 32,
    outputType: "binary",
  });
  return derived;
}

// 8. Pack binary communications frame
export function packMessage(type: "text" | "audio", rawDataBytes: Uint8Array): Uint8Array {
  const headerByte = type === "text" ? 0x01 : 0x02;
  const packed = new Uint8Array(1 + rawDataBytes.length);
  packed[0] = headerByte;
  packed.set(rawDataBytes, 1);
  return packed;
}

// 9. Unpack binary communications frame
export function unpackMessage(packedBytes: Uint8Array): { type: "text" | "audio"; data: Uint8Array } {
  const headerByte = packedBytes[0];
  const data = packedBytes.slice(1);
  const type = headerByte === 0x01 ? "text" : "audio";
  return { type, data };
}
