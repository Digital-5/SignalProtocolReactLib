import {x25519} from "@noble/curves/ed25519.js";

export function generateX25519KeyPair() {
    const privateKey = x25519.utils.randomSecretKey();

    // For X25519 compatibility AND XEdDSA, we need to:
    // 1. Clamp the private key as X25519 requires
    // 2. Generate the public key using the clamped key

    // X25519 clamping (RFC 7748) Chapter 5 (Page 8):
    // - Clear bits 0, 1, 2 of the first byte
    // - Clear bit 255 of the last byte
    // - Set bit 254 of the last byte
    const clampedPrivateKey = new Uint8Array(privateKey);
    clampedPrivateKey[0] &= 248;  // Clear bottom 3 bits
    clampedPrivateKey[31] &= 127; // Clear bit 255
    clampedPrivateKey[31] |= 64;  // Set bit 254

    // Now generate the public key using the standard X25519 method
    // This ensures compatibility with standard X25519 DH
    const publicKey = x25519.getPublicKey(clampedPrivateKey);

    return {
        privateKey: clampedPrivateKey,
        publicKey
    };
}

export async function deriveSharedSecret(
    privateKeyBytes: Uint8Array,
    publicKeyBytes: Uint8Array
): Promise<Uint8Array> {
    // Validierung
    if (privateKeyBytes.length !== 32) {
        throw new Error(`X25519 private key must be 32 bytes, got ${privateKeyBytes.length}`);
    }
    if (publicKeyBytes.length !== 32) {
        throw new Error(`X25519 public key must be 32 bytes, got ${publicKeyBytes.length}`);
    }

    // X25519(privateKey, publicKey) - Use standard X25519 scalar multiplication
    // The public key is already in Montgomery u-coordinate format
    // The private key is the raw scalar
    const sharedSecret = x25519.getSharedSecret(privateKeyBytes, publicKeyBytes);

    return new Uint8Array(sharedSecret);
}