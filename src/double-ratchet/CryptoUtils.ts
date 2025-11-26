/**
 * Kryptografische Hilfsfunktionen für das Double Ratchet Protocol
 * Verwendet X25519 (Curve25519) gemäß Signal Protocol Specification
 * Implementiert mit @noble/curves für echte X25519 Unterstützung
 */
import { x25519 } from '@noble/curves/ed25519.js';

/**
 * Schlüsselpaar-Interface für asymmetrische Kryptographie
 */
export interface KeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}

/**
 * Generiert ein neues X25519-Schlüsselpaar (Curve25519)
 * Signal Protocol Standard: Schneller, sicherer gegen Side-Channels
 * @returns Promise mit dem generierten Schlüsselpaar (32 Bytes public, 32 Bytes private)
 */
export async function generateKeyPair(): Promise<KeyPair> {
    // Generiere 32 zufällige Bytes für Private Key
    const privateKey = x25519.utils.randomSecretKey();

    // Berechne Public Key = X25519(privateKey, basepoint)
    const publicKey = x25519.getPublicKey(privateKey);

    return {
        publicKey: new Uint8Array(publicKey),
        privateKey: new Uint8Array(privateKey)
    };
}

/**
 * Leitet ein gemeinsames Geheimnis mittels X25519 ab
 * Signal Protocol Standard: ECDH mit Curve25519 (RFC 7748)
 * @param privateKeyBytes - Unser privater Schlüssel (32 Bytes)
 * @param publicKeyBytes - Öffentlicher Schlüssel der Gegenseite (32 Bytes)
 * @returns Das abgeleitete gemeinsame Geheimnis (32 Bytes)
 */
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

    // X25519(privateKey, publicKey) - Berechne Shared Secret
    const sharedSecret = x25519.getSharedSecret(privateKeyBytes, publicKeyBytes);

    return new Uint8Array(sharedSecret);
}