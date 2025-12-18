/**
 * Kryptografische Hilfsfunktionen für das Double Ratchet Protocol
 * Verwendet X25519 (Curve25519) gemäß Signal Protocol Specification
 * Implementiert mit @noble/curves für echte X25519 Unterstützung
 */
import {x25519} from '@noble/curves/ed25519.js';
import {gcm} from '@noble/ciphers/aes.js';
import {randomBytes} from '@noble/hashes/utils.js';

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

/**
 * Generiert kryptografisch sichere Zufallsbytes
 * Verwendet @noble/hashes für React Native Kompatibilität
 * @param length - Anzahl der zu generierenden Bytes
 * @returns Uint8Array mit Zufallsbytes
 */
export function getRandomBytes(length: number): Uint8Array {
    return randomBytes(length);
}

/**
 * Verschlüsselt Daten mit AES-256-GCM
 * @param key - 32-Byte Verschlüsselungsschlüssel
 * @param plaintext - Zu verschlüsselnde Daten
 * @param additionalData - Optional: Zusätzliche authentifizierte Daten (AEAD)
 * @returns Verschlüsselte Daten (12 Bytes IV + Ciphertext + 16 Bytes Auth-Tag)
 */
export function aesGcmEncrypt(
    key: Uint8Array,
    plaintext: Uint8Array,
    additionalData?: Uint8Array
): Uint8Array {
    if (key.length !== 32) {
        throw new Error(`AES-256-GCM requires 32-byte key, got ${key.length}`);
    }

    // Generiere 12-Byte IV (Nonce) für GCM
    const iv = getRandomBytes(12);

    // Erstelle AES-GCM Cipher
    const cipher = gcm(key, iv, additionalData);

    // Verschlüssele (enthält automatisch 16-Byte Auth-Tag am Ende)
    const ciphertext = cipher.encrypt(plaintext);

    // Kombiniere IV + Ciphertext (IV muss für Entschlüsselung bekannt sein)
    const result = new Uint8Array(iv.length + ciphertext.length);
    result.set(iv, 0);
    result.set(ciphertext, iv.length);

    return result;
}

/**
 * Entschlüsselt Daten mit AES-256-GCM
 * @param key - 32-Byte Verschlüsselungsschlüssel
 * @param encryptedData - Verschlüsselte Daten (IV + Ciphertext + Auth-Tag)
 * @param additionalData - Optional: Zusätzliche authentifizierte Daten (AEAD)
 * @returns Entschlüsselte Daten
 * @throws Error wenn Authentifizierung fehlschlägt
 */
export function aesGcmDecrypt(
    key: Uint8Array,
    encryptedData: Uint8Array,
    additionalData?: Uint8Array
): Uint8Array {
    if (key.length !== 32) {
        throw new Error(`AES-256-GCM requires 32-byte key, got ${key.length}`);
    }
    if (encryptedData.length < 12 + 16) {
        throw new Error('Encrypted data too short (must contain IV and auth tag)');
    }

    // Extrahiere IV (erste 12 Bytes)
    const iv = encryptedData.slice(0, 12);

    // Rest ist Ciphertext + Auth-Tag
    const ciphertext = encryptedData.slice(12);

    // Erstelle AES-GCM Cipher
    const cipher = gcm(key, iv, additionalData);

    // Entschlüssele und validiere Auth-Tag
    // Wirft Error wenn Authentifizierung fehlschlägt
    const plaintext = cipher.decrypt(ciphertext);

    return plaintext;
}