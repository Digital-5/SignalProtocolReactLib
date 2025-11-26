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
export declare function generateKeyPair(): Promise<KeyPair>;
/**
 * Leitet ein gemeinsames Geheimnis mittels X25519 ab
 * Signal Protocol Standard: ECDH mit Curve25519 (RFC 7748)
 * @param privateKeyBytes - Unser privater Schlüssel (32 Bytes)
 * @param publicKeyBytes - Öffentlicher Schlüssel der Gegenseite (32 Bytes)
 * @returns Das abgeleitete gemeinsame Geheimnis (32 Bytes)
 */
export declare function deriveSharedSecret(privateKeyBytes: Uint8Array, publicKeyBytes: Uint8Array): Promise<Uint8Array>;
