/**
 * Kryptografische Hilfsfunktionen für das Double Ratchet Protocol
 * Verwendet ECDH (Elliptic Curve Diffie-Hellman) mit P-256 Kurve
 */
/**
 * Schlüsselpaar-Interface für asymmetrische Kryptographie
 */
export interface KeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}
/**
 * Generiert ein neues ECDH-Schlüsselpaar (P-256)
 * @returns Promise mit dem generierten Schlüsselpaar
 */
export declare function generateKeyPair(): Promise<KeyPair>;
/**
 * Leitet ein gemeinsames Geheimnis mittels ECDH ab
 * @param privateKeyBytes - Unser privater Schlüssel (PKCS#8 Format)
 * @param publicKeyBytes - Öffentlicher Schlüssel der Gegenseite (Raw Format)
 * @returns Das abgeleitete gemeinsame Geheimnis (32 Bytes)
 */
export declare function deriveSharedSecret(privateKeyBytes: Uint8Array, publicKeyBytes: Uint8Array): Promise<Uint8Array>;
