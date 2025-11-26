"use strict";
/**
 * Kryptografische Hilfsfunktionen für das Double Ratchet Protocol
 * Verwendet ECDH (Elliptic Curve Diffie-Hellman) mit P-256 Kurve
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateKeyPair = generateKeyPair;
exports.deriveSharedSecret = deriveSharedSecret;
/**
 * Generiert ein neues ECDH-Schlüsselpaar (P-256)
 * @returns Promise mit dem generierten Schlüsselpaar
 */
async function generateKeyPair() {
    // Generiere ein ECDH-Schlüsselpaar mit P-256 Kurve
    const keyPair = await crypto.subtle.generateKey({
        name: "ECDH",
        namedCurve: "P-256",
    }, true, ["deriveKey", "deriveBits"]);
    // Exportiere die Schlüssel als Byte-Arrays
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
    const privateKey = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
    return { publicKey, privateKey };
}
/**
 * Leitet ein gemeinsames Geheimnis mittels ECDH ab
 * @param privateKeyBytes - Unser privater Schlüssel (PKCS#8 Format)
 * @param publicKeyBytes - Öffentlicher Schlüssel der Gegenseite (Raw Format)
 * @returns Das abgeleitete gemeinsame Geheimnis (32 Bytes)
 */
async function deriveSharedSecret(privateKeyBytes, publicKeyBytes) {
    // Importiere unseren privaten Schlüssel
    const privateKey = await crypto.subtle.importKey("pkcs8", privateKeyBytes.buffer, {
        name: "ECDH",
        namedCurve: "P-256",
    }, false, ["deriveBits"]);
    // Importiere den öffentlichen Schlüssel der Gegenseite
    const publicKey = await crypto.subtle.importKey("raw", publicKeyBytes.buffer, {
        name: "ECDH",
        namedCurve: "P-256",
    }, false, []);
    // Führe ECDH aus und erhalte das gemeinsame Geheimnis
    const sharedSecret = await crypto.subtle.deriveBits({
        name: "ECDH",
        public: publicKey,
    }, privateKey, 256 // 256 Bits = 32 Bytes
    );
    return new Uint8Array(sharedSecret);
}
