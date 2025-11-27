"use strict";
/**
 * Header Encryption für Double Ratchet
 * Implementiert Signal Protocol Specification Section 4
 * https://signal.org/docs/specifications/doubleratchet/
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.encryptHeader = encryptHeader;
exports.decryptHeader = decryptHeader;
/**
 * Verschlüsselt einen Message Header mit AES-256-GCM
 * Signal Spec Section 4.2: HENCRYPT(hk, plaintext)
 *
 * @param headerKey - Der Header Key für die Verschlüsselung (32 Bytes)
 * @param header - Der zu verschlüsselnde Header
 * @returns Verschlüsselter Header (inkl. IV)
 */
async function encryptHeader(headerKey, header) {
    // Serialisiere Header zu Bytes
    const headerBytes = serializeHeaderForEncryption(header);
    // Generiere einen zufälligen IV (12 Bytes für GCM)
    // Signal Spec: "AEAD nonce must either be stateful non-repeating value,
    // or must be random non-repeating value chosen with at least 128 bits of entropy"
    const iv = crypto.getRandomValues(new Uint8Array(12));
    // Importiere Header Key
    const key = await crypto.subtle.importKey('raw', headerKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    // Verschlüssele Header mit AES-256-GCM
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, headerBytes);
    // Kombiniere IV + Ciphertext
    const result = new Uint8Array(iv.length + ciphertext.byteLength);
    result.set(iv);
    result.set(new Uint8Array(ciphertext), iv.length);
    return result;
}
/**
 * Entschlüsselt einen verschlüsselten Message Header
 * Signal Spec Section 4.2: HDECRYPT(hk, ciphertext)
 *
 * @param headerKey - Der Header Key für die Entschlüsselung (32 Bytes)
 * @param encryptedHeader - Der verschlüsselte Header (inkl. IV)
 * @returns Entschlüsselter Header oder null bei Fehler
 */
async function decryptHeader(headerKey, encryptedHeader) {
    // Signal Spec: "If authentication fails, or if the header key hk is empty (None), returns None"
    if (!headerKey) {
        return null;
    }
    try {
        // Extrahiere IV und Ciphertext
        const iv = encryptedHeader.slice(0, 12);
        const ciphertext = encryptedHeader.slice(12);
        // Importiere Header Key
        const key = await crypto.subtle.importKey('raw', headerKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
        // Entschlüssele Header
        const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ciphertext);
        // Deserialisiere Header
        return deserializeHeaderFromEncryption(new Uint8Array(plaintext));
    }
    catch {
        // Signal Spec: "If authentication fails ... returns None"
        return null;
    }
}
/**
 * Serialisiert einen Message Header zu Bytes für Verschlüsselung
 * Format: dh_length(2) + dh + pn(4) + n(4)
 */
function serializeHeaderForEncryption(header) {
    const dhLength = header.dh.length;
    const result = new Uint8Array(2 + dhLength + 4 + 4);
    const view = new DataView(result.buffer);
    // DH Public Key Länge (2 Bytes)
    view.setUint16(0, dhLength, false);
    // DH Public Key
    result.set(header.dh, 2);
    // PN (4 Bytes)
    view.setUint32(2 + dhLength, header.pn, false);
    // N (4 Bytes)
    view.setUint32(2 + dhLength + 4, header.n, false);
    return result;
}
/**
 * Deserialisiert einen Message Header von Bytes
 */
function deserializeHeaderFromEncryption(data) {
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    // DH Public Key Länge
    const dhLength = view.getUint16(0, false);
    // DH Public Key
    const dh = data.slice(2, 2 + dhLength);
    // PN
    const pn = view.getUint32(2 + dhLength, false);
    // N
    const n = view.getUint32(2 + dhLength + 4, false);
    return { dh, pn, n };
}
