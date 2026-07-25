/**
 * Header Encryption für Double Ratchet
 * Implementiert Signal Protocol Specification Section 4
 * https://signal.org/docs/specifications/doubleratchet/
 */

import {MessageHeader} from './DR_Interfaces';
import {aesGcmEncrypt, aesGcmDecrypt} from './CryptoUtils';

/**
 * Verschlüsselt einen Message Header mit AES-256-GCM
 * Signal Spec Section 4.2: HENCRYPT(hk, plaintext)
 *
 * @param headerKey - Der Header Key für die Verschlüsselung (32 Bytes)
 * @param header - Der zu verschlüsselnde Header
 * @returns Verschlüsselter Header (inkl. IV)
 */
export async function encryptHeader(
    headerKey: Uint8Array,
    header: MessageHeader
): Promise<Uint8Array> {
    // Serialisiere Header zu Bytes
    const headerBytes = serializeHeaderForEncryption(header);

    // Verschlüssele Header mit AES-256-GCM
    // Signal Spec: "AEAD nonce must either be stateful non-repeating value,
    // or must be random non-repeating value chosen with at least 128 bits of entropy"
    const encryptedHeader = aesGcmEncrypt(headerKey, headerBytes);

    return encryptedHeader;
}

/**
 * Entschlüsselt einen verschlüsselten Message Header
 * Signal Spec Section 4.2: HDECRYPT(hk, ciphertext)
 *
 * @param headerKey - Der Header Key für die Entschlüsselung (32 Bytes)
 * @param encryptedHeader - Der verschlüsselte Header (inkl. IV)
 * @returns Entschlüsselter Header oder null bei Fehler
 */
export async function decryptHeader(
    headerKey: Uint8Array | null,
    encryptedHeader: Uint8Array
): Promise<MessageHeader | null> {
    // Signal Spec: "If authentication fails, or if the header key hk is empty (None), returns None"
    if (!headerKey) {
        return null;
    }

    try {
        // Entschlüssele Header mit AES-256-GCM
        const plaintext = aesGcmDecrypt(headerKey, encryptedHeader);

        // Deserialisiere Header
        return deserializeHeaderFromEncryption(plaintext);
    } catch {
        // Signal Spec: "If authentication fails ... returns None"
        return null;
    }
}

/**
 * Serialisiert einen Message Header zu Bytes für Verschlüsselung
 * Format: dh_length(2) + dh + pn(4) + n(4)
 */
function serializeHeaderForEncryption(header: MessageHeader): Uint8Array {
    const MAX_UINT32 = 0xFFFFFFFF;
    if (header.n >= MAX_UINT32) {
        throw new Error(`Message counter n overflow: ${header.n} >= 2^32`);
    }
    if (header.pn >= MAX_UINT32) {
        throw new Error(`Previous chain counter pn overflow: ${header.pn} >= 2^32`);
    }

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
function deserializeHeaderFromEncryption(data: Uint8Array): MessageHeader {
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

    // DH Public Key Länge
    const dhLength = view.getUint16(0, false);
    // DH Public Key
    const dh = data.slice(2, 2 + dhLength);
    // PN
    const pn = view.getUint32(2 + dhLength, false);
    // N
    const n = view.getUint32(2 + dhLength + 4, false);

    return {dh, pn, n};
}

