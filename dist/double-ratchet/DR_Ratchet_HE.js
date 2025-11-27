"use strict";
/**
 * Double Ratchet mit Header Encryption
 * Implementiert Signal Protocol Specification Section 4.5 und 4.6
 * https://signal.org/docs/specifications/doubleratchet/
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.ratchetEncryptHE = ratchetEncryptHE;
exports.ratchetDecryptHE = ratchetDecryptHE;
const HeaderEncryption_1 = require("./HeaderEncryption");
const HKDF_1 = require("./HKDF");
const CryptoUtils_1 = require("./CryptoUtils");
/**
 * Leitet einen Message Key aus einem Chain Key ab
 */
async function deriveMessageKey(chainKey) {
    const hkdf = new HKDF_1.HKDF('SHA-512');
    const derived = await hkdf.deriveKeys(new Uint8Array(32), chainKey, 64);
    const newChainKey = derived.slice(0, 32);
    const messageKey = derived.slice(32, 64);
    return [newChainKey, messageKey];
}
/**
 * Verschlüsselt eine Nachricht mit AES-256-GCM
 */
async function encryptMessageContent(messageKey, plaintext, encryptedHeader, associatedData) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey('raw', messageKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    // Signal Spec: CONCAT(AD, enc_header)
    const ad = associatedData
        ? concatArrays(associatedData, encryptedHeader)
        : encryptedHeader;
    const ciphertext = await crypto.subtle.encrypt({
        name: 'AES-GCM',
        iv: iv,
        additionalData: ad
    }, key, plaintext);
    const result = new Uint8Array(iv.length + ciphertext.byteLength);
    result.set(iv);
    result.set(new Uint8Array(ciphertext), iv.length);
    return result;
}
/**
 * Entschlüsselt eine Nachricht mit AES-256-GCM
 */
async function decryptMessageContent(messageKey, ciphertext, encryptedHeader, associatedData) {
    const iv = ciphertext.slice(0, 12);
    const actualCiphertext = ciphertext.slice(12);
    const key = await crypto.subtle.importKey('raw', messageKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    // Signal Spec: CONCAT(AD, enc_header)
    const ad = associatedData
        ? concatArrays(associatedData, encryptedHeader)
        : encryptedHeader;
    const plaintext = await crypto.subtle.decrypt({
        name: 'AES-GCM',
        iv: iv,
        additionalData: ad
    }, key, actualCiphertext);
    return new Uint8Array(plaintext);
}
/**
 * Verschlüsselt eine Nachricht mit Header Encryption
 * Signal Spec Section 4.5: RatchetEncryptHE
 *
 * @param state - Aktueller DRStateHE
 * @param plaintext - Zu verschlüsselnde Nachricht
 * @param associatedData - Optional: Associated Data
 * @returns Tuple mit [verschlüsselte Nachricht, neuer State]
 */
async function ratchetEncryptHE(state, plaintext, associatedData) {
    // Signal Spec: state.CKs, mk = KDF_CK(state.CKs)
    const [newSendingChainKey, messageKey] = await deriveMessageKey(state.sendingChainKey);
    // Signal Spec: header = HEADER(state.DHRs, state.PN, state.Ns)
    const header = {
        dh: state.ourEphemeralKeyPair.publicKey,
        pn: state.pn,
        n: state.messageNumbers.sending
    };
    // Signal Spec: enc_header = HENCRYPT(state.HKs, header)
    const encryptedHeader = await (0, HeaderEncryption_1.encryptHeader)(state.sendingHeaderKey, header);
    // Signal Spec: ENCRYPT(mk, plaintext, CONCAT(AD, enc_header))
    const ciphertext = await encryptMessageContent(messageKey, plaintext, encryptedHeader, associatedData);
    // Signal Spec: state.Ns += 1
    const newState = {
        ...state,
        sendingChainKey: newSendingChainKey,
        messageNumbers: {
            ...state.messageNumbers,
            sending: state.messageNumbers.sending + 1
        }
    };
    return [{ encryptedHeader, ciphertext }, newState];
}
/**
 * Entschlüsselt eine Nachricht mit Header Encryption
 * Signal Spec Section 4.6: RatchetDecryptHE
 *
 * @param state - Aktueller DRStateHE
 * @param message - Verschlüsselte Nachricht
 * @param associatedData - Optional: Associated Data
 * @returns Tuple mit [entschlüsselte Nachricht, neuer State]
 */
async function ratchetDecryptHE(state, message, associatedData) {
    // Signal Spec: plaintext = TrySkippedMessageKeysHE(state, enc_header, ciphertext, AD)
    const skippedResult = await trySkippedMessageKeysHE(state, message, associatedData);
    if (skippedResult) {
        return skippedResult;
    }
    // Signal Spec: header, dh_ratchet = DecryptHeader(state, enc_header)
    const { header, dhRatchet } = await decryptHeaderHE(state, message.encryptedHeader);
    if (dhRatchet) {
        // Signal Spec: SkipMessageKeysHE(state, header.pn)
        state = await skipMessageKeysHE(state, header.pn);
        // Signal Spec: DHRatchetHE(state, header)
        state = await performDHRatchetHE(state, header);
    }
    // Signal Spec: SkipMessageKeysHE(state, header.n)
    state = await skipMessageKeysHE(state, header.n);
    // Signal Spec: state.CKr, mk = KDF_CK(state.CKr)
    const [newReceivingChainKey, messageKey] = await deriveMessageKey(state.receivingChainKey);
    // Signal Spec: state.Nr += 1
    const newState = {
        ...state,
        receivingChainKey: newReceivingChainKey,
        messageNumbers: {
            ...state.messageNumbers,
            receiving: header.n + 1
        }
    };
    // Signal Spec: DECRYPT(mk, ciphertext, CONCAT(AD, enc_header))
    const plaintext = await decryptMessageContent(messageKey, message.ciphertext, message.encryptedHeader, associatedData);
    return [plaintext, newState];
}
/**
 * Signal Spec: DecryptHeader - Versuche Header mit HKr oder NHKr zu entschlüsseln
 */
async function decryptHeaderHE(state, encryptedHeader) {
    // Signal Spec: header = HDECRYPT(state.HKr, enc_header)
    let header = await (0, HeaderEncryption_1.decryptHeader)(state.receivingHeaderKey, encryptedHeader);
    if (header) {
        return { header, dhRatchet: false };
    }
    // Signal Spec: header = HDECRYPT(state.NHKr, enc_header)
    header = await (0, HeaderEncryption_1.decryptHeader)(state.nextReceivingHeaderKey, encryptedHeader);
    if (header) {
        return { header, dhRatchet: true };
    }
    throw new Error('Failed to decrypt header with any available key');
}
/**
 * Signal Spec Section 4.6: DHRatchetHE
 */
async function performDHRatchetHE(state, header) {
    const hkdf = new HKDF_1.HKDF('SHA-512');
    // Signal Spec: state.PN = state.Ns
    const pn = state.messageNumbers.sending;
    // Signal Spec: state.HKs = state.NHKs; state.HKr = state.NHKr
    const sendingHeaderKey = state.nextSendingHeaderKey;
    const receivingHeaderKey = state.nextReceivingHeaderKey;
    // Signal Spec: state.DHRr = header.dh
    const theirPublicKey = header.dh;
    // Signal Spec: state.RK, state.CKr, state.NHKr = KDF_RK_HE(state.RK, DH(state.DHRs, state.DHRr))
    const dhOutput1 = await (0, CryptoUtils_1.deriveSharedSecret)(state.ourEphemeralKeyPair.privateKey, theirPublicKey);
    const [rootKey1, receivingChainKey, nextReceivingHeaderKey] = await hkdf.deriveKeysHE(state.rootKey, dhOutput1);
    // Signal Spec: state.DHRs = GENERATE_DH()
    const newKeyPair = await (0, CryptoUtils_1.generateKeyPair)();
    // Signal Spec: state.RK, state.CKs, state.NHKs = KDF_RK_HE(state.RK, DH(state.DHRs, state.DHRr))
    const dhOutput2 = await (0, CryptoUtils_1.deriveSharedSecret)(newKeyPair.privateKey, theirPublicKey);
    const [rootKey2, sendingChainKey, nextSendingHeaderKey] = await hkdf.deriveKeysHE(rootKey1, dhOutput2);
    return {
        ...state,
        rootKey: rootKey2,
        sendingChainKey: sendingChainKey,
        receivingChainKey: receivingChainKey,
        ourEphemeralKeyPair: newKeyPair,
        theirEphemeralPublicKey: theirPublicKey,
        pn: pn,
        messageNumbers: {
            sending: 0,
            receiving: 0
        },
        sendingHeaderKey: sendingHeaderKey,
        receivingHeaderKey: receivingHeaderKey,
        nextSendingHeaderKey: nextSendingHeaderKey,
        nextReceivingHeaderKey: nextReceivingHeaderKey
    };
}
/**
 * Signal Spec: TrySkippedMessageKeysHE
 */
async function trySkippedMessageKeysHE(state, _message, _associatedData) {
    // Versuche mit allen gespeicherten Header Keys
    for (const [keyId, _skippedKey] of state.skippedMessageKeys.entries()) {
        // Extrahiere Header Key und Message Number aus keyId
        const parts = keyId.split(':');
        if (parts.length !== 2)
            continue;
        const _headerKeyBase64 = parts[0];
        const _n = parseInt(parts[1], 10);
        // Rekonstruiere Header Key (vereinfacht - in Produktion würde man Header Keys separat speichern)
        // Für diese Implementierung überspringen wir die Header-Key-basierte Entschlüsselung
        // da es komplexer State-Management erfordern würde
    }
    return null;
}
/**
 * Signal Spec: SkipMessageKeysHE
 */
async function skipMessageKeysHE(state, until) {
    // Signal Spec: If nothing to skip, return
    if (state.messageNumbers.receiving >= until) {
        return state;
    }
    const maxSkip = state.maxSkippedMessageKeys || 1000;
    if (state.messageNumbers.receiving + maxSkip < until) {
        throw new Error(`Too many skipped messages: ${until - state.messageNumbers.receiving} > ${maxSkip}`);
    }
    let currentChainKey = state.receivingChainKey;
    const newSkippedKeys = new Map(state.skippedMessageKeys);
    while (state.messageNumbers.receiving < until) {
        const [newChainKey, messageKey] = await deriveMessageKey(currentChainKey);
        // Speichere Message Key (vereinfachte Version)
        const keyId = `${btoa(String.fromCharCode(...state.theirEphemeralPublicKey))}:${state.messageNumbers.receiving}`;
        newSkippedKeys.set(keyId, {
            messageKey: messageKey,
            timestamp: Date.now()
        });
        currentChainKey = newChainKey;
        state = {
            ...state,
            messageNumbers: {
                ...state.messageNumbers,
                receiving: state.messageNumbers.receiving + 1
            }
        };
    }
    return {
        ...state,
        receivingChainKey: currentChainKey,
        skippedMessageKeys: newSkippedKeys
    };
}
function concatArrays(a, b) {
    const result = new Uint8Array(a.length + b.length);
    result.set(a);
    result.set(b, a.length);
    return result;
}
