"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.performDHRatchet = performDHRatchet;
exports.ratchetEncrypt = ratchetEncrypt;
exports.ratchetDecrypt = ratchetDecrypt;
const CryptoUtils_js_1 = require("./CryptoUtils.js");
const HKDF_js_1 = require("./HKDF.js");
/**
 * Führt einen DH Ratchet Step aus (Schlüsselrotation)
 * @param state - Aktueller Double Ratchet State
 * @param theirPublicKey - Neuer öffentlicher Schlüssel der Gegenseite
 * @returns Aktualisierter State
 */
async function performDHRatchet(state, theirPublicKey) {
    // Leite neues Schlüsselpaar ab
    const newKeyPair = await (0, CryptoUtils_js_1.generateKeyPair)();
    // Berechne DH mit dem neuen Schlüssel der Gegenseite
    const dhOutput = await (0, CryptoUtils_js_1.deriveSharedSecret)(state.ourEphemeralKeyPair.privateKey, theirPublicKey);
    // Leite neue Root Key und Receiving Chain Key ab
    const hkdf = new HKDF_js_1.HKDF('SHA-256');
    const derivedKeys1 = await hkdf.deriveKeys(state.rootKey, dhOutput, 64);
    const newRootKey1 = derivedKeys1.slice(0, 32);
    const newReceivingChainKey = derivedKeys1.slice(32, 64);
    // Berechne DH mit unserem neuen Schlüssel
    const dhOutput2 = await (0, CryptoUtils_js_1.deriveSharedSecret)(newKeyPair.privateKey, theirPublicKey);
    // Leite finale Root Key und Sending Chain Key ab
    const derivedKeys2 = await hkdf.deriveKeys(newRootKey1, dhOutput2, 64);
    const newRootKey2 = derivedKeys2.slice(0, 32);
    const newSendingChainKey = derivedKeys2.slice(32, 64);
    return {
        rootKey: newRootKey2,
        sendingChainKey: newSendingChainKey,
        receivingChainKey: newReceivingChainKey,
        ourEphemeralKeyPair: newKeyPair,
        theirEphemeralPublicKey: theirPublicKey,
        messageNumbers: {
            sending: 0,
            receiving: 0
        }
    };
}
/**
 * Leitet einen Message Key aus einem Chain Key ab (Symmetric Ratchet)
 * @param chainKey - Der aktuelle Chain Key
 * @returns Tuple mit [neuer Chain Key, Message Key]
 */
async function deriveMessageKey(chainKey) {
    const hkdf = new HKDF_js_1.HKDF('SHA-256');
    // Verwende den Chain Key als Input und leite neuen Chain Key + Message Key ab
    const derived = await hkdf.deriveKeys(new Uint8Array(32), // Empty salt
    chainKey, 64 // 32 Bytes für neuen Chain Key + 32 Bytes für Message Key
    );
    const newChainKey = derived.slice(0, 32);
    const messageKey = derived.slice(32, 64);
    return [newChainKey, messageKey];
}
/**
 * Verschlüsselt eine Nachricht mit AES-256-GCM
 * @param messageKey - Der Message Key für die Verschlüsselung
 * @param plaintext - Die zu verschlüsselnde Nachricht
 * @returns Die verschlüsselte Nachricht (inkl. IV)
 */
async function encryptMessage(messageKey, plaintext) {
    // Generiere einen zufälligen IV (12 Bytes für GCM)
    const iv = crypto.getRandomValues(new Uint8Array(12));
    // Importiere den Message Key
    const key = await crypto.subtle.importKey('raw', messageKey, { name: 'AES-GCM' }, false, ['encrypt']);
    // Verschlüssele die Nachricht
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
    // Kombiniere IV + Ciphertext
    const result = new Uint8Array(iv.length + ciphertext.byteLength);
    result.set(iv);
    result.set(new Uint8Array(ciphertext), iv.length);
    return result;
}
/**
 * Entschlüsselt eine Nachricht mit AES-256-GCM
 * @param messageKey - Der Message Key für die Entschlüsselung (32 Bytes)
 * @param ciphertext - Die verschlüsselte Nachricht (inkl. IV)
 * @returns Die entschlüsselte Nachricht
 */
async function decryptMessage(messageKey, ciphertext) {
    // Extrahiere IV und Ciphertext
    const iv = ciphertext.slice(0, 12);
    const actualCiphertext = ciphertext.slice(12);
    // Importiere den Message Key (verwende nur die ersten 32 Bytes für AES-256)
    const key = await crypto.subtle.importKey('raw', messageKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    // Entschlüssele die Nachricht
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, actualCiphertext);
    return new Uint8Array(plaintext);
}
/**
 * Verschlüsselt eine Nachricht und aktualisiert den State (Ratchet Step)
 * @param state - Aktueller Double Ratchet State
 * @param plaintext - Die zu verschlüsselnde Nachricht
 * @returns Tuple mit [verschlüsselte Nachricht, aktualisierter State]
 */
async function ratchetEncrypt(state, plaintext) {
    // Leite Message Key aus Sending Chain Key ab
    const [newSendingChainKey, messageKey] = await deriveMessageKey(state.sendingChainKey);
    // Verschlüssele die Nachricht
    const ciphertext = await encryptMessage(messageKey, plaintext);
    // Erstelle die verschlüsselte Nachricht mit Header
    const message = {
        header: {
            publicKey: state.ourEphemeralKeyPair.publicKey,
            messageNumber: state.messageNumbers.sending
        },
        ciphertext
    };
    // Aktualisiere den State
    const newState = {
        ...state,
        sendingChainKey: newSendingChainKey,
        messageNumbers: {
            ...state.messageNumbers,
            sending: state.messageNumbers.sending + 1
        }
    };
    return [message, newState];
}
/**
 * Entschlüsselt eine Nachricht und aktualisiert den State (Ratchet Step)
 * @param state - Aktueller Double Ratchet State
 * @param message - Die verschlüsselte Nachricht
 * @returns Tuple mit [entschlüsselte Nachricht, aktualisierter State]
 */
async function ratchetDecrypt(state, message) {
    let currentState = state;
    // Prüfe, ob wir einen DH Ratchet Step durchführen müssen
    // (wenn sich der öffentliche Schlüssel der Gegenseite geändert hat)
    const receivedPublicKey = message.header.publicKey;
    const currentPublicKey = state.theirEphemeralPublicKey;
    // Vergleiche die öffentlichen Schlüssel
    const keysAreDifferent = !arraysEqual(receivedPublicKey, currentPublicKey);
    if (keysAreDifferent) {
        // Führe DH Ratchet aus
        currentState = await performDHRatchet(currentState, receivedPublicKey);
    }
    // Leite Message Key aus Receiving Chain Key ab
    const [newReceivingChainKey, messageKey] = await deriveMessageKey(currentState.receivingChainKey);
    // Entschlüssele die Nachricht
    const plaintext = await decryptMessage(messageKey, message.ciphertext);
    // Aktualisiere den State
    const newState = {
        ...currentState,
        receivingChainKey: newReceivingChainKey,
        messageNumbers: {
            ...currentState.messageNumbers,
            receiving: message.header.messageNumber + 1
        }
    };
    return [plaintext, newState];
}
/**
 * Hilfsfunktion zum Vergleich von zwei Uint8Arrays
 * @param a - Erstes Array
 * @param b - Zweites Array
 * @returns true wenn beide Arrays identisch sind
 */
function arraysEqual(a, b) {
    if (a.length !== b.length)
        return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i])
            return false;
    }
    return true;
}
