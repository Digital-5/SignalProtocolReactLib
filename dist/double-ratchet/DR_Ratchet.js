"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.performDHRatchet = performDHRatchet;
exports.ratchetEncrypt = ratchetEncrypt;
exports.ratchetDecrypt = ratchetDecrypt;
const CryptoUtils_1 = require("./CryptoUtils");
const HKDF_1 = require("./HKDF");
/**
 * Führt einen DH Ratchet Step aus (Schlüsselrotation)
 * @param state - Aktueller Double Ratchet State
 * @param theirPublicKey - Neuer öffentlicher Schlüssel der Gegenseite
 * @returns Aktualisierter State
 */
async function performDHRatchet(state, theirPublicKey) {
    // Leite neues Schlüsselpaar ab
    const newKeyPair = await (0, CryptoUtils_1.generateKeyPair)();
    // Berechne DH mit dem neuen Schlüssel der Gegenseite
    const dhOutput = await (0, CryptoUtils_1.deriveSharedSecret)(state.ourEphemeralKeyPair.privateKey, theirPublicKey);
    // Leite neue Root Key und Receiving Chain Key ab
    const hkdf = new HKDF_1.HKDF('SHA-512');
    const derivedKeys1 = await hkdf.deriveKeys(state.rootKey, dhOutput, 64);
    const newRootKey1 = derivedKeys1.slice(0, 32);
    const newReceivingChainKey = derivedKeys1.slice(32, 64);
    // Berechne DH mit unserem neuen Schlüssel
    const dhOutput2 = await (0, CryptoUtils_1.deriveSharedSecret)(newKeyPair.privateKey, theirPublicKey);
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
    const hkdf = new HKDF_1.HKDF('SHA-256');
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
 * Unterstützt Out-of-Order Messages durch Skipped Message Keys
 * @param state - Aktueller Double Ratchet State
 * @param message - Die verschlüsselte Nachricht
 * @returns Tuple mit [entschlüsselte Nachricht, aktualisierter State]
 */
async function ratchetDecrypt(state, message) {
    const receivedPublicKey = message.header.publicKey;
    const messageNumber = message.header.messageNumber;
    // Erstelle Schlüssel für Skipped Message Keys Map
    const skippedKeyId = createSkippedKeyId(receivedPublicKey, messageNumber);
    // 1. Prüfe, ob wir bereits einen Skipped Message Key für diese Nachricht haben
    const skippedKey = state.skippedMessageKeys.get(skippedKeyId);
    if (skippedKey) {
        // Entschlüssele mit dem gespeicherten Key
        const plaintext = await decryptMessage(skippedKey.messageKey, message.ciphertext);
        // Entferne den verwendeten Key
        const newSkippedKeys = new Map(state.skippedMessageKeys);
        newSkippedKeys.delete(skippedKeyId);
        return [plaintext, {
                ...state,
                skippedMessageKeys: newSkippedKeys
            }];
    }
    // 2. Prüfe, ob wir einen DH Ratchet Step durchführen müssen
    const keysAreDifferent = !arraysEqual(receivedPublicKey, state.theirEphemeralPublicKey);
    let currentState = state;
    if (keysAreDifferent) {
        // Speichere alle Skipped Message Keys bis zum aktuellen Message Number
        currentState = await skipMessageKeys(currentState, state.messageNumbers.receiving);
        // Führe DH Ratchet aus
        currentState = await performDHRatchet(currentState, receivedPublicKey);
    }
    // 3. Überspringe Nachrichten, die wir nicht erhalten haben (Out-of-Order)
    if (messageNumber > currentState.messageNumbers.receiving) {
        currentState = await skipMessageKeys(currentState, messageNumber);
    }
    // 4. Leite Message Key ab und entschlüssele
    const [newReceivingChainKey, messageKey] = await deriveMessageKey(currentState.receivingChainKey);
    const plaintext = await decryptMessage(messageKey, message.ciphertext);
    // 5. Aktualisiere State
    const newState = {
        ...currentState,
        receivingChainKey: newReceivingChainKey,
        messageNumbers: {
            ...currentState.messageNumbers,
            receiving: messageNumber + 1
        }
    };
    return [plaintext, newState];
}
/**
 * Überspringt Message Keys für fehlende Nachrichten (Out-of-Order)
 * @param state - Aktueller State
 * @param untilMessageNumber - Bis zu welcher Message Number übersprungen werden soll
 * @returns Aktualisierter State mit gespeicherten Skipped Message Keys
 */
async function skipMessageKeys(state, untilMessageNumber) {
    const maxSkip = state.maxSkippedMessageKeys || 1000;
    const currentReceiving = state.messageNumbers.receiving;
    // DoS-Schutz: Verhindere zu viele Skipped Keys
    if (untilMessageNumber - currentReceiving > maxSkip) {
        throw new Error(`Too many skipped messages: ${untilMessageNumber - currentReceiving} > ${maxSkip}`);
    }
    let currentChainKey = state.receivingChainKey;
    const newSkippedKeys = new Map(state.skippedMessageKeys);
    // Leite Message Keys für alle übersprungenen Nachrichten ab
    for (let i = currentReceiving; i < untilMessageNumber; i++) {
        const [newChainKey, messageKey] = await deriveMessageKey(currentChainKey);
        // Speichere den Message Key
        const keyId = createSkippedKeyId(state.theirEphemeralPublicKey, i);
        newSkippedKeys.set(keyId, {
            messageKey: messageKey,
            timestamp: Date.now()
        });
        currentChainKey = newChainKey;
    }
    // Cleanup alte Skipped Keys (älter als 7 Tage)
    const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    for (const [keyId, skippedKey] of newSkippedKeys.entries()) {
        if (skippedKey.timestamp < sevenDaysAgo) {
            newSkippedKeys.delete(keyId);
        }
    }
    return {
        ...state,
        receivingChainKey: currentChainKey,
        skippedMessageKeys: newSkippedKeys
    };
}
/**
 * Erstellt einen eindeutigen Identifier für einen Skipped Message Key
 * @param publicKey - Der öffentliche Schlüssel
 * @param messageNumber - Die Message Number
 * @returns String-Identifier im Format "base64(publicKey):messageNumber"
 */
function createSkippedKeyId(publicKey, messageNumber) {
    // Konvertiere Public Key zu Base64 für Map-Key
    const keyBase64 = btoa(String.fromCharCode(...Array.from(publicKey)));
    return `${keyBase64}:${messageNumber}`;
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
