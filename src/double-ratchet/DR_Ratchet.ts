/**
 * Double Ratchet Core Funktionen
 * Implementiert Verschlüsselung, Entschlüsselung und Ratchet Steps
 */
import { DRState } from "./DR_State";
import { generateKeyPair, deriveSharedSecret } from "./CryptoUtils";
import { HKDF } from "./HKDF";

/**
 * Verschlüsselte Nachricht mit Header-Informationen
 */
export interface RatchetMessage {
    /** Der öffentliche ephemere Schlüssel des Senders */
    header: {
        publicKey: Uint8Array;
        messageNumber: number;
    };
    /** Die verschlüsselte Nachricht */
    ciphertext: Uint8Array;
}

/**
 * Führt einen DH Ratchet Step aus (Schlüsselrotation)
 * @param state - Aktueller Double Ratchet State
 * @param theirPublicKey - Neuer öffentlicher Schlüssel der Gegenseite
 * @returns Aktualisierter State
 */
export async function performDHRatchet(state: DRState, theirPublicKey: Uint8Array): Promise<DRState> {
    // Leite neues Schlüsselpaar ab
    const newKeyPair = await generateKeyPair();

    // Berechne DH mit dem neuen Schlüssel der Gegenseite
    const dhOutput = await deriveSharedSecret(state.ourEphemeralKeyPair.privateKey, theirPublicKey);

    // Leite neue Root Key und Receiving Chain Key ab
    const hkdf = new HKDF('SHA-512');
    const derivedKeys1 = await hkdf.deriveKeys(state.rootKey, dhOutput, 64);
    const newRootKey1 = derivedKeys1.slice(0, 32);
    const newReceivingChainKey = derivedKeys1.slice(32, 64);

    // Berechne DH mit unserem neuen Schlüssel
    const dhOutput2 = await deriveSharedSecret(newKeyPair.privateKey, theirPublicKey);

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
        },
        skippedMessageKeys: state.skippedMessageKeys, // Behalte vorhandene Skipped Keys
        maxSkippedMessageKeys: state.maxSkippedMessageKeys
    };
}

/**
 * Leitet einen Message Key aus einem Chain Key ab (Symmetric Ratchet)
 * @param chainKey - Der aktuelle Chain Key
 * @returns Tuple mit [neuer Chain Key, Message Key]
 */
async function deriveMessageKey(chainKey: Uint8Array): Promise<[Uint8Array, Uint8Array]> {
    const hkdf = new HKDF('SHA-256');

    // Verwende den Chain Key als Input und leite neuen Chain Key + Message Key ab
    const derived = await hkdf.deriveKeys(
        new Uint8Array(32), // Empty salt
        chainKey,
        64 // 32 Bytes für neuen Chain Key + 32 Bytes für Message Key
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
async function encryptMessage(messageKey: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
    // Generiere einen zufälligen IV (12 Bytes für GCM)
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Importiere den Message Key
    const key = await crypto.subtle.importKey(
        'raw',
        messageKey as BufferSource,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    );

    // Verschlüssele die Nachricht
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        plaintext as BufferSource
    );

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
async function decryptMessage(messageKey: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
    // Extrahiere IV und Ciphertext
    const iv = ciphertext.slice(0, 12);
    const actualCiphertext = ciphertext.slice(12);

    // Importiere den Message Key (verwende nur die ersten 32 Bytes für AES-256)
    const key = await crypto.subtle.importKey(
        'raw',
        messageKey as BufferSource,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );

    // Entschlüssele die Nachricht
    const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv as BufferSource },
        key,
        actualCiphertext as BufferSource
    );

    return new Uint8Array(plaintext);
}

/**
 * Verschlüsselt eine Nachricht und aktualisiert den State (Ratchet Step)
 * @param state - Aktueller Double Ratchet State
 * @param plaintext - Die zu verschlüsselnde Nachricht
 * @returns Tuple mit [verschlüsselte Nachricht, aktualisierter State]
 */
export async function ratchetEncrypt(
    state: DRState,
    plaintext: Uint8Array
): Promise<[RatchetMessage, DRState]> {
    // Leite Message Key aus Sending Chain Key ab
    const [newSendingChainKey, messageKey] = await deriveMessageKey(state.sendingChainKey);

    // Verschlüssele die Nachricht
    const ciphertext = await encryptMessage(messageKey, plaintext);

    // Erstelle die verschlüsselte Nachricht mit Header
    const message: RatchetMessage = {
        header: {
            publicKey: state.ourEphemeralKeyPair.publicKey,
            messageNumber: state.messageNumbers.sending
        },
        ciphertext
    };

    // Aktualisiere den State
    const newState: DRState = {
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
export async function ratchetDecrypt(
    state: DRState,
    message: RatchetMessage
): Promise<[Uint8Array, DRState]> {
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
    const newState: DRState = {
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
async function skipMessageKeys(state: DRState, untilMessageNumber: number): Promise<DRState> {
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
function createSkippedKeyId(publicKey: Uint8Array, messageNumber: number): string {
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
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

