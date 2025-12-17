/**
 * Double Ratchet mit Header Encryption
 * Implementiert Signal Protocol Specification Section 4.5 und 4.6
 * https://signal.org/docs/specifications/doubleratchet/
 */

import {DRState, MessageHeader, RatchetMessageHE} from './DR_Interfaces';
import {encryptHeader, decryptHeader} from './HeaderEncryption';
import {HKDF} from './HKDF';
import {deriveSharedSecret, generateKeyPair} from './CryptoUtils';



/**
 * Leitet einen Message Key aus einem Chain Key mittels HKDF ab (KDF_CK)
 *
 * @param chainKey - Der aktuelle Chain Key (32 Bytes), darf nicht null sein
 * @returns Tuple aus [neuer Chain Key, Message Key] - jeweils 32 Bytes
 * @throws {Error} Wenn chainKey null ist
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#kdf-chains
 */
async function deriveMessageKey(chainKey: Uint8Array | null): Promise<[Uint8Array, Uint8Array]> {
    if (!chainKey) {
        throw new Error('Cannot derive message key: chain key is null');
    }
    const hkdf = new HKDF('SHA-512');
    const derived = await hkdf.deriveKeys(
        new Uint8Array(32),
        chainKey,
        64
    );
    const newChainKey = derived.slice(0, 32);
    const messageKey = derived.slice(32, 64);
    return [newChainKey, messageKey];
}

/**
 * Verschlüsselt den Nachrichteninhalt mit AES-256-GCM (AEAD)
 *
 * @param messageKey - Der Message Key für die Verschlüsselung (32 Bytes)
 * @param plaintext - Die zu verschlüsselnde Nachricht
 * @param encryptedHeader - Der verschlüsselte Header (wird in AD eingebunden)
 * @param associatedData - server verfication token?
 * @returns Verschlüsselter Ciphertext (IV + verschlüsselte Daten)
 *
 * @remarks
 * Die Associated Data (AD) wird konstruiert als: CONCAT(associatedData, encryptedHeader)
 * Dies garantiert Authentifizierung sowohl der zusätzlichen Daten als auch des Headers
 */
async function encryptMessageContent(
    messageKey: Uint8Array,
    plaintext: Uint8Array,
    encryptedHeader: Uint8Array,
    associatedData?: Uint8Array
): Promise<Uint8Array> {
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const key = await crypto.subtle.importKey(
        'raw',
        messageKey as BufferSource,
        {name: 'AES-GCM', length: 256},
        false,
        ['encrypt']
    );

    // Konstruiere Associated Data: CONCAT(AD, enc_header)
    const ad = associatedData
        ? concatArrays(associatedData, encryptedHeader)
        : encryptedHeader;

    const ciphertext = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv as BufferSource,
            additionalData: ad as BufferSource
        },
        key,
        plaintext as BufferSource
    );

    const result = new Uint8Array(iv.length + ciphertext.byteLength);
    result.set(iv);
    result.set(new Uint8Array(ciphertext), iv.length);
    return result;
}

/**
 * Entschlüsselt den Nachrichteninhalt mit AES-256-GCM (AEAD)
 *
 * @param messageKey - Der Message Key für die Entschlüsselung (32 Bytes)
 * @param ciphertext - Der verschlüsselte Ciphertext (IV + Daten)
 * @param encryptedHeader - Der verschlüsselte Header (wird in AD eingebunden)
 * @param associatedData - Optional: Zusätzliche authentifizierte Daten
 * @returns Entschlüsselter Plaintext
 * @throws {Error} Wenn die Authentifizierung fehlschlägt
 *
 * @remarks
 * Die Associated Data (AD) muss identisch zur Verschlüsselung sein: CONCAT(associatedData, encryptedHeader)
 */
async function decryptMessageContent(
    messageKey: Uint8Array,
    ciphertext: Uint8Array,
    encryptedHeader: Uint8Array,
    associatedData?: Uint8Array
): Promise<Uint8Array> {
    const iv = ciphertext.slice(0, 12);
    const actualCiphertext = ciphertext.slice(12);

    const key = await crypto.subtle.importKey(
        'raw',
        messageKey as BufferSource,
        {name: 'AES-GCM', length: 256},
        false,
        ['decrypt']
    );

    // Konstruiere Associated Data: CONCAT(AD, enc_header)
    const ad = associatedData
        ? concatArrays(associatedData, encryptedHeader)
        : encryptedHeader;

    const plaintext = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: iv as BufferSource,
            additionalData: ad as BufferSource
        },
        key,
        actualCiphertext as BufferSource
    );

    return new Uint8Array(plaintext);
}

/**
 * Verschlüsselt eine Nachricht mit Header Encryption (RatchetEncryptHE)
 *
 * @param state - Aktueller Double Ratchet State mit Header Encryption
 * @param plaintext - Zu verschlüsselnde Nachricht
 * @param associatedData - Optional: Zusätzliche authentifizierte Daten (AEAD)
 * @returns Tuple aus [verschlüsselte Nachricht, neuer State]
 * @throws {Error} Wenn sendingChainKey oder sendingHeaderKey nicht initialisiert ist
 *
 * @remarks
 * Führt folgende Schritte aus:
 * 1. Leitet Message Key vom Sending Chain Key ab (KDF_CK)
 * 2. Erstellt Message Header (DH public key, Previous chain length, Message number)
 * 3. Verschlüsselt Header mit sendingHeaderKey (HENCRYPT)
 * 4. Verschlüsselt Nachricht mit Message Key (ENCRYPT mit AD)
 * 5. Inkrementiert Sending Message Number
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#encrypting-messages
 */
export async function ratchetEncryptHE(
    state: DRState,
    plaintext: Uint8Array,
    associatedData?: Uint8Array
): Promise<[RatchetMessageHE, DRState]> {
    // Validiere dass CKs nicht None ist
    if (!state.sendingChainKey) {
        throw new Error('Cannot encrypt: sendingChainKey is not initialized. Perform DH ratchet first.');
    }

    // Leite neuen Chain Key und Message Key ab: CKs, mk = KDF_CK(CKs)
    const [newSendingChainKey, messageKey] = await deriveMessageKey(state.sendingChainKey);

    // Erstelle Message Header: HEADER(DHRs, PN, Ns)
    const header: MessageHeader = {
        dh: state.ourEphemeralKeyPair.publicKey,
        pn: state.pn,
        n: state.messageNumbers.sending
    };

    // Verschlüssele Header: enc_header = HENCRYPT(HKs, header)
    if (!state.HeaderKeys.sendingHeaderKey) {
        throw new Error('Cannot encrypt header: sendingHeaderKey is not initialized');
    }
    const encryptedHeader = await encryptHeader(state.HeaderKeys.sendingHeaderKey, header);

    // Verschlüssele Nachricht: ENCRYPT(mk, plaintext, CONCAT(AD, enc_header))
    const ciphertext = await encryptMessageContent(messageKey, plaintext, encryptedHeader, associatedData);

    // Inkrementiere Sending Message Number: Ns += 1
    const newState: DRState = {
        ...state,
        sendingChainKey: newSendingChainKey,
        messageNumbers: {
            ...state.messageNumbers,
            sending: state.messageNumbers.sending + 1
        }
    };

    return [{encryptedHeader, ciphertext}, newState];
}

/**
 * Entschlüsselt eine Nachricht mit Header Encryption (RatchetDecryptHE)
 *
 * @param state - Aktueller Double Ratchet State mit Header Encryption
 * @param message - Verschlüsselte Nachricht (encryptedHeader + ciphertext)
 * @param associatedData - Optional: Zusätzliche authentifizierte Daten (AEAD)
 * @returns Tuple aus [entschlüsselte Nachricht, neuer State]
 * @throws {Error} Wenn Header nicht entschlüsselt werden kann oder Chain Key null ist
 *
 * @remarks
 * Führt folgende Schritte aus:
 * 1. Versucht Entschlüsselung mit gespeicherten skipped message keys
 * 2. Entschlüsselt Header und prüft ob DH Ratchet Step nötig ist
 * 3. Überspringt fehlende Message Keys falls nötig
 * 4. Führt DH Ratchet Step aus falls nötig
 * 5. Leitet Message Key ab und entschlüsselt Nachricht
 * 6. Inkrementiert Receiving Message Number
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#decrypting-messages
 */
export async function ratchetDecryptHE(
    state: DRState,
    message: RatchetMessageHE,
    associatedData?: Uint8Array
): Promise<[Uint8Array, DRState]> {
    // Versuche Entschlüsselung mit skipped message keys: TrySkippedMessageKeysHE
    const skippedResult = await trySkippedMessageKeysHE(state, message, associatedData);
    if (skippedResult) {
        return skippedResult;
    }

    // Entschlüssele Header und prüfe ob DH Ratchet nötig: DecryptHeader
    const {header, dhRatchet} = await decryptHeaderHE(state, message.encryptedHeader);

    if (dhRatchet) {
        // Überspringe Messages bis zur vorherigen Chain: SkipMessageKeysHE(pn)
        state = await skipMessageKeysHE(state, header.pn);

        // Führe DH Ratchet Step aus: DHRatchetHE
        state = await performDHRatchetHE(state, header);
    }

    // Überspringe Messages bis zur aktuellen: SkipMessageKeysHE(n)
    state = await skipMessageKeysHE(state, header.n);

    // Leite Message Key ab: CKr, mk = KDF_CK(CKr)
    if (!state.receivingChainKey) {
        throw new Error(`Cannot derive message key: receivingChainKey is null after DH ratchet (header.n=${header.n}, Nr=${state.messageNumbers.receiving})`);
    }
    const [newReceivingChainKey, messageKey] = await deriveMessageKey(state.receivingChainKey);

    // Inkrementiere Receiving Message Number: Nr = n + 1
    const newState: DRState = {
        ...state,
        receivingChainKey: newReceivingChainKey,
        messageNumbers: {
            ...state.messageNumbers,
            receiving: header.n + 1
        }
    };

    // Entschlüssele Nachricht: DECRYPT(mk, ciphertext, CONCAT(AD, enc_header))
    const plaintext = await decryptMessageContent(messageKey, message.ciphertext, message.encryptedHeader, associatedData);

    return [plaintext, newState];
}

/**
 * Entschlüsselt einen Message Header und prüft ob DH Ratchet nötig ist (DecryptHeader)
 *
 * @param state - Aktueller Double Ratchet State
 * @param encryptedHeader - Der verschlüsselte Header
 * @returns Objekt mit entschlüsseltem Header und DH Ratchet Flag
 * @throws {Error} Wenn Header mit keinem verfügbaren Key entschlüsselt werden kann
 *
 * @remarks
 * Versucht zuerst mit receivingHeaderKey (HKr) zu entschlüsseln.
 * Falls das fehlschlägt, versucht es mit receivingNextHeaderKey (NHKr).
 * Wenn NHKr erfolgreich ist, bedeutet das, dass ein DH Ratchet Step nötig ist.
 */
async function decryptHeaderHE(
    state: DRState,
    encryptedHeader: Uint8Array
): Promise<{ header: MessageHeader; dhRatchet: boolean }> {
    // Versuche mit aktuellem receiving header key: HDECRYPT(HKr, enc_header)
    let header = await decryptHeader(state.HeaderKeys.receivingHeaderKey, encryptedHeader);
    if (header) {
        return {header, dhRatchet: false};
    }

    // Versuche mit next receiving header key: HDECRYPT(NHKr, enc_header)
    header = await decryptHeader(state.HeaderKeys.receivingNextHeaderKey, encryptedHeader);
    if (header) {
        return {header, dhRatchet: true};
    }

    throw new Error('Failed to decrypt header with any available key');
}

/**
 * Führt einen DH Ratchet Step mit Header Encryption aus (DHRatchetHE)
 *
 * @param state - Aktueller Double Ratchet State
 * @param header - Der entschlüsselte Message Header mit neuem DH Public Key
 * @returns Neuer State nach DH Ratchet Step
 *
 * @remarks
 * Führt folgende Schritte aus:
 * 1. Speichert Previous Chain Length (PN = Ns)
 * 2. Rotiert Header Keys (HKs = NHKs, HKr = NHKr)
 * 3. Führt DH mit empfangenem Public Key durch und leitet Receiving Chain Key ab
 * 4. Generiert neues eigenes DH Key Pair
 * 5. Führt DH mit neuem Key Pair durch und leitet Sending Chain Key ab
 * 6. Setzt Message Numbers zurück (Ns = 0, Nr = 0)
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#the-diffie-hellman-ratchet
 */
async function performDHRatchetHE(state: DRState, header: MessageHeader): Promise<DRState> {
    const hkdf = new HKDF('SHA-512');

    // Speichere vorherige Sending Chain Length
    const pn = state.messageNumbers.sending;

    // Rotiere Header Keys: HKs = NHKs, HKr = NHKr
    const sendingHeaderKey = state.HeaderKeys.sendingNextHeaderKey;
    const receivingHeaderKey = state.HeaderKeys.receivingNextHeaderKey;

    // Speichere empfangenen Public Key
    const theirPublicKey = header.dh;

    // Leite Receiving Chain Key und Next Receiving Header Key ab
    const dhOutput1 = await deriveSharedSecret(state.ourEphemeralKeyPair.privateKey, theirPublicKey);
    const [rootKey1, receivingChainKey, nextReceivingHeaderKey] = await hkdf.deriveKeysHE(state.rootKey, dhOutput1);

    // Generiere neues eigenes DH Key Pair
    const newKeyPair = await generateKeyPair();

    // Leite Sending Chain Key und Next Sending Header Key ab
    const dhOutput2 = await deriveSharedSecret(newKeyPair.privateKey, theirPublicKey);
    const [rootKey2, sendingChainKey, nextSendingHeaderKey] = await hkdf.deriveKeysHE(rootKey1, dhOutput2);

    return {
        rootKey: rootKey2,
        sendingChainKey: sendingChainKey,
        receivingChainKey: receivingChainKey,
        ourEphemeralKeyPair: newKeyPair,
        theirEphemeralPublicKey: theirPublicKey,

        messageNumbers: {
            sending: 0,
            receiving: 0
        },
        pn: pn,
        skippedMessageKeys: state.skippedMessageKeys,
        HeaderKeys: {
            sendingHeaderKey: sendingHeaderKey,
            sendingNextHeaderKey: nextSendingHeaderKey,
            receivingHeaderKey: receivingHeaderKey,
            receivingNextHeaderKey: nextReceivingHeaderKey
        }
    };
}

/**
 * Versucht eine Nachricht mit gespeicherten Skipped Message Keys zu entschlüsseln (TrySkippedMessageKeysHE)
 *
 * @param state - Aktueller Double Ratchet State
 * @param message - Verschlüsselte Nachricht
 * @param associatedData - Optional: Zusätzliche authentifizierte Daten
 * @returns Tuple aus [entschlüsselte Nachricht, neuer State] oder null wenn kein passender Key gefunden
 *
 * @remarks
 * Iteriert über alle gespeicherten skipped message keys und versucht:
 * 1. Header mit verfügbaren Header Keys zu entschlüsseln
 * 2. Wenn erfolgreich: Konstruiert Key-ID aus Public Key und Message Number
 * 3. Prüft ob ein gespeicherter Key mit dieser ID existiert
 * 4. Versucht Nachricht zu entschlüsseln
 * 5. Bei Erfolg: Löscht verwendeten Key aus Map
 */
async function trySkippedMessageKeysHE(
    state: DRState,
    message: RatchetMessageHE,
    associatedData?: Uint8Array
): Promise<[Uint8Array, DRState] | null> {
    // Versuche Header mit allen gespeicherten Header Keys zu entschlüsseln
    for (const [keyId, skippedKey] of state.skippedMessageKeys.entries()) {
        // Der keyId Format ist: "base64(publicKey):n"
        // Wir müssen den Header mit allen möglichen Header Keys entschlüsseln

        // Versuche mit aktuellem Header Key
        let header = await decryptHeader(state.HeaderKeys.receivingHeaderKey, message.encryptedHeader);

        // Versuche mit Next Header Key falls nicht erfolgreich (Nullish Coalescing)
        header ??= await decryptHeader(state.HeaderKeys.receivingNextHeaderKey, message.encryptedHeader);

        if (header) {
            // Erstelle KeyId für diese Nachricht (DH Public Key + Message Number)
            const messageKeyId = `${btoa(String.fromCodePoint(...header.dh))}:${header.n}`;

            // Prüfe ob wir einen gespeicherten Key für diese Nachricht haben
            if (messageKeyId === keyId) {
                // Entschlüssele mit dem skipped message key
                try {
                    const plaintext = await decryptMessageContent(
                        skippedKey.messageKey,
                        message.ciphertext,
                        message.encryptedHeader,
                        associatedData
                    );

                    // Lösche den verwendeten skipped message key
                    const newSkippedKeys = new Map(state.skippedMessageKeys);
                    newSkippedKeys.delete(keyId);

                    const newState: DRState = {
                        ...state,
                        skippedMessageKeys: newSkippedKeys
                    };

                    return [plaintext, newState];
                } catch {
                    // Entschlüsselung fehlgeschlagen, versuche nächsten Key
                }
            }
        }
    }

    return null;
}

/**
 * Überspringt fehlende Message Keys und speichert sie für spätere Out-of-Order Entschlüsselung (SkipMessageKeysHE)
 *
 * @param state - Aktueller Double Ratchet State
 * @param until - Message Number bis zu der übersprungen werden soll (exklusiv)
 * @returns Neuer State mit gespeicherten skipped keys und aktualisierter Receiving Number
 * @throws {Error} Wenn zu viele Messages übersprungen werden müssen (> MAX_SKIP)
 *
 * @remarks
 * Diese Funktion wird verwendet wenn eine Nachricht mit höherer Message Number empfangen wird.
 * Alle Message Keys dazwischen werden generiert und gespeichert, falls diese Nachrichten
 * später noch ankommen (Out-of-Order Delivery).
 *
 * MAX_SKIP = 1000 verhindert DoS-Attacken durch künstlich hohe Message Numbers.
 */
async function skipMessageKeysHE(state: DRState, until: number): Promise<DRState> {
    // Falls nichts zu überspringen ist, direkt zurückgeben
    if (state.messageNumbers.receiving >= until) {
        return state;
    }

    // Nur skippen wenn Chain Key existiert (CKr != None)
    if (!state.receivingChainKey) {
        return state;
    }

    const maxSkip = 1000;

    if (state.messageNumbers.receiving + maxSkip < until) {
        throw new Error(`Too many skipped messages: ${until - state.messageNumbers.receiving} > ${maxSkip}`);
    }

    let currentChainKey = state.receivingChainKey;
    const newSkippedKeys = new Map(state.skippedMessageKeys);

    while (state.messageNumbers.receiving < until) {
        const [newChainKey, messageKey] = await deriveMessageKey(currentChainKey);

        // Speichere Message Key mit ID: "base64(publicKey):messageNumber"
        const keyId = `${btoa(String.fromCodePoint(...state.theirEphemeralPublicKey))}:${state.messageNumbers.receiving}`;
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

/**
 * Konkateniert zwei Uint8Arrays zu einem neuen Array
 *
 * @param a - Erstes Array
 * @param b - Zweites Array
 * @returns Neues Array mit Inhalt von a gefolgt von b
 */
function concatArrays(a: Uint8Array, b: Uint8Array): Uint8Array {
    const result = new Uint8Array(a.length + b.length);
    result.set(a);
    result.set(b, a.length);
    return result;
}

