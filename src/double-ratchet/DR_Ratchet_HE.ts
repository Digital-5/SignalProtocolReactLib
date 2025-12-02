/**
 * Double Ratchet mit Header Encryption
 * Implementiert Signal Protocol Specification Section 4.5 und 4.6
 * https://signal.org/docs/specifications/doubleratchet/
 */

import {DRStateHE} from './DR_State';
import {MessageHeader} from './DR_Ratchet';
import {encryptHeader, decryptHeader} from './HeaderEncryption';
import {HKDF} from './HKDF';
import {deriveSharedSecret, generateKeyPair} from './CryptoUtils';

/**
 * Encrypted Message mit Header Encryption
 * Signal Spec Section 4: Encrypted Header + Ciphertext
 */
export interface RatchetMessageHE {
    /** Verschlüsselter Header */
    encryptedHeader: Uint8Array;
    /** Die verschlüsselte Nachricht */
    ciphertext: Uint8Array;
}

/**
 * Leitet einen Message Key aus einem Chain Key ab
 * Signal Spec: KDF_CK(ck) - If ck is None this function must fail
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
 * Verschlüsselt eine Nachricht mit AES-256-GCM
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

    // Signal Spec: CONCAT(AD, enc_header)
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
 * Entschlüsselt eine Nachricht mit AES-256-GCM
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

    // Signal Spec: CONCAT(AD, enc_header)
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
 * Verschlüsselt eine Nachricht mit Header Encryption
 * Signal Spec Section 4.5: RatchetEncryptHE
 *
 * @param state - Aktueller DRStateHE
 * @param plaintext - Zu verschlüsselnde Nachricht
 * @param associatedData - Optional: Associated Data
 * @returns Tuple mit [verschlüsselte Nachricht, neuer State]
 */
export async function ratchetEncryptHE(
    state: DRStateHE,
    plaintext: Uint8Array,
    associatedData?: Uint8Array
): Promise<[RatchetMessageHE, DRStateHE]> {
    // Signal Spec: Validiere dass CKs nicht None ist
    if (!state.sendingChainKey) {
        throw new Error('Cannot encrypt: sendingChainKey is not initialized. Perform DH ratchet first.');
    }

    // Signal Spec: state.CKs, mk = KDF_CK(state.CKs)
    const [newSendingChainKey, messageKey] = await deriveMessageKey(state.sendingChainKey);

    // Signal Spec: header = HEADER(state.DHRs, state.PN, state.Ns)
    const header: MessageHeader = {
        dh: state.ourEphemeralKeyPair.publicKey,
        pn: state.pn,
        n: state.messageNumbers.sending
    };

    // Signal Spec: enc_header = HENCRYPT(state.HKs, header)
    if (!state.sendingHeaderKey) {
        throw new Error('Cannot encrypt header: sendingHeaderKey is not initialized');
    }
    const encryptedHeader = await encryptHeader(state.sendingHeaderKey, header);

    // Signal Spec: ENCRYPT(mk, plaintext, CONCAT(AD, enc_header))
    const ciphertext = await encryptMessageContent(messageKey, plaintext, encryptedHeader, associatedData);

    // Signal Spec: state.Ns += 1
    const newState: DRStateHE = {
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
 * Entschlüsselt eine Nachricht mit Header Encryption
 * Signal Spec Section 4.6: RatchetDecryptHE
 *
 * @param state - Aktueller DRStateHE
 * @param message - Verschlüsselte Nachricht
 * @param associatedData - Optional: Associated Data
 * @returns Tuple mit [entschlüsselte Nachricht, neuer State]
 */
export async function ratchetDecryptHE(
    state: DRStateHE,
    message: RatchetMessageHE,
    associatedData?: Uint8Array
): Promise<[Uint8Array, DRStateHE]> {
    // Signal Spec: plaintext = TrySkippedMessageKeysHE(state, enc_header, ciphertext, AD)
    const skippedResult = await trySkippedMessageKeysHE(state, message, associatedData);
    if (skippedResult) {
        return skippedResult;
    }

    // Signal Spec: header, dh_ratchet = DecryptHeader(state, enc_header)
    const {header, dhRatchet} = await decryptHeaderHE(state, message.encryptedHeader);

    if (dhRatchet) {
        // Signal Spec: SkipMessageKeysHE(state, header.pn)
        state = await skipMessageKeysHE(state, header.pn);

        // Signal Spec: DHRatchetHE(state, header)
        state = await performDHRatchetHE(state, header);
    }

    // Signal Spec: SkipMessageKeysHE(state, header.n)
    state = await skipMessageKeysHE(state, header.n);

    // Signal Spec: state.CKr, mk = KDF_CK(state.CKr)
    if (!state.receivingChainKey) {
        throw new Error(`Cannot derive message key: receivingChainKey is null after DH ratchet (header.n=${header.n}, Nr=${state.messageNumbers.receiving})`);
    }
    const [newReceivingChainKey, messageKey] = await deriveMessageKey(state.receivingChainKey);

    // Signal Spec: state.Nr += 1
    const newState: DRStateHE = {
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
async function decryptHeaderHE(
    state: DRStateHE,
    encryptedHeader: Uint8Array
): Promise<{ header: MessageHeader; dhRatchet: boolean }> {
    // Signal Spec: header = HDECRYPT(state.HKr, enc_header)
    let header = await decryptHeader(state.receivingHeaderKey, encryptedHeader);
    if (header) {
        return {header, dhRatchet: false};
    }

    // Signal Spec: header = HDECRYPT(state.NHKr, enc_header)
    header = await decryptHeader(state.nextReceivingHeaderKey, encryptedHeader);
    if (header) {
        return {header, dhRatchet: true};
    }

    throw new Error('Failed to decrypt header with any available key');
}

/**
 * Signal Spec Section 4.6: DHRatchetHE
 */
async function performDHRatchetHE(state: DRStateHE, header: MessageHeader): Promise<DRStateHE> {
    const hkdf = new HKDF('SHA-512');

    // Signal Spec: state.PN = state.Ns
    const pn = state.messageNumbers.sending;

    // Signal Spec: state.HKs = state.NHKs; state.HKr = state.NHKr
    const sendingHeaderKey = state.nextSendingHeaderKey;
    const receivingHeaderKey = state.nextReceivingHeaderKey;

    // Signal Spec: state.DHRr = header.dh
    const theirPublicKey = header.dh;

    // Signal Spec: state.RK, state.CKr, state.NHKr = KDF_RK_HE(state.RK, DH(state.DHRs, state.DHRr))
    const dhOutput1 = await deriveSharedSecret(state.ourEphemeralKeyPair.privateKey, theirPublicKey);
    const [rootKey1, receivingChainKey, nextReceivingHeaderKey] = await hkdf.deriveKeysHE(state.rootKey, dhOutput1);

    // Signal Spec: state.DHRs = GENERATE_DH()
    const newKeyPair = await generateKeyPair();

    // Signal Spec: state.RK, state.CKs, state.NHKs = KDF_RK_HE(state.RK, DH(state.DHRs, state.DHRr))
    const dhOutput2 = await deriveSharedSecret(newKeyPair.privateKey, theirPublicKey);
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
 * Versucht, eine Nachricht mit gespeicherten skipped message keys zu entschlüsseln
 */
async function trySkippedMessageKeysHE(
    state: DRStateHE,
    message: RatchetMessageHE,
    associatedData?: Uint8Array
): Promise<[Uint8Array, DRStateHE] | null> {
    // Signal Spec: Versuche Header mit allen gespeicherten Header Keys zu entschlüsseln
    // Für jeden skipped message key, versuche den Header zu entschlüsseln
    for (const [keyId, skippedKey] of state.skippedMessageKeys.entries()) {
        // Der keyId Format ist: "base64(publicKey):n"
        // Wir müssen den Header mit allen möglichen Header Keys entschlüsseln

        // Versuche mit aktuellem Header Key
        let header = await decryptHeader(state.receivingHeaderKey, message.encryptedHeader);

        // Versuche mit Next Header Key falls nicht erfolgreich
        if (!header) {
            header = await decryptHeader(state.nextReceivingHeaderKey, message.encryptedHeader);
        }

        if (header) {
            // Erstelle KeyId für diese Nachricht
            const messageKeyId = `${btoa(String.fromCodePoint(...header.dh))}:${header.n}`;

            // Prüfe ob wir einen gespeicherten Key für diese Nachricht haben
            if (messageKeyId === keyId) {
                // Signal Spec: Entschlüssele mit dem skipped message key
                try {
                    const plaintext = await decryptMessageContent(
                        skippedKey.messageKey,
                        message.ciphertext,
                        message.encryptedHeader,
                        associatedData
                    );

                    // Signal Spec: Lösche den verwendeten skipped message key
                    const newSkippedKeys = new Map(state.skippedMessageKeys);
                    newSkippedKeys.delete(keyId);

                    const newState: DRStateHE = {
                        ...state,
                        skippedMessageKeys: newSkippedKeys
                    };

                    return [plaintext, newState];
                } catch {
                    // Entschlüsselung fehlgeschlagen, versuche nächsten Key
                    continue;
                }
            }
        }
    }

    return null;
}

/**
 * Signal Spec: SkipMessageKeysHE
 */
async function skipMessageKeysHE(state: DRStateHE, until: number): Promise<DRStateHE> {
    // Signal Spec: If nothing to skip, return
    if (state.messageNumbers.receiving >= until) {
        return state;
    }

    // Signal Spec: "if state.CKr != None" - nur skippen wenn Chain Key existiert
    if (!state.receivingChainKey) {
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

function concatArrays(a: Uint8Array, b: Uint8Array): Uint8Array {
    const result = new Uint8Array(a.length + b.length);
    result.set(a);
    result.set(b, a.length);
    return result;
}

