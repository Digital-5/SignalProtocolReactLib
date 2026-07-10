/**
 * Double Ratchet State Definition
 * Implementiert Signal Protocol Specification Section 3.2
 * https://signal.org/docs/specifications/doubleratchet/
 */

/**
 * Skipped Message Key Entry
 * Speichert Message Keys für Nachrichten, die übersprungen wurden
 * Signal Spec: MKSKIPPED dictionary
 */
export interface SkippedMessageKey {
    /** Der Header Key, der aktiv war als dieser Key gespeichert wurde */
    headerKey: Uint8Array;
    /** Der Message Key für die Entschlüsselung */
    messageKey: Uint8Array;
    /** Zeitstempel, wann dieser Key erstellt wurde (für Cleanup) in ms (Date.now) */
    timestamp: number;
}

export interface Headerkeys {
    sendingHeaderKey: Uint8Array | null, //selber gen sonst null
    sendingNextHeaderKey: Uint8Array | null, //^
    //später braucht man für jede Seite HK und NHK:
    receivingHeaderKey: Uint8Array | null, // bekomme ich von pqxdh oder ich berechne es selber
    receivingNextHeaderKey: Uint8Array | null //^sollte nie null sein
}

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
 * Message Header (Signal Protocol kompatibel)
 */
export interface MessageHeader {
    /** DH Ratchet Public Key */
    dh: Uint8Array;
    /** Previous Chain Length (Anzahl Nachrichten in vorheriger Sending Chain) */
    pn: number;
    /** Message Number in aktueller Chain */
    n: number;
}

/**
 * Der State des Double Ratchet Algorithmus
 *
 * Signal Protocol Specification Section 3.2 State Variables:
 * - DHs: DH Ratchet key pair (sending/self) = ourEphemeralKeyPair
 * - DHr: DH Ratchet public key (received/remote) = theirEphemeralPublicKey
 * - RK: Root Key = rootKey
 * - CKs: Sending Chain Key = sendingChainKey
 * - CKr: Receiving Chain Key = receivingChainKey
 * - Ns: Sending message number = messageNumbers.sending
 * - Nr: Receiving message number = messageNumbers.receiving
 * - PN: Previous chain length = pn
 * - MKSKIPPED: Skipped message keys = skippedMessageKeys
 */
export interface DRState {
    // Signal Spec: RK (32-byte Root Key)
    /** Root Key für die Ableitung neuer Chain Keys */
    rootKey: Uint8Array;

    // Signal Spec: CKs, CKr (32-byte Chain Keys)
    /** Chain Key für ausgehende Nachrichten (CKs in Signal Spec) */
    sendingChainKey: Uint8Array | null;
    /** Chain Key für eingehende Nachrichten (CKr in Signal Spec) */
    receivingChainKey: Uint8Array | null;

    /** Unser aktuelles ephemeres Schlüsselpaar (DHs in Signal Spec) */
    ourEphemeralKeyPair: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };

    /** Öffentlicher ephemerer Schlüssel der Gegenseite (DHr in Signal Spec) */
    theirEphemeralPublicKey: Uint8Array;

    /** Nachrichtenzähler zur Verhinderung von Replay-Angriffen */
    messageNumbers: {
        /** Anzahl gesendeter Nachrichten (Ns in Signal Spec) */
        sending: number;
        /** Anzahl empfangener Nachrichten (Nr in Signal Spec) */
        receiving: number;
    };

    /**
     * PN: Anzahl der Nachrichten in der vorherigen Sending Chain
     * Signal Spec Section 3.2: "Number of messages in previous sending chain"
     */
    pn: number;

    /**
     * Skipped Message Keys für Out-of-Order Messages
     *
     * string = index by ratchet public key and message number
     *
     * SkippedMessageKey wird oben als interface implementiert
     */
    skippedMessageKeys: Map<string, SkippedMessageKey>;

    //groupped header keys for header encryption
    HeaderKeys: Headerkeys;
}

