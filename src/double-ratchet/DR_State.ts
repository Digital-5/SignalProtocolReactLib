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
    /** Der Message Key für die Entschlüsselung */
    messageKey: Uint8Array;
    /** Zeitstempel, wann dieser Key erstellt wurde (für Cleanup) */
    timestamp: number;
}

export interface Headerkeys {
    sendingHeaderKey: Uint8Array | null, //eines von beiden ist am anfang null
    receivingHeaderKey: Uint8Array | null, // da eins durch pqxdh kommt (Je nachdem wer initiiert)
    nextSendingHeaderKey: Uint8Array |null, //^ aber das andere kann mit dem rootkey und das ss erzeugt werden
    nextReceivingHeaderKey: Uint8Array |null, // ^^ wenn man antwortet
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

    // Signal Spec: DHs (DH Ratchet key pair - sending/self)
    /** Unser aktuelles ephemeres Schlüsselpaar (DHs in Signal Spec) */
    ourEphemeralKeyPair: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };

    // Signal Spec: DHr (DH Ratchet public key - received/remote)
    /** Öffentlicher ephemerer Schlüssel der Gegenseite (DHr in Signal Spec) */
    theirEphemeralPublicKey: Uint8Array;

    // Signal Spec: Ns, Nr (Message numbers)
    /** Nachrichtenzähler zur Verhinderung von Replay-Angriffen */
    messageNumbers: {
        /** Anzahl gesendeter Nachrichten (Ns in Signal Spec) */
        sending: number;
        /** Anzahl empfangener Nachrichten (Nr in Signal Spec) */
        receiving: number;
    };

    // Signal Spec: PN (Previous chain length)
    /**
     * PN: Anzahl der Nachrichten in der vorherigen Sending Chain
     * Signal Spec Section 3.2: "Number of messages in previous sending chain"
     */
    pn: number;

    // Signal Spec: MKSKIPPED (Dictionary of skipped message keys)
    /**
     * Skipped Message Keys für Out-of-Order Messages
     * Signal Spec Section 3.2: "Dictionary of skipped-over message keys,
     * indexed by ratchet public key and message number"
     *
     * wird oben als Map implementiert
     */
    skippedMessageKeys: Map<string, SkippedMessageKey>;

    /**
     * Wird verwendet, um Header der aktuellen Sending Chain zu verschlüsseln
     * Signal Spec: Can be None (null) before first DH ratchet (Bob's initial state)
     */
    sendingHeaderKey: Uint8Array | null;

    /**
     * Wird verwendet, um Header der aktuellen Receiving Chain zu entschlüsseln
     */
    receivingHeaderKey: Uint8Array | null;

    /**
     * Wird zur nächsten Sending Header Key nach DH Ratchet
     */
    nextSendingHeaderKey: Uint8Array | null;

    /**
     * Wird zur nächsten Receiving Header Key nach DH Ratchet
     */
    nextReceivingHeaderKey: Uint8Array | null;
}

