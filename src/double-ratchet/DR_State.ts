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
    sendingChainKey: Uint8Array;
    /** Chain Key für eingehende Nachrichten (CKr in Signal Spec) */
    receivingChainKey: Uint8Array;

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
     * Map: "base64(DHr):N" -> SkippedMessageKey
     */
    skippedMessageKeys: Map<string, SkippedMessageKey>;

    // Extension: MAX_SKIP constant (Signal Spec Section 3.1)
    /**
     * Maximale Anzahl an Skipped Message Keys (DoS-Schutz)
     * Signal Spec Section 3.1: "MAX_SKIP constant"
     * Empfohlen: 1000
     */
    maxSkippedMessageKeys?: number;
}
