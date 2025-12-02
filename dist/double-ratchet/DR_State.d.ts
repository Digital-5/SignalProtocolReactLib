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
    /** Root Key für die Ableitung neuer Chain Keys */
    rootKey: Uint8Array;
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
     * Signal Spec Section 3.2: "Dictionary of skipped-over message keys,
     * indexed by ratchet public key and message number"
     * Map: "base64(DHr):N" -> SkippedMessageKey
     */
    skippedMessageKeys: Map<string, SkippedMessageKey>;
    /**
     * Maximale Anzahl an Skipped Message Keys (DoS-Schutz)
     * Signal Spec Section 3.1: "MAX_SKIP constant"
     * Empfohlen: 1000
     */
    maxSkippedMessageKeys?: number;
}
/**
 * Double Ratchet State mit Header Encryption
 * Signal Protocol Specification Section 4.3
 * Erweitert DRState um Header Encryption Keys
 */
export interface DRStateHE extends DRState {
    /**
     * Sending Header Key (HKs in Signal Spec)
     * Wird verwendet, um Header der aktuellen Sending Chain zu verschlüsseln
     * Signal Spec: Can be None (null) before first DH ratchet (Bob's initial state)
     */
    sendingHeaderKey: Uint8Array | null;
    /**
     * Receiving Header Key (HKr in Signal Spec)
     * Wird verwendet, um Header der aktuellen Receiving Chain zu entschlüsseln
     */
    receivingHeaderKey: Uint8Array | null;
    /**
     * Next Sending Header Key (NHKs in Signal Spec)
     * Wird zur nächsten Sending Header Key nach DH Ratchet
     */
    nextSendingHeaderKey: Uint8Array;
    /**
     * Next Receiving Header Key (NHKr in Signal Spec)
     * Wird zur nächsten Receiving Header Key nach DH Ratchet
     */
    nextReceivingHeaderKey: Uint8Array;
}
