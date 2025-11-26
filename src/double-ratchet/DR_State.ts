/**
 * Double Ratchet State Definition
 * Speichert den aktuellen Zustand des Double Ratchet Algorithmus
 */

/**
 * Skipped Message Key Entry
 * Speichert Message Keys für Nachrichten, die übersprungen wurden
 */
export interface SkippedMessageKey {
    /** Der Message Key für die Entschlüsselung */
    messageKey: Uint8Array;
    /** Zeitstempel, wann dieser Key erstellt wurde */
    timestamp: number;
}

/**
 * Der State des Double Ratchet Algorithmus
 * Enthält alle Schlüssel und Zähler für sichere Nachrichtenverschlüsselung
 */
export interface DRState {
    /** Root Key für die Ableitung neuer Chain Keys */
    rootKey: Uint8Array;
    /** Chain Key für ausgehende Nachrichten */
    sendingChainKey: Uint8Array;
    /** Chain Key für eingehende Nachrichten */
    receivingChainKey: Uint8Array;
    /** Unser aktuelles ephemeres Schlüsselpaar */
    ourEphemeralKeyPair: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };
    /** Öffentlicher ephemerer Schlüssel der Gegenseite */
    theirEphemeralPublicKey: Uint8Array;
    /** Nachrichtenzähler zur Verhinderung von Replay-Angriffen */
    messageNumbers: {
        /** Anzahl gesendeter Nachrichten */
        sending: number;
        /** Anzahl empfangener Nachrichten */
        receiving: number;
    };
    /**
     * PN (Previous Number): Anzahl der Nachrichten in der vorherigen Sending Chain
     * Wird bei DH Ratchet aktualisiert, damit Empfänger weiß, wie viele Messages übersprungen wurden
     */
    pn: number;
    /**
     * Skipped Message Keys für Out-of-Order Messages
     * Map: "publicKey:messageNumber" -> SkippedMessageKey
     */
    skippedMessageKeys: Map<string, SkippedMessageKey>;
    /** Maximale Anzahl an Skipped Message Keys (DoS-Schutz) */
    maxSkippedMessageKeys?: number;
}
