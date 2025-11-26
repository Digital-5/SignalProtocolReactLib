/**
 * Double Ratchet State Definition
 * Speichert den aktuellen Zustand des Double Ratchet Algorithmus
 */

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
}
