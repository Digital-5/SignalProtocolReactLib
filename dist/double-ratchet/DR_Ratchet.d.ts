/**
 * Double Ratchet Core Funktionen
 * Implementiert Verschlüsselung, Entschlüsselung und Ratchet Steps
 */
import { DRState } from "./DR_State";
/**
 * Verschlüsselte Nachricht mit Header-Informationen
 * Folgt der Signal Protocol Specification (Section 3)
 */
export interface RatchetMessage {
    /** Message Header mit DH Public Key, Previous Chain Length, Message Number */
    header: MessageHeader;
    /** Die verschlüsselte Nachricht (AEAD) */
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
 * Führt einen DH Ratchet Step aus (Schlüsselrotation)
 * @param state - Aktueller Double Ratchet State
 * @param theirPublicKey - Neuer öffentlicher Schlüssel der Gegenseite
 * @returns Aktualisierter State
 */
export declare function performDHRatchet(state: DRState, theirPublicKey: Uint8Array): Promise<DRState>;
/**
 * Verschlüsselt eine Nachricht und aktualisiert den State (Ratchet Step)
 * Signal Protocol kompatibel mit PN und AD Support
 * @param state - Aktueller Double Ratchet State
 * @param plaintext - Die zu verschlüsselnde Nachricht
 * @param associatedData - Optional: Associated Data für AEAD (wird authentifiziert, aber nicht verschlüsselt)
 * @returns Tuple mit [verschlüsselte Nachricht, aktualisierter State]
 */
export declare function ratchetEncrypt(state: DRState, plaintext: Uint8Array, associatedData?: Uint8Array): Promise<[RatchetMessage, DRState]>;
/**
 * Entschlüsselt eine Nachricht und aktualisiert den State (Ratchet Step)
 * Signal Protocol kompatibel mit PN und AD Support
 * Unterstützt Out-of-Order Messages durch Skipped Message Keys
 * @param state - Aktueller Double Ratchet State
 * @param message - Die verschlüsselte Nachricht
 * @param associatedData - Optional: Associated Data für AEAD-Verifikation
 * @returns Tuple mit [entschlüsselte Nachricht, aktualisierter State]
 */
export declare function ratchetDecrypt(state: DRState, message: RatchetMessage, associatedData?: Uint8Array): Promise<[Uint8Array, DRState]>;
