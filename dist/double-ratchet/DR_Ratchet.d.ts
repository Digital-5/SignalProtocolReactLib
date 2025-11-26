/**
 * Double Ratchet Core Funktionen
 * Implementiert Verschlüsselung, Entschlüsselung und Ratchet Steps
 */
import { DRState } from "./DR_State";
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
export declare function performDHRatchet(state: DRState, theirPublicKey: Uint8Array): Promise<DRState>;
/**
 * Verschlüsselt eine Nachricht und aktualisiert den State (Ratchet Step)
 * @param state - Aktueller Double Ratchet State
 * @param plaintext - Die zu verschlüsselnde Nachricht
 * @returns Tuple mit [verschlüsselte Nachricht, aktualisierter State]
 */
export declare function ratchetEncrypt(state: DRState, plaintext: Uint8Array): Promise<[RatchetMessage, DRState]>;
/**
 * Entschlüsselt eine Nachricht und aktualisiert den State (Ratchet Step)
 * @param state - Aktueller Double Ratchet State
 * @param message - Die verschlüsselte Nachricht
 * @returns Tuple mit [entschlüsselte Nachricht, aktualisierter State]
 */
export declare function ratchetDecrypt(state: DRState, message: RatchetMessage): Promise<[Uint8Array, DRState]>;
