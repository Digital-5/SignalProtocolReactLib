/**
 * Double Ratchet mit Header Encryption
 * Implementiert Signal Protocol Specification Section 4.5 und 4.6
 * https://signal.org/docs/specifications/doubleratchet/
 */
import { DRStateHE } from './DR_State';
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
 * Verschlüsselt eine Nachricht mit Header Encryption
 * Signal Spec Section 4.5: RatchetEncryptHE
 *
 * @param state - Aktueller DRStateHE
 * @param plaintext - Zu verschlüsselnde Nachricht
 * @param associatedData - Optional: Associated Data
 * @returns Tuple mit [verschlüsselte Nachricht, neuer State]
 */
export declare function ratchetEncryptHE(state: DRStateHE, plaintext: Uint8Array, associatedData?: Uint8Array): Promise<[RatchetMessageHE, DRStateHE]>;
/**
 * Entschlüsselt eine Nachricht mit Header Encryption
 * Signal Spec Section 4.6: RatchetDecryptHE
 *
 * @param state - Aktueller DRStateHE
 * @param message - Verschlüsselte Nachricht
 * @param associatedData - Optional: Associated Data
 * @returns Tuple mit [entschlüsselte Nachricht, neuer State]
 */
export declare function ratchetDecryptHE(state: DRStateHE, message: RatchetMessageHE, associatedData?: Uint8Array): Promise<[Uint8Array, DRStateHE]>;
