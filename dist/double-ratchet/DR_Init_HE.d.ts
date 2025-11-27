/**
 * Double Ratchet Initialization mit Header Encryption
 * Implementiert Signal Protocol Specification Section 4.4
 * https://signal.org/docs/specifications/doubleratchet/
 */
import { DRStateHE } from './DR_State';
import { KeyPair } from './CryptoUtils';
/**
 * Initialisierungsparameter für Double Ratchet mit Header Encryption (Alice)
 * Signal Spec Section 4.4: RatchetInitAliceHE
 */
export interface DR_InitParamsHE {
    /** Shared Secret Key (32 Bytes) - von PQXDH */
    rootKey: Uint8Array;
    /** Unser Identity Key Pair */
    ourIdentityKeyPair: KeyPair;
    /** Öffentlicher Identity Key der Gegenseite */
    theirIdentityPublicKey: Uint8Array;
    /** Unser Ephemeral Key Pair */
    ourEphemeralKeyPair: KeyPair;
    /** Öffentlicher Ephemeral Key der Gegenseite */
    theirEphemeralPublicKey: Uint8Array;
    /** Shared Sending Header Key (HKa in Signal Spec) */
    sharedSendingHeaderKey: Uint8Array;
    /** Shared Next Receiving Header Key (NHKb in Signal Spec) */
    sharedNextReceivingHeaderKey: Uint8Array;
    /** Ob wir der Initiator sind (Alice=true, Bob=false) */
    isInitiator: boolean;
}
/**
 * Initialisiert den Double Ratchet State mit Header Encryption
 * Signal Spec Section 4.4: RatchetInitAliceHE / RatchetInitBobHE
 *
 * @param params - Initialisierungsparameter
 * @returns Initialisierter DRStateHE
 */
export declare function DR_InitHE(params: DR_InitParamsHE): Promise<DRStateHE>;
