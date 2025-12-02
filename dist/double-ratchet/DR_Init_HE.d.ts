import { KeyPair } from './CryptoUtils';
import { DRStateHE } from './DR_State';
export interface DR_InitParamsHE {
    rootKey: Uint8Array;
    ourRatchetKeyPair: KeyPair;
    theirRatchetPublicKey: Uint8Array;
    sendingHeaderKey: Uint8Array;
    nextReceivingHeaderKey: Uint8Array;
    isInitiator: boolean;
}
/**
 * Initialisiert einen Double Ratchet State mit Header Encryption
 * Signal Protocol Specification Section 4.4
 */
export declare function DR_Init_HE(params: DR_InitParamsHE): Promise<DRStateHE>;
