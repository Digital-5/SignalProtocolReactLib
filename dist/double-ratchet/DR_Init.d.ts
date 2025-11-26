/**
 * Double Ratchet Initialisierung
 * Implementiert die Initialisierungsphase des Double Ratchet Algorithmus
 * nach dem Signal Protocol
 */
import { DRState } from "./DR_State";
import { KeyPair } from "./CryptoUtils";
/**
 * Parameter für die Double Ratchet Initialisierung
 */
export interface DRInitParams {
    /** Root Key für die Schlüsselableitung */
    rootKey: Uint8Array;
    /** Unser Identity-Schlüsselpaar */
    ourIdentityKeyPair: KeyPair;
    /** Öffentlicher Identity-Schlüssel der Gegenseite */
    theirIdentityPublicKey: Uint8Array;
    /** Unser ephemerer Schlüssel (wird regelmäßig rotiert) */
    ourEphemeralKeyPair: KeyPair;
    /** Öffentlicher ephemerer Schlüssel der Gegenseite */
    theirEphemeralPublicKey: Uint8Array;
    /** Sind wir der Initiator der Konversation? */
    isInitiator: boolean;
}
/**
 * Initialisiert den Double Ratchet State
 * Führt die initiale Schlüsselvereinbarung durch und richtet die Chain Keys ein
 * @param params - Initialisierungsparameter
 * @returns Der initialisierte Double Ratchet State
 */
export declare function DR_Init(params: DRInitParams): Promise<DRState>;
