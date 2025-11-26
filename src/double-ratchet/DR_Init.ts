/**
 * Double Ratchet Initialisierung
 * Implementiert die Initialisierungsphase des Double Ratchet Algorithmus
 * nach dem Signal Protocol
 */
import { DRState } from "./DR_State";
import { KeyPair, deriveSharedSecret } from "./CryptoUtils";
import { HKDF } from "./HKDF";

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
export async function DR_Init(params: DRInitParams): Promise<DRState> {
    const { rootKey, ourIdentityKeyPair, theirIdentityPublicKey, ourEphemeralKeyPair, theirEphemeralPublicKey, isInitiator } = params;

    // Schritt 1: Leite die initialen gemeinsamen Geheimnisse mittels ECDH ab
    // DH1: Identity-Schlüssel für langfristige Authentifizierung
    const dh1 = await deriveSharedSecret(ourIdentityKeyPair.privateKey, theirIdentityPublicKey);
    // DH2: Ephemerer Schlüssel für Forward Secrecy
    const dh2 = await deriveSharedSecret(ourEphemeralKeyPair.privateKey, theirEphemeralPublicKey);

    // Schritt 2: Kombiniere beide Geheimnisse für maximale Sicherheit
    const combinedSecret = new Uint8Array(dh1.length + dh2.length);
    combinedSecret.set(dh1);
    combinedSecret.set(dh2, dh1.length);

    // Schritt 3: Verwende HKDF zur Ableitung von Root Key und Chain Keys (SHA-512 für Post-Quantum Sicherheit)
    const hkdf = new HKDF('SHA-512');
    const derivedKeys = await hkdf.deriveKeys(rootKey, combinedSecret, 96); // 96 Bytes für Root und Chain Keys

    // Teile die abgeleiteten Schlüssel auf
    const newRootKey = derivedKeys.slice(0, 32);     // Erste 32 Bytes für Root Key
    const chainKey1 = derivedKeys.slice(32, 64);     // Nächste 32 Bytes für Chain Key 1
    const chainKey2 = derivedKeys.slice(64, 96);     // Letzte 32 Bytes für Chain Key 2

    // Der Initiator verwendet chainKey1 zum Senden und chainKey2 zum Empfangen
    // Der Responder verwendet chainKey2 zum Senden und chainKey1 zum Empfangen
    const sendingChainKey = isInitiator ? chainKey1 : chainKey2;
    const receivingChainKey = isInitiator ? chainKey2 : chainKey1;

    // Schritt 4: Initialisiere den Double Ratchet State
    return {
        rootKey: newRootKey,
        sendingChainKey: sendingChainKey,
        receivingChainKey: receivingChainKey,
        ourEphemeralKeyPair: ourEphemeralKeyPair,
        theirEphemeralPublicKey: theirEphemeralPublicKey,
        messageNumbers: {
            sending: 0,
            receiving: 0
        },
        pn: 0, // Previous Number: Initial 0
        skippedMessageKeys: new Map(),
        maxSkippedMessageKeys: 1000 // Standard: max 1000 skipped keys
    };
}