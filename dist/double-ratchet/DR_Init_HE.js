"use strict";
/**
 * Double Ratchet Initialization mit Header Encryption
 * Implementiert Signal Protocol Specification Section 4.4
 * https://signal.org/docs/specifications/doubleratchet/
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.DR_InitHE = DR_InitHE;
const CryptoUtils_1 = require("./CryptoUtils");
const HKDF_1 = require("./HKDF");
/**
 * Initialisiert den Double Ratchet State mit Header Encryption
 * Signal Spec Section 4.4: RatchetInitAliceHE / RatchetInitBobHE
 *
 * @param params - Initialisierungsparameter
 * @returns Initialisierter DRStateHE
 */
async function DR_InitHE(params) {
    const { rootKey, ourIdentityKeyPair, theirIdentityPublicKey, ourEphemeralKeyPair, theirEphemeralPublicKey, sharedSendingHeaderKey, sharedNextReceivingHeaderKey, isInitiator } = params;
    const hkdf = new HKDF_1.HKDF('SHA-512');
    if (isInitiator) {
        // Alice (Initiator) - Signal Spec Section 4.4: RatchetInitAliceHE
        // Signal Spec: state.RK, state.CKs, state.NHKs = KDF_RK_HE(SK, DH(state.DHRs, state.DHRr))
        // Berechne DH Output zwischen Ephemeral Keys
        const dhOutput = await (0, CryptoUtils_1.deriveSharedSecret)(ourEphemeralKeyPair.privateKey, theirEphemeralPublicKey);
        // Leite Root Key + Sending Chain Key + Next Sending Header Key ab
        const [newRootKey, sendingChainKey, nextSendingHeaderKey] = await hkdf.deriveKeysHE(rootKey, dhOutput);
        // Schritt 3: Initialisiere State
        return {
            rootKey: newRootKey,
            sendingChainKey: sendingChainKey,
            receivingChainKey: new Uint8Array(32), // Wird beim ersten DH Ratchet gesetzt
            ourEphemeralKeyPair: ourEphemeralKeyPair,
            theirEphemeralPublicKey: theirEphemeralPublicKey,
            messageNumbers: {
                sending: 0,
                receiving: 0
            },
            pn: 0,
            skippedMessageKeys: new Map(),
            maxSkippedMessageKeys: 1000,
            // Header Encryption Keys
            sendingHeaderKey: sharedSendingHeaderKey, // HKs = shared_hka
            receivingHeaderKey: null, // HKr = None (wird beim ersten Empfang gesetzt)
            nextSendingHeaderKey: nextSendingHeaderKey, // NHKs
            nextReceivingHeaderKey: sharedNextReceivingHeaderKey // NHKr = shared_nhkb
        };
    }
    else {
        // Bob (Responder) - Signal Spec Section 4.4: RatchetInitBobHE
        // Bob wartet auf Alice's erste Nachricht um DH Ratchet durchzuführen
        // Generiere temporäre Chain Keys (werden beim ersten DH Ratchet ersetzt)
        const tempChainKey = await hkdf.deriveKeys(rootKey, new Uint8Array(32), 32);
        return {
            rootKey: rootKey, // RK = SK (unverändert bis zum ersten Empfang)
            sendingChainKey: tempChainKey, // CKs = temporär
            receivingChainKey: tempChainKey, // CKr = temporär
            ourEphemeralKeyPair: ourEphemeralKeyPair,
            theirEphemeralPublicKey: new Uint8Array(32), // DHr = None (wird beim ersten Empfang gesetzt)
            messageNumbers: {
                sending: 0,
                receiving: 0
            },
            pn: 0,
            skippedMessageKeys: new Map(),
            maxSkippedMessageKeys: 1000,
            // Header Encryption Keys
            sendingHeaderKey: crypto.getRandomValues(new Uint8Array(32)), // HKs = temporär
            receivingHeaderKey: null, // HKr = None
            nextSendingHeaderKey: sharedNextReceivingHeaderKey, // NHKs = shared_nhkb
            nextReceivingHeaderKey: sharedSendingHeaderKey // NHKr = shared_hka
        };
    }
}
