"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DR_Init_HE = DR_Init_HE;
const CryptoUtils_1 = require("./CryptoUtils");
const HKDF_1 = require("./HKDF");
/**
 * Initialisiert einen Double Ratchet State mit Header Encryption
 * Signal Protocol Specification Section 4.4
 */
async function DR_Init_HE(params) {
    const skippedKeys = new Map();
    if (params.isInitiator) {
        // Alice initialisiert - Signal Spec Section 4.4 RatchetInitAliceHE
        // Alice generiert ihre DH Keys und führt DH mit Bob's Public Key durch
        const dhOutput = await (0, CryptoUtils_1.deriveSharedSecret)(params.ourRatchetKeyPair.privateKey, params.theirRatchetPublicKey);
        const [RK, CKs, NHKs] = await KDF_RK_HE(params.rootKey, dhOutput);
        const state = {
            rootKey: RK,
            sendingChainKey: CKs,
            receivingChainKey: null, // Signal Spec: CKr = None (wird beim ersten Empfang gesetzt)
            ourEphemeralKeyPair: params.ourRatchetKeyPair,
            theirEphemeralPublicKey: params.theirRatchetPublicKey,
            messageNumbers: {
                sending: 0,
                receiving: 0
            },
            pn: 0,
            skippedMessageKeys: skippedKeys,
            sendingHeaderKey: params.sendingHeaderKey,
            receivingHeaderKey: null,
            nextSendingHeaderKey: NHKs,
            nextReceivingHeaderKey: params.nextReceivingHeaderKey
        };
        return state;
    }
    else {
        // Bob initialisiert - Signal Spec Section 4.4 RatchetInitBobHE
        // Signal Spec: Bob's NHKr = Alice's HKs (wird als nextReceivingHeaderKey übergeben)
        //             Bob's NHKs = shared_nhkb (wird als sendingHeaderKey übergeben)
        const state = {
            rootKey: params.rootKey,
            sendingChainKey: null, // Signal Spec: CKs = None (wird beim ersten DH Ratchet Step gesetzt)
            receivingChainKey: null, // Signal Spec: CKr = None (wird beim ersten DH Ratchet Step gesetzt)
            ourEphemeralKeyPair: params.ourRatchetKeyPair,
            theirEphemeralPublicKey: params.theirRatchetPublicKey,
            messageNumbers: {
                sending: 0,
                receiving: 0
            },
            pn: 0,
            skippedMessageKeys: skippedKeys,
            sendingHeaderKey: null, // Signal Spec: HKs = None (wird beim ersten DH Ratchet Step gesetzt)
            receivingHeaderKey: null, // Signal Spec: HKr = None
            nextSendingHeaderKey: params.sendingHeaderKey, // NHKs = shared_nhkb
            nextReceivingHeaderKey: params.nextReceivingHeaderKey // NHKr = shared_hka (Alice's HKs)
        };
        return state;
    }
}
// KDF_RK_HE für Header Encryption
// Signal Spec Section 4.2: KDF_RK_HE(rk, dh_out) returns (root key, chain key, next header key)
async function KDF_RK_HE(rk, dhOutput) {
    // Verwende HKDF mit SHA-512 zur Ableitung von RK, CK und NHK
    // Signal Spec: KDF keyed by RK with DH output as input
    const hkdf = new HKDF_1.HKDF('SHA-512');
    const derived = await hkdf.deriveKeys(rk, // salt = root key
    dhOutput, // input key material = DH output
    96 // 3 x 32 bytes = RK + CK + NHK
    );
    // Teile in 3 x 32 Bytes auf
    const RK = derived.slice(0, 32);
    const CK = derived.slice(32, 64);
    const NHK = derived.slice(64, 96);
    return [RK, CK, NHK];
}
