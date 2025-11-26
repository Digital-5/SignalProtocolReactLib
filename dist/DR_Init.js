"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DR_Init = DR_Init;
const CryptoUtils_js_1 = require("./CryptoUtils.js");
const HKDF_js_1 = require("./HKDF.js");
/**
 * Initialisiert den Double Ratchet State
 * Führt die initiale Schlüsselvereinbarung durch und richtet die Chain Keys ein
 * @param params - Initialisierungsparameter
 * @returns Der initialisierte Double Ratchet State
 */
async function DR_Init(params) {
    const { rootKey, ourIdentityKeyPair, theirIdentityPublicKey, ourEphemeralKeyPair, theirEphemeralPublicKey, isInitiator } = params;
    // Schritt 1: Leite die initialen gemeinsamen Geheimnisse mittels ECDH ab
    // DH1: Identity-Schlüssel für langfristige Authentifizierung
    const dh1 = await (0, CryptoUtils_js_1.deriveSharedSecret)(ourIdentityKeyPair.privateKey, theirIdentityPublicKey);
    // DH2: Ephemerer Schlüssel für Forward Secrecy
    const dh2 = await (0, CryptoUtils_js_1.deriveSharedSecret)(ourEphemeralKeyPair.privateKey, theirEphemeralPublicKey);
    // Schritt 2: Kombiniere beide Geheimnisse für maximale Sicherheit
    const combinedSecret = new Uint8Array(dh1.length + dh2.length);
    combinedSecret.set(dh1);
    combinedSecret.set(dh2, dh1.length);
    // Schritt 3: Verwende HKDF zur Ableitung von Root Key und Chain Keys
    const hkdf = new HKDF_js_1.HKDF('SHA-256');
    const derivedKeys = await hkdf.deriveKeys(rootKey, combinedSecret, 96); // 96 Bytes für Root und Chain Keys
    // Teile die abgeleiteten Schlüssel auf
    const newRootKey = derivedKeys.slice(0, 32); // Erste 32 Bytes für Root Key
    const chainKey1 = derivedKeys.slice(32, 64); // Nächste 32 Bytes für Chain Key 1
    const chainKey2 = derivedKeys.slice(64, 96); // Letzte 32 Bytes für Chain Key 2
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
        }
    };
}
