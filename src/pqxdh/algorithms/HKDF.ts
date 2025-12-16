import { concatenateUint8Arrays } from "./CryptoMath";
import { hkdf } from "@noble/hashes/hkdf.js"
import { sha256 } from "@noble/hashes/sha2.js";

export function HKDF_Func(
    input: Uint8Array
): Uint8Array {
    // 32 Bytes 0xFF as specified in docs for Curve25519
    const prefix = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        prefix[i] = 0xFF;
    }
    // 32 bytes of 0x00 as specified for sha256
    const salt = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        salt[i] = 0x00;
    }
    const INFO = "DIGITAL5_CURVE25519_SHA-512_CRYSTALS-KYBER-1024"
    const INFO_BYTES = new TextEncoder().encode(INFO);
    const ikm = concatenateUint8Arrays([prefix, input]);
    return hkdf(sha256, ikm, salt, INFO_BYTES, 32);

}