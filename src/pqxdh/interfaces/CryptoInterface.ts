/*
 * This is the interface for cryptographic operations such as signing and verifying data.
 * All data coming and going from here shall be in hexadecimal string format.
 * Signatures etc... will be done on the raw bytes represented by the hex strings.
 */

import {HexStringToUInt8Array, UInt8ArrayToHexString} from "../algorithms/CryptoMath";
import {xeddsa_sign, xeddsa_verify} from "../algorithms/XEdDSA";
import {generateX25519KeyPair, x25519PrivateKeyToUint8Array, x25519PublicKeyToUint8Array, deriveSharedSecret} from "../algorithms/X25519";
import {StringKeyPair} from "../objects/StringKeyPair";
import {generateKemKeypair} from "../algorithms/Kyber";
import {HKDF_Func} from "../algorithms/HKDF";

export function generateX25519Keys(): StringKeyPair {
    const keyPair = generateX25519KeyPair()
    const privateKeyHex = x25519PrivateKeyToUint8Array(keyPair.privateKey);
    const publicKeyHex = x25519PublicKeyToUint8Array(keyPair.publicKey);
    return {
        privateKey: UInt8ArrayToHexString(privateKeyHex),
        publicKey: UInt8ArrayToHexString(publicKeyHex)
    };
}

export async function generateKyberKeyPair(): Promise<StringKeyPair> {
    const kyberKeyPair = await generateKemKeypair();
    return {
        privateKey: UInt8ArrayToHexString(kyberKeyPair.privateKey),
        publicKey: UInt8ArrayToHexString(kyberKeyPair.publicKey)
    }
}

export function signKey(privateKey: string, toSign: string) {
    const dataBytes = HexStringToUInt8Array(toSign);
    const privateKeyBytes = HexStringToUInt8Array(privateKey);
    const randomness = crypto.getRandomValues(new Uint8Array(64));
    const signature = xeddsa_sign(privateKeyBytes, dataBytes, randomness);
    const signatureHex = UInt8ArrayToHexString(signature);
    return signatureHex;
}

export function verifySignature(publicKey: string, data: Uint8Array, signature: string) {
    const publicKeyBytes = HexStringToUInt8Array(publicKey);
    const dataBytes = data;
    const signatureBytes = HexStringToUInt8Array(signature);
    const isValid = xeddsa_verify(publicKeyBytes, dataBytes, signatureBytes);
    return isValid;
}

export async function diffieHellman(privateKey: string, publicKey: string): Promise<string> {
    const privateKeyBytes = HexStringToUInt8Array(privateKey);
    const publicKeyBytes = HexStringToUInt8Array(publicKey);
    const sharedSecretBytes = await deriveSharedSecret(privateKeyBytes, publicKeyBytes);
    const sharedSecretHex = UInt8ArrayToHexString(sharedSecretBytes);
    return sharedSecretHex;
}

export async function HKDF_NotFromCopilot(input: Uint8Array): Promise<Uint8Array> {
    return HKDF_Func(input);
}