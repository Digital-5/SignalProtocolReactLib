/*
 * This is the interface for cryptographic operations such as signing and verifying data.
 * All data coming and going from here shall be in hexadecimal string format.
 * Signatures etc... will be done on the raw bytes represented by the hex strings.
 */

import {HexStringToUInt8Array, UInt8ArrayToHexString} from "../algorithms/CryptoMath";
import {xeddsa_sign, xeddsa_verify} from "../algorithms/XEdDSA";
import {generateX25519KeyPair, deriveSharedSecret} from "../algorithms/X25519";
import {StringKeyPair} from "../objects/StringKeyPair";
import {generateKemKeypair, encapsulate, decapsulate} from "../algorithms/Kyber";
import {HKDF_Func} from "../algorithms/HKDF";

export function generateX25519Keys(): StringKeyPair {
    const keyPair = generateX25519KeyPair()
    const privateKeyHex = UInt8ArrayToHexString(keyPair.privateKey);
    const publicKeyHex = UInt8ArrayToHexString(keyPair.publicKey);
    return {
        privateKey: privateKeyHex,
        publicKey: publicKeyHex
    };
}

export async function generateKyberKeyPair(): Promise<StringKeyPair> {
    const kyberKeyPair = await generateKemKeypair();
    return {
        privateKey: UInt8ArrayToHexString(kyberKeyPair.privateKey),
        publicKey: UInt8ArrayToHexString(kyberKeyPair.publicKey)
    }
}

export async function encapsulateKyber(publicKey: string): Promise<{ cipherText: string, sharedSecret: string }> {
    const publicKeyBytes = HexStringToUInt8Array(publicKey);
    const { cipherText: cipherText, sharedSecret: sharedSecret } = await encapsulate(publicKeyBytes);
    return {
        cipherText: UInt8ArrayToHexString(cipherText),
        sharedSecret: UInt8ArrayToHexString(sharedSecret)
    };
}

export async function decapsulateKyber(cipherText: string, privateKey: string): Promise<string> {
    const cipherTextBytes = HexStringToUInt8Array(cipherText);
    const privateKeyBytes = HexStringToUInt8Array(privateKey);
    const sharedSecretBytes = await decapsulate(cipherTextBytes, privateKeyBytes);
    return UInt8ArrayToHexString(sharedSecretBytes);
}

export function signKey(privateKey: string, toSign: string) {
    const dataBytes = HexStringToUInt8Array(toSign);
    const privateKeyBytes = HexStringToUInt8Array(privateKey);
    const randomness = crypto.getRandomValues(new Uint8Array(64));
    const signature = xeddsa_sign(privateKeyBytes, dataBytes, randomness);
    const signatureHex = UInt8ArrayToHexString(signature);
    return signatureHex;
}

export function verifySignature(publicKey: string, data: string, signature: string) {
    const publicKeyBytes = HexStringToUInt8Array(publicKey);
    const dataBytes = HexStringToUInt8Array(data);
    const signatureBytes = HexStringToUInt8Array(signature);
    const isValid = xeddsa_verify(publicKeyBytes, dataBytes, signatureBytes);
    return isValid;
}

export async function stringDiffieHellman(privateKey: string, publicKey: string): Promise<string> {
    const privateKeyBytes = HexStringToUInt8Array(privateKey);
    const publicKeyBytes = HexStringToUInt8Array(publicKey);
    const sharedSecretBytes = await deriveSharedSecret(privateKeyBytes, publicKeyBytes);
    const sharedSecretHex = UInt8ArrayToHexString(sharedSecretBytes);
    return sharedSecretHex;
}

export async function stringHKDF(input: string): Promise<Uint8Array> {
    const hex = HexStringToUInt8Array(input);
    return HKDF_Func(hex);
}