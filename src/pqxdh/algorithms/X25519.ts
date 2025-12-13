import crypto from "node:crypto";
import {x25519} from "@noble/curves/ed25519.js";

export function generateX25519KeyPair() {
	return crypto.generateKeyPairSync('x25519');
}

export function x25519PublicKeyToUint8Array(publicKey: crypto.KeyObject): Uint8Array {
	const spkiBuf = publicKey.export({ format: 'der', type: 'spki' });
	return new Uint8Array(spkiBuf.buffer, spkiBuf.byteOffset + spkiBuf.length - 32, 32);
}

export function x25519PrivateKeyToUint8Array(privateKey: crypto.KeyObject): Uint8Array {
	const pkcs8Buf = privateKey.export({ format: 'der', type: 'pkcs8' });
	return new Uint8Array(pkcs8Buf.buffer, pkcs8Buf.byteOffset + pkcs8Buf.length - 32, 32);
}

// Stole from Haidar
export async function deriveSharedSecret(
    privateKeyBytes: Uint8Array,
    publicKeyBytes: Uint8Array
): Promise<Uint8Array> {
    // Validierung
    if (privateKeyBytes.length !== 32) {
        throw new Error(`X25519 private key must be 32 bytes, got ${privateKeyBytes.length}`);
    }
    if (publicKeyBytes.length !== 32) {
        throw new Error(`X25519 public key must be 32 bytes, got ${publicKeyBytes.length}`);
    }

    // X25519(privateKey, publicKey) - Berechne Shared Secret
    const sharedSecret = x25519.getSharedSecret(privateKeyBytes, publicKeyBytes);

    return new Uint8Array(sharedSecret);
}