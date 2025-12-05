import crypto from "node:crypto";

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
