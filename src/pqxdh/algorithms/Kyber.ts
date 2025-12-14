import { MlKem1024 } from "crystals-kyber-js";

/**
 * Generates a Kyber-1024 keypair.
 * @returns Promise with publicKey and privateKey as Uint8Array
 */
export async function generateKemKeypair(): Promise<{ publicKey: Uint8Array, privateKey: Uint8Array }> {
	const kyber = new MlKem1024();
	const [publicKey, privateKey] = await kyber.generateKeyPair();
	return { publicKey, privateKey };
}

/**
 * Encapsulates a secret with the Public Key.
 * @param publicKey The public key of the recipient
 * @returns Promise with ciphertext and sharedSecret as Uint8Array
 */
export async function encapsulate(publicKey: Uint8Array): Promise<{ cipherText: Uint8Array, sharedSecret: Uint8Array }> {
	const kyber = new MlKem1024();
	const [cipherText, sharedSecret] = await kyber.encap(publicKey);
	return { cipherText, sharedSecret };
}

/**
 * Decapsulates the secret with the Private Key.
 * @param cipherText The ciphertext to decapsulate
 * @param privateKey The private key of the recipient
 * @returns Promise with sharedSecret as Uint8Array
 */
export async function decapsulate(cipherText: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
	const kyber = new MlKem1024();
	const sharedSecret = await kyber.decap(cipherText, privateKey);
	return sharedSecret;
}
