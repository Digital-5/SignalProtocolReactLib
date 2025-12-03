/**
 * Signal Protocol React Library
 * Eine TypeScript-Implementierung des Signal Protocol für sichere End-to-End-Verschlüsselung
 */

import { calculate_key_pair, xeddsa_sign, xeddsa_verify } from "./pqxdh/algorithms/XEdDSA.js";
import { generateX25519KeyPair, x25519PrivateKeyToUint8Array, x25519PublicKeyToUint8Array } from "./pqxdh/algorithms/X25519.js";
import { Uint8ArrayToBigintLE, bigintToUint8ArrayLE } from "./pqxdh/algorithms/CryptoMath.js";

const keyPair =  generateX25519KeyPair();
const privateKey = x25519PrivateKeyToUint8Array(keyPair.privateKey);
const publicKey = x25519PublicKeyToUint8Array(keyPair.publicKey);
const privateKeyBigint = Uint8ArrayToBigintLE(privateKey);
const message = new Uint8Array([1,2,3,4,5]);

// Generate 64 bytes of random data
const randomData = crypto.getRandomValues(new Uint8Array(64));

const signature = xeddsa_sign(privateKey, message, randomData);
console.log("Signature:", signature);
const isValid = xeddsa_verify(publicKey, message, signature);
console.log("Signature is valid:", isValid);



