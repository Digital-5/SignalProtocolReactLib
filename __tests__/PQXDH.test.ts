import { generateKemKeypair, encapsulate, decapsulate } from '../src/pqxdh/algorithms/Kyber';
import { convert_mont, xeddsa_sign, xeddsa_verify} from '../src/pqxdh/algorithms/XEdDSA';
import { generateX25519KeyPair, x25519PrivateKeyToUint8Array, x25519PublicKeyToUint8Array} from '../src/pqxdh/algorithms/X25519';
import { bigintToUint8ArrayLE, UInt8ArrayToHexString, stringToUint8Array, Uint8ArrayToBigintLE} from '../src/pqxdh/algorithms/CryptoMath';
import {generateX25519Keys, signKey, verifySignature} from "../src/pqxdh/interfaces/CryptoInterface";


describe('PQXDH_Tests', () => {
    describe('XEdDSA', () => {
        it('X25519 to Ed25519 Public Key conversion using known base point', async () => {
            const input = bigintToUint8ArrayLE(9n)
            const edpublic = convert_mont(input);
            expect(UInt8ArrayToHexString(edpublic)).toEqual("5866666666666666666666666666666666666666666666666666666666666666")
        });
        it('Generating X25519, signing and verifying the signature', async () => {
            const stringKeys = generateX25519Keys();
            const message = "Test Key?";
            const signature = signKey(stringKeys.privateKey, message);
            const isValid = verifySignature(stringKeys.publicKey, message, signature);
            expect(isValid).toBe(true);
        });
    });
    describe('Kyber_KEM', () => {
        it('Kyber_encryption_decryption_test', async () => {
            const { publicKey, privateKey } = await generateKemKeypair();
            const { ciphertext, sharedSecret: firstSecret } = await encapsulate(publicKey);
            const secondSecret = await decapsulate(ciphertext, privateKey);
            expect(secondSecret).toEqual(firstSecret);
        });
    });
});