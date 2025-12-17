import { generateKemKeypair, encapsulate, decapsulate } from '../src/pqxdh/algorithms/Kyber';
import { convert_mont} from '../src/pqxdh/algorithms/XEdDSA';
import { bigintToUint8ArrayLE, HexStringToUInt8Array, UInt8ArrayToHexString} from '../src/pqxdh/algorithms/CryptoMath';
import {generateX25519Keys, signKey, verifySignature, stringHKDF, stringDiffieHellman, generateKyberKeyPair, encapsulateKyber, decapsulateKyber} from "../src/pqxdh/interfaces/CryptoInterface";

describe('PQXDH_Tests', () => {
    describe('XEdDSA', () => {
        it('X25519 to Ed25519 Public Key conversion using known base point', async () => {
            const input = bigintToUint8ArrayLE(9n)
            const edpublic = convert_mont(input);
            expect(UInt8ArrayToHexString(edpublic)).toEqual("5866666666666666666666666666666666666666666666666666666666666666")
        });
        it('Generating X25519, signing and verifying the signature', async () => {
            const stringKeys = generateX25519Keys();
            const message = "F6A1FA6512"; // Random message in hex
            const signature = signKey(stringKeys.privateKey, message);
            console.log(stringKeys.publicKey)
            console.log(stringKeys.privateKey)
            const isValid = verifySignature(stringKeys.publicKey, message, signature);
            expect(isValid).toBe(true);
        });
        it('Generating X25519 checking length', async () => {
            const stringKeys = generateX25519Keys();
            expect(HexStringToUInt8Array(stringKeys.privateKey).length).toBe(32);
            expect(HexStringToUInt8Array(stringKeys.publicKey).length).toBe(32);
        });
    });
    describe('Kyber_KEM', () => {
        it('LowLevelDecapsulationTest', async () => {
            const { publicKey, privateKey } = await generateKemKeypair();
            const { cipherText, sharedSecret: firstSecret } = await encapsulate(publicKey);
            const secondSecret = await decapsulate(cipherText, privateKey);
            expect(secondSecret).toEqual(firstSecret);
        });
        it('HighLevelDecapsulationTest', async () => {
            const keyPair = await generateKyberKeyPair();
            const { cipherText: cipherText, sharedSecret: firstSecret } = await encapsulateKyber(keyPair.publicKey);
            const secondSecret = await decapsulateKyber(cipherText, keyPair.privateKey);
            expect(secondSecret).toEqual(firstSecret);
        });
    });
    describe('Key Derivation and Shared Secrets', () => {
        it('Simple Diffie Hellman function Tests', async () => {
            const aliceKeys = generateX25519Keys();
            const bobKeys = generateX25519Keys();
            const dh1 = stringDiffieHellman(aliceKeys.privateKey, bobKeys.publicKey);
            const dh2 = stringDiffieHellman(bobKeys.privateKey, aliceKeys.publicKey);
            expect(await dh1).toEqual(await dh2);
        });
        it('Complete Key Derivation using multiple Diffie-Hellman functions', async () => {
            const aliceIdentityKeys = generateX25519Keys();
            const aliceEphemeral = generateX25519Keys();
            const bobIdentityKeys = generateX25519Keys();
            const bobEphemeral = generateX25519Keys();

            const aliceDH1 = stringDiffieHellman(aliceKeys.privateKey, bobKeys.publicKey);
            const aliceDH2 = stringDiffieHellman(aliceEphemeral.privateKey, bobKeys.publicKey);
            const aliceDH3 = stringDiffieHellman(aliceKeys.privateKey, bobEphemeral.publicKey);
            const aliceDH4 = stringDiffieHellman(aliceEphemeral.privateKey, bobEphemeral.publicKey);
            // Bob's DH Operationen müssen in der gleichen Reihenfolge sein (DH ist kommutativ)
            const bobDH1 = stringDiffieHellman(bobKeys.privateKey, aliceKeys.publicKey);
            const bobDH2 = stringDiffieHellman(bobKeys.privateKey, aliceEphemeral.publicKey); // Korrigiert!
            const bobDH3 = stringDiffieHellman(bobEphemeral.privateKey, aliceKeys.publicKey);
            const bobDH4 = stringDiffieHellman(bobEphemeral.privateKey, aliceEphemeral.publicKey);
            const aliceConcat = (await aliceDH1) + (await aliceDH2) + (await aliceDH3) + (await aliceDH4);
            const bobConcat = (await bobDH1) + (await bobDH2) + (await bobDH3) + (await bobDH4);

            const dh1 = stringHKDF(aliceConcat);
            const dh2 = stringHKDF(bobConcat);
            expect(await dh1).toEqual(await dh2);
        });
    });
});