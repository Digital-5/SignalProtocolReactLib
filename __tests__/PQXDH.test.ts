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
            const bobOneTimeKeys = generateX25519Keys();
            const aliceDH1 = await stringDiffieHellman(aliceIdentityKeys.privateKey, bobIdentityKeys.publicKey);
            const aliceDH2 = await stringDiffieHellman(aliceEphemeral.privateKey, bobIdentityKeys.publicKey);
            const aliceDH3 = await stringDiffieHellman(aliceEphemeral.privateKey, bobEphemeral.publicKey);
            const aliceDH4 = await stringDiffieHellman(aliceEphemeral.privateKey, bobOneTimeKeys.publicKey);
            const bobDH1 = await stringDiffieHellman(bobIdentityKeys.privateKey, aliceIdentityKeys.publicKey);
            const bobDH2 = await stringDiffieHellman(bobIdentityKeys.privateKey, aliceEphemeral.publicKey);
            const bobDH3 = await stringDiffieHellman(bobEphemeral.privateKey, aliceEphemeral.publicKey);
            const bobDH4 = await stringDiffieHellman(bobOneTimeKeys.privateKey, aliceEphemeral.publicKey);
            const aliceConcat = aliceDH1 + aliceDH2 + aliceDH3 + aliceDH4;
            const bobConcat = bobDH1 + bobDH2 + bobDH3 + bobDH4;
            expect(aliceDH1).toEqual(bobDH1);
            expect(aliceDH2).toEqual(bobDH2);
            expect(aliceDH3).toEqual(bobDH3);
            expect(aliceDH4).toEqual(bobDH4);
            const dh1 = stringHKDF(aliceConcat);
            const dh2 = stringHKDF(bobConcat);
            expect(await dh1).toEqual(await dh2);
        });
    });
});
