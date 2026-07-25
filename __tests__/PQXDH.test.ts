import { generateKemKeypair, encapsulate, decapsulate } from '../src/pqxdh/algorithms/Kyber';
import { convert_mont, xeddsa_sign, xeddsa_verify } from '../src/pqxdh/algorithms/XEdDSA';
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
    describe('cross-component test vectors', () => {
        /**
         * Deterministic XEdDSA test vectors generated with a 64-byte zero nonce.
         * Each vector provides a clamped X25519 private key, an X25519 public key,
         * a UTF-8 message, and the expected signature bytes.
         *
         * Verification: xeddsa_sign(privateKey, utf8(message), zeroNonce) === expectedSig
         *               xeddsa_verify(publicKey, utf8(message), expectedSig) === true
         */
        const ZERO_NONCE = new Uint8Array(64);

        const vectors = [
            {
                privateKeyHex: '4060f0100b9b2564a0e8fa4bc9aac2d4a1b39a6d6a7a2e2c5c3f3e3d3c3b3a78',
                publicKeyHex:  'a3bd3fb554f9c36f49df567f069be85aebc0da4b9dfb27340fd835eda8fe152c',
                message:       'Hello Digital5',
                expectedSignatureHex: 'c6eb465bab7b3af1f680e184c5ce16115122cb6d535d545a89e7de5d6bf60c834d65c0704f66702363f416d903a9dec8c256a172c4ab05eb98f363744c573f05',
            },
            {
                privateKeyHex: '7840d0c0b8f0e060300810584808c8f8e8d8c8b8a89888786856484838281840',
                publicKeyHex:  '348d99030c3eb99e52e849a0192cee7ee1ea29f24a034b04d465a5a2f2a06e72',
                message:       'test message 2',
                expectedSignatureHex: '7412814af2230afa21911df2f7801b62ba2f6a36c00d4d999addbed4033a580f3ca26ffa0f703f32761de24678dabaac87d8bce3a8647b1267d2d0dac9341b01',
            },
            {
                privateKeyHex: 'a0b2c3d4e5f6071829304a5b6c7d8e9f0a1b2c3d4e5f6071829304a5b6c7d860',
                publicKeyHex:  '2b53d89198e7dc9e9670c4dc00ac621bf150a75fe114a2ababa21d9164c0f408',
                message:       'cross-component vector 3',
                expectedSignatureHex: '5710ec052a4e9cface287d1a8ab3073c29273e7d8af7e7b4336eb2ef0ed86abb3ed6c026a7c2acd2c708e9af8d843c76f98ce0b727cd2b42aa245e83954dc600',
            },
            {
                privateKeyHex: '1034567890abcdef1234567890abcdef1234567890abcdef1234567890abcd6f',
                publicKeyHex:  '05ee18184ed593900f639b87b8d99a7a5c5c00cc0aaac5629c45f8869c602907',
                message:       'Signal Protocol XEdDSA',
                expectedSignatureHex: '48199616a1b87f03dc762edee143d969ec568464a31445512a45f903a9b374083feeaf95ac7a0586581ea5cadaabb26140de1314308e3b4fd163ac5d42541508',
            },
            {
                privateKeyHex: 'd8adbeefcafebabe0102030405060708090a0b0c0d0e0f101112131415161758',
                publicKeyHex:  '1113f6376e2ae22135bb91a634c2ee6ce2a545766cba69e25642022752782267',
                message:       'deterministic test vector 5',
                expectedSignatureHex: 'b2820daf791db499b882b2066ec512445f636d4bc1c2fcb4bfb76573ad4effe6d49d0d2955c7d9c8317f1715a8597d288aa453beeab098ea8cb5bb4177d6550f',
            },
        ];

        vectors.forEach(({ privateKeyHex, publicKeyHex, message, expectedSignatureHex }, index) => {
            it(`vector ${index + 1}: sign "${message}" produces expected deterministic signature`, () => {
                const privateKeyBytes = HexStringToUInt8Array(privateKeyHex);
                const messageBytes = new TextEncoder().encode(message);
                const actualSignature = xeddsa_sign(privateKeyBytes, messageBytes, ZERO_NONCE);
                expect(UInt8ArrayToHexString(actualSignature)).toEqual(expectedSignatureHex);
            });

            it(`vector ${index + 1}: verify "${message}" with expected signature returns true`, () => {
                const publicKeyBytes = HexStringToUInt8Array(publicKeyHex);
                const messageBytes = new TextEncoder().encode(message);
                const signatureBytes = HexStringToUInt8Array(expectedSignatureHex);
                const isValid = xeddsa_verify(publicKeyBytes, messageBytes, signatureBytes);
                expect(isValid).toBe(true);
            });
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
