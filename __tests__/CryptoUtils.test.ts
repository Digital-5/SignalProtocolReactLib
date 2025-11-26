/**
 * Tests für CryptoUtils
 * Testet ECDH-Schlüsselerzeugung und Shared Secret Ableitung
 */
import { generateKeyPair, deriveSharedSecret } from '../src/double-ratchet/CryptoUtils';

describe('CryptoUtils', () => {
    describe('generateKeyPair', () => {
        it('sollte ein gültiges Schlüsselpaar generieren', async () => {
            const keyPair = await generateKeyPair();

            expect(keyPair).toBeDefined();
            expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
            expect(keyPair.privateKey).toBeInstanceOf(Uint8Array);
            expect(keyPair.publicKey.length).toBeGreaterThan(0);
            expect(keyPair.privateKey.length).toBeGreaterThan(0);
        });

        it('sollte bei jedem Aufruf unterschiedliche Schlüssel generieren', async () => {
            const keyPair1 = await generateKeyPair();
            const keyPair2 = await generateKeyPair();

            expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey);
            expect(keyPair1.privateKey).not.toEqual(keyPair2.privateKey);
        });
    });

    describe('deriveSharedSecret', () => {
        it('sollte dasselbe gemeinsame Geheimnis für beide Parteien ableiten', async () => {
            const aliceKeyPair = await generateKeyPair();
            const bobKeyPair = await generateKeyPair();

            const aliceSharedSecret = await deriveSharedSecret(
                aliceKeyPair.privateKey,
                bobKeyPair.publicKey
            );

            const bobSharedSecret = await deriveSharedSecret(
                bobKeyPair.privateKey,
                aliceKeyPair.publicKey
            );

            expect(aliceSharedSecret).toEqual(bobSharedSecret);
            expect(aliceSharedSecret.length).toBe(32); // 256 bits = 32 bytes
        });

        it('sollte unterschiedliche Geheimnisse für verschiedene Schlüsselpaare erzeugen', async () => {
            const alice1 = await generateKeyPair();
            const alice2 = await generateKeyPair();
            const bob = await generateKeyPair();

            const secret1 = await deriveSharedSecret(alice1.privateKey, bob.publicKey);
            const secret2 = await deriveSharedSecret(alice2.privateKey, bob.publicKey);

            expect(secret1).not.toEqual(secret2);
        });

        it('sollte einen Fehler werfen bei ungültigen Schlüsseln', async () => {
            const validKeyPair = await generateKeyPair();
            const invalidKey = new Uint8Array(10); // Zu kurz

            await expect(
                deriveSharedSecret(invalidKey, validKeyPair.publicKey)
            ).rejects.toThrow();
        });
    });
});

