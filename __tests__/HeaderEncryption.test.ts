/**
 * Tests für Header Encryption (Signal Protocol Section 4)
 * Testet verschlüsselte Header und erweiterte State-Verwaltung
 */
import { DR_Init_HE } from '../src/double-ratchet/DR_Init_HE';
import { ratchetEncryptHE, ratchetDecryptHE } from '../src/double-ratchet/DR_Ratchet_HE';
import { DRState, MessageHeader } from '../src/double-ratchet/DR_Interfaces';
import { encryptHeader, decryptHeader } from '../src/double-ratchet/HeaderEncryption';
import { generateKeyPair } from '../src/double-ratchet/CryptoUtils';

describe('Header Encryption (Section 4)', () => {
    let aliceEphemeralKeyPair: any;
    let bobEphemeralKeyPair: any;
    let rootKey: Uint8Array;
    let sharedSendingHeaderKey: Uint8Array;
    let sharedNextReceivingHeaderKey: Uint8Array;

    beforeEach(async () => {
        aliceEphemeralKeyPair = await generateKeyPair();
        bobEphemeralKeyPair = await generateKeyPair();
        rootKey = crypto.getRandomValues(new Uint8Array(32));
        sharedSendingHeaderKey = crypto.getRandomValues(new Uint8Array(32));
        sharedNextReceivingHeaderKey = crypto.getRandomValues(new Uint8Array(32));
    });

    describe('DR_Init_HE', () => {
        it('sollte Alice korrekt mit Header Encryption initialisieren', async () => {
            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceEphemeralKeyPair,
                theirRatchetPublicKey: bobEphemeralKeyPair.publicKey,
                HeaderKey: sharedSendingHeaderKey,
                nextReceivingHeaderKey: sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            expect(aliceState.rootKey).toBeInstanceOf(Uint8Array);
            expect(aliceState.sendingChainKey).toBeInstanceOf(Uint8Array);
            expect(aliceState.messageNumbers.sending).toBe(0);
            expect(aliceState.messageNumbers.receiving).toBe(0);
            expect(aliceState.HeaderKeys.sendingHeaderKey).toEqual(sharedSendingHeaderKey);
            // sendingNextHeaderKey wird vom KDF_RK_HE berechnet, nicht vom Input übernommen
            expect(aliceState.HeaderKeys.sendingNextHeaderKey).toBeInstanceOf(Uint8Array);
            expect(aliceState.HeaderKeys.sendingNextHeaderKey?.length).toBe(32);
            expect(aliceState.HeaderKeys.receivingNextHeaderKey).toEqual(sharedNextReceivingHeaderKey);
        });

        it('sollte Bob korrekt mit Header Encryption initialisieren', async () => {
            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobEphemeralKeyPair,
                theirRatchetPublicKey: aliceEphemeralKeyPair.publicKey,
                HeaderKey: sharedNextReceivingHeaderKey,
                nextReceivingHeaderKey: sharedSendingHeaderKey,
                isInitiator: false
            });

            expect(bobState.rootKey).toEqual(rootKey);
            expect(bobState.HeaderKeys.sendingNextHeaderKey).toEqual(sharedNextReceivingHeaderKey);
            expect(bobState.HeaderKeys.receivingNextHeaderKey).toEqual(sharedSendingHeaderKey);
        });
    });

    describe('Header Encryption/Decryption', () => {
        it('sollte Header verschlüsseln und entschlüsseln können', async () => {
            const headerKey = crypto.getRandomValues(new Uint8Array(32));
            const header: MessageHeader = {
                dh: aliceEphemeralKeyPair.publicKey,
                pn: 5,
                n: 10
            };

            const encrypted = await encryptHeader(headerKey, header);
            expect(encrypted).toBeInstanceOf(Uint8Array);
            expect(encrypted.length).toBeGreaterThan(0);

            const decrypted = await decryptHeader(headerKey, encrypted);
            expect(decrypted).not.toBeNull();
            expect(decrypted!.dh).toEqual(header.dh);
            expect(decrypted!.pn).toBe(header.pn);
            expect(decrypted!.n).toBe(header.n);
        });

        it('sollte bei falschem Key fehlschlagen', async () => {
            const headerKey = crypto.getRandomValues(new Uint8Array(32));
            const wrongKey = crypto.getRandomValues(new Uint8Array(32));
            const header: MessageHeader = {
                dh: aliceEphemeralKeyPair.publicKey,
                pn: 5,
                n: 10
            };

            const encrypted = await encryptHeader(headerKey, header);
            const decrypted = await decryptHeader(wrongKey, encrypted);
            expect(decrypted).toBeNull();
        });

        it('sollte mit null Header Key null zurückgeben', async () => {
            const encrypted = crypto.getRandomValues(new Uint8Array(100));
            const decrypted = await decryptHeader(null, encrypted);
            expect(decrypted).toBeNull();
        });
    });

    describe('End-to-End mit Header Encryption', () => {
        it('sollte eine Nachricht mit verschlüsseltem Header senden und empfangen', async () => {
            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceEphemeralKeyPair,
                theirRatchetPublicKey: bobEphemeralKeyPair.publicKey,
                HeaderKey: sharedSendingHeaderKey,
                nextReceivingHeaderKey: sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobEphemeralKeyPair,
                theirRatchetPublicKey: aliceEphemeralKeyPair.publicKey,
                HeaderKey: sharedNextReceivingHeaderKey,
                nextReceivingHeaderKey: sharedSendingHeaderKey,
                isInitiator: false
            });

            const plaintext = new TextEncoder().encode('Test mit Header Encryption');
            const [encrypted, newAliceState] = await ratchetEncryptHE(aliceState, plaintext);

            expect(encrypted.encryptedHeader).toBeInstanceOf(Uint8Array);
            expect(encrypted.ciphertext).toBeInstanceOf(Uint8Array);

            const [decrypted, newBobState] = await ratchetDecryptHE(bobState, encrypted);
            expect(decrypted).toEqual(plaintext);
        });

        it('sollte mehrere Nachrichten mit Header Encryption verarbeiten', async () => {
            let aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceEphemeralKeyPair,
                theirRatchetPublicKey: bobEphemeralKeyPair.publicKey,
                HeaderKey: sharedSendingHeaderKey,
                nextReceivingHeaderKey: sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            let bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobEphemeralKeyPair,
                theirRatchetPublicKey: aliceEphemeralKeyPair.publicKey,
                HeaderKey: sharedNextReceivingHeaderKey,
                nextReceivingHeaderKey: sharedSendingHeaderKey,
                isInitiator: false
            });

            // Alice sendet 3 Nachrichten
            const messages = ['Nachricht 1', 'Nachricht 2', 'Nachricht 3'];
            const encrypted: any[] = [];

            for (const msg of messages) {
                const plaintext = new TextEncoder().encode(msg);
                const [enc, newState] = await ratchetEncryptHE(aliceState, plaintext);
                encrypted.push(enc);
                aliceState = newState;
            }

            // Bob empfängt alle Nachrichten
            for (let i = 0; i < messages.length; i++) {
                const [decrypted, newState] = await ratchetDecryptHE(bobState, encrypted[i]);
                expect(new TextDecoder().decode(decrypted)).toBe(messages[i]);
                bobState = newState;
            }
        });

        it('sollte bidirektionale Kommunikation mit Header Encryption unterstützen', async () => {
            let aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceEphemeralKeyPair,
                theirRatchetPublicKey: bobEphemeralKeyPair.publicKey,
                HeaderKey: sharedSendingHeaderKey,
                nextReceivingHeaderKey: sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            let bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobEphemeralKeyPair,
                theirRatchetPublicKey: aliceEphemeralKeyPair.publicKey,
                HeaderKey: sharedNextReceivingHeaderKey,
                nextReceivingHeaderKey: sharedSendingHeaderKey,
                isInitiator: false
            });

            // Alice -> Bob
            const msg1 = new TextEncoder().encode('Hallo Bob');
            const [enc1, newAliceState1] = await ratchetEncryptHE(aliceState, msg1);
            aliceState = newAliceState1;

            const [dec1, newBobState1] = await ratchetDecryptHE(bobState, enc1);
            bobState = newBobState1;
            expect(dec1).toEqual(msg1);

            // Bob -> Alice
            const msg2 = new TextEncoder().encode('Hallo Alice');
            const [enc2, newBobState2] = await ratchetEncryptHE(bobState, msg2);
            bobState = newBobState2;

            const [dec2, newAliceState2] = await ratchetDecryptHE(aliceState, enc2);
            aliceState = newAliceState2;
            expect(dec2).toEqual(msg2);

            // Alice -> Bob nochmal
            const msg3 = new TextEncoder().encode('Wie geht es?');
            const [enc3, newAliceState3] = await ratchetEncryptHE(aliceState, msg3);
            aliceState = newAliceState3;

            const [dec3, newBobState3] = await ratchetDecryptHE(bobState, enc3);
            bobState = newBobState3;
            expect(dec3).toEqual(msg3);
        });
    });

    describe('Edge Cases mit Header Encryption', () => {
        it('sollte mit manipulierten Headers umgehen', async () => {
            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceEphemeralKeyPair,
                theirRatchetPublicKey: bobEphemeralKeyPair.publicKey,
                HeaderKey: sharedSendingHeaderKey,
                nextReceivingHeaderKey: sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobEphemeralKeyPair,
                theirRatchetPublicKey: aliceEphemeralKeyPair.publicKey,
                HeaderKey: sharedNextReceivingHeaderKey,
                nextReceivingHeaderKey: sharedSendingHeaderKey,
                isInitiator: false
            });

            const plaintext = new TextEncoder().encode('Test');
            const [encrypted, _] = await ratchetEncryptHE(aliceState, plaintext);

            // Manipuliere Header
            encrypted.encryptedHeader[0] ^= 1;

            await expect(ratchetDecryptHE(bobState, encrypted)).rejects.toThrow();
        });

        it('sollte leere Nachrichten mit Header Encryption verarbeiten', async () => {
            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceEphemeralKeyPair,
                theirRatchetPublicKey: bobEphemeralKeyPair.publicKey,
                HeaderKey: sharedSendingHeaderKey,
                nextReceivingHeaderKey: sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobEphemeralKeyPair,
                theirRatchetPublicKey: aliceEphemeralKeyPair.publicKey,
                HeaderKey: sharedNextReceivingHeaderKey,
                nextReceivingHeaderKey: sharedSendingHeaderKey,
                isInitiator: false
            });

            const plaintext = new Uint8Array(0);
            const [encrypted, _] = await ratchetEncryptHE(aliceState, plaintext);
            const [decrypted, __] = await ratchetDecryptHE(bobState, encrypted);

            expect(decrypted).toEqual(plaintext);
            expect(decrypted.length).toBe(0);
        });

        it('sollte sehr lange Nachrichten mit Header Encryption verarbeiten', async () => {
            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceEphemeralKeyPair,
                theirRatchetPublicKey: bobEphemeralKeyPair.publicKey,
                HeaderKey: sharedSendingHeaderKey,
                nextReceivingHeaderKey: sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobEphemeralKeyPair,
                theirRatchetPublicKey: aliceEphemeralKeyPair.publicKey,
                HeaderKey: sharedNextReceivingHeaderKey,
                nextReceivingHeaderKey: sharedSendingHeaderKey,
                isInitiator: false
            });

            // 64 KB Nachricht (Maximum für crypto.getRandomValues)
            const plaintext = crypto.getRandomValues(new Uint8Array(64 * 1024));
            const [encrypted, _] = await ratchetEncryptHE(aliceState, plaintext);
            const [decrypted, __] = await ratchetDecryptHE(bobState, encrypted);

            expect(decrypted).toEqual(plaintext);
        });
    });
});

