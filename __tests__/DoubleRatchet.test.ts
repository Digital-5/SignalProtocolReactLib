/**
 * Tests für Double Ratchet
 * Testet die vollständige Implementierung inkl. Verschlüsselung, Entschlüsselung und Ratchet Steps
 */
import { DR_Init } from '../src/double-ratchet/DR_Init';
import { ratchetEncrypt, ratchetDecrypt, performDHRatchet } from '../src/double-ratchet/DR_Ratchet';
import { generateKeyPair } from '../src/double-ratchet/CryptoUtils';
import { DRState } from '../src/double-ratchet/DR_State';

describe('Double Ratchet', () => {
    let aliceIdentityKeyPair: any;
    let bobIdentityKeyPair: any;
    let aliceEphemeralKeyPair: any;
    let bobEphemeralKeyPair: any;
    let rootKey: Uint8Array;

    // Optimierung: Generiere Schlüsselpaare nur einmal für alle Tests (spart ~100ms)
    beforeAll(async () => {
        aliceIdentityKeyPair = await generateKeyPair();
        bobIdentityKeyPair = await generateKeyPair();
        aliceEphemeralKeyPair = await generateKeyPair();
        bobEphemeralKeyPair = await generateKeyPair();
    });

    beforeEach(() => {
        // Nur Root Key neu generieren (schnell, ~0.1ms)
        rootKey = crypto.getRandomValues(new Uint8Array(32));
    });

    describe('DR_Init', () => {
        it('sollte einen gültigen Double Ratchet State initialisieren', async () => {
            const state = await DR_Init({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                isInitiator: true
            });

            expect(state).toBeDefined();
            expect(state.rootKey).toBeInstanceOf(Uint8Array);
            expect(state.sendingChainKey).toBeInstanceOf(Uint8Array);
            expect(state.receivingChainKey).toBeInstanceOf(Uint8Array);
            expect(state.ourEphemeralKeyPair).toBeDefined();
            expect(state.theirEphemeralPublicKey).toBeInstanceOf(Uint8Array);
            expect(state.messageNumbers.sending).toBe(0);
            expect(state.messageNumbers.receiving).toBe(0);
        });

        it('sollte verschiedene States für verschiedene Eingaben erzeugen', async () => {
            const state1 = await DR_Init({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                isInitiator: true
            });

            const differentRootKey = crypto.getRandomValues(new Uint8Array(32));
            const state2 = await DR_Init({
                rootKey: differentRootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                isInitiator: true
            });

            expect(state1.rootKey).not.toEqual(state2.rootKey);
            expect(state1.sendingChainKey).not.toEqual(state2.sendingChainKey);
        });
    });

    describe('ratchetEncrypt & ratchetDecrypt', () => {
        it('sollte eine Nachricht verschlüsseln und entschlüsseln können', async () => {
            // Initialisiere Alice's State (Initiator)
            const aliceState = await DR_Init({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                isInitiator: true
            });

            // Initialisiere Bob's State (Responder)
            const bobState = await DR_Init({
                rootKey,
                ourIdentityKeyPair: bobIdentityKeyPair,
                theirIdentityPublicKey: aliceIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: bobEphemeralKeyPair,
                theirEphemeralPublicKey: aliceEphemeralKeyPair.publicKey,
                isInitiator: false
            });

            // Alice verschlüsselt eine Nachricht
            const plaintext = new TextEncoder().encode('Hallo Bob!');
            const [encryptedMessage, newAliceState] = await ratchetEncrypt(aliceState, plaintext);

            expect(encryptedMessage).toBeDefined();
            expect(encryptedMessage.header.dh).toEqual(aliceState.ourEphemeralKeyPair.publicKey);
            expect(encryptedMessage.header.n).toBe(0);
            expect(encryptedMessage.header.pn).toBe(0);
            expect(encryptedMessage.ciphertext).toBeInstanceOf(Uint8Array);

            // Bob entschlüsselt die Nachricht
            const [decryptedMessage, newBobState] = await ratchetDecrypt(bobState, encryptedMessage);

            expect(decryptedMessage).toEqual(plaintext);
            expect(new TextDecoder().decode(decryptedMessage)).toBe('Hallo Bob!');
        });

        it('sollte mehrere Nachrichten nacheinander verschlüsseln können', async () => {
            const aliceState = await DR_Init({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                isInitiator: true
            });

            const bobState = await DR_Init({
                rootKey,
                ourIdentityKeyPair: bobIdentityKeyPair,
                theirIdentityPublicKey: aliceIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: bobEphemeralKeyPair,
                theirEphemeralPublicKey: aliceEphemeralKeyPair.publicKey,
                isInitiator: false
            });

            // Sende 3 Nachrichten von Alice zu Bob
            let currentAliceState = aliceState;
            let currentBobState = bobState;

            for (let i = 0; i < 3; i++) {
                const plaintext = new TextEncoder().encode(`Nachricht ${i + 1}`);
                const [encryptedMessage, newAliceState] = await ratchetEncrypt(currentAliceState, plaintext);
                currentAliceState = newAliceState;

                const [decryptedMessage, newBobState] = await ratchetDecrypt(currentBobState, encryptedMessage);
                currentBobState = newBobState;

                expect(new TextDecoder().decode(decryptedMessage)).toBe(`Nachricht ${i + 1}`);
                expect(encryptedMessage.header.n).toBe(i);
            }
        });

        it('sollte bidirektionale Kommunikation unterstützen', async () => {
            let aliceState = await DR_Init({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                isInitiator: true
            });

            let bobState = await DR_Init({
                rootKey,
                ourIdentityKeyPair: bobIdentityKeyPair,
                theirIdentityPublicKey: aliceIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: bobEphemeralKeyPair,
                theirEphemeralPublicKey: aliceEphemeralKeyPair.publicKey,
                isInitiator: false
            });

            // Alice -> Bob
            const plaintext1 = new TextEncoder().encode('Hallo Bob!');
            let [msg1, newAliceState] = await ratchetEncrypt(aliceState, plaintext1);
            aliceState = newAliceState;

            let [decrypted1, newBobState] = await ratchetDecrypt(bobState, msg1);
            bobState = newBobState;
            expect(new TextDecoder().decode(decrypted1)).toBe('Hallo Bob!');

            // Bob -> Alice
            const plaintext2 = new TextEncoder().encode('Hallo Alice!');
            let [msg2, newBobState2] = await ratchetEncrypt(bobState, plaintext2);
            bobState = newBobState2;

            let [decrypted2, newAliceState2] = await ratchetDecrypt(aliceState, msg2);
            aliceState = newAliceState2;
            expect(new TextDecoder().decode(decrypted2)).toBe('Hallo Alice!');

            // Alice -> Bob (wieder)
            const plaintext3 = new TextEncoder().encode('Wie geht es dir?');
            let [msg3, newAliceState3] = await ratchetEncrypt(aliceState, plaintext3);
            aliceState = newAliceState3;

            let [decrypted3, newBobState3] = await ratchetDecrypt(bobState, msg3);
            bobState = newBobState3;
            expect(new TextDecoder().decode(decrypted3)).toBe('Wie geht es dir?');
        });

        it('sollte Message Numbers korrekt inkrementieren', async () => {
            const aliceState = await DR_Init({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                isInitiator: true
            });

            let currentState = aliceState;

            for (let i = 0; i < 5; i++) {
                const [msg, newState] = await ratchetEncrypt(currentState, new Uint8Array([i]));
                expect(msg.header.n).toBe(i);
                expect(newState.messageNumbers.sending).toBe(i + 1);
                currentState = newState;
            }
        });
    });

    describe('Edge Cases', () => {
        it('sollte leere Nachrichten verarbeiten können', async () => {
            const aliceState = await DR_Init({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                isInitiator: true
            });

            const bobState = await DR_Init({
                rootKey,
                ourIdentityKeyPair: bobIdentityKeyPair,
                theirIdentityPublicKey: aliceIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: bobEphemeralKeyPair,
                theirEphemeralPublicKey: aliceEphemeralKeyPair.publicKey,
                isInitiator: false
            });

            const emptyMessage = new Uint8Array(0);
            const [encrypted, newAliceState] = await ratchetEncrypt(aliceState, emptyMessage);
            const [decrypted, newBobState] = await ratchetDecrypt(bobState, encrypted);

            expect(decrypted).toEqual(emptyMessage);
        });

        it('sollte sehr lange Nachrichten verarbeiten können', async () => {
            const aliceState = await DR_Init({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                isInitiator: true
            });

            const bobState = await DR_Init({
                rootKey,
                ourIdentityKeyPair: bobIdentityKeyPair,
                theirIdentityPublicKey: aliceIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: bobEphemeralKeyPair,
                theirEphemeralPublicKey: aliceEphemeralKeyPair.publicKey,
                isInitiator: false
            });

            const longMessage = new Uint8Array(10000).fill(42);
            const [encrypted, newAliceState] = await ratchetEncrypt(aliceState, longMessage);
            const [decrypted, newBobState] = await ratchetDecrypt(bobState, encrypted);

            expect(decrypted).toEqual(longMessage);
        });

        it('sollte bei manipulierter Nachricht einen Fehler werfen', async () => {
            const aliceState = await DR_Init({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                isInitiator: true
            });

            const bobState = await DR_Init({
                rootKey,
                ourIdentityKeyPair: bobIdentityKeyPair,
                theirIdentityPublicKey: aliceIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: bobEphemeralKeyPair,
                theirEphemeralPublicKey: aliceEphemeralKeyPair.publicKey,
                isInitiator: false
            });

            const plaintext = new TextEncoder().encode('Geheime Nachricht');
            const [encrypted, newAliceState] = await ratchetEncrypt(aliceState, plaintext);

            // Manipuliere die Nachricht
            encrypted.ciphertext[0] ^= 1;

            // Entschlüsselung sollte fehlschlagen
            await expect(ratchetDecrypt(bobState, encrypted)).rejects.toThrow();
        });

        it('sollte mit Unicode-Nachrichten funktionieren', async () => {
            const aliceState = await DR_Init({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                isInitiator: true
            });

            const bobState = await DR_Init({
                rootKey,
                ourIdentityKeyPair: bobIdentityKeyPair,
                theirIdentityPublicKey: aliceIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: bobEphemeralKeyPair,
                theirEphemeralPublicKey: aliceEphemeralKeyPair.publicKey,
                isInitiator: false
            });

            const unicodeMessage = new TextEncoder().encode('Hello 世界 🌍 مرحبا');
            const [encrypted, newAliceState] = await ratchetEncrypt(aliceState, unicodeMessage);
            const [decrypted, newBobState] = await ratchetDecrypt(bobState, encrypted);

            expect(new TextDecoder().decode(decrypted)).toBe('Hello 世界 🌍 مرحبا');
        });
    });

    describe('performDHRatchet', () => {
        it('sollte einen DH Ratchet Step korrekt durchführen', async () => {
            const state = await DR_Init({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                isInitiator: true
            });

            const newBobEphemeralKeyPair = await generateKeyPair();
            const newState = await performDHRatchet(state, newBobEphemeralKeyPair.publicKey);

            expect(newState.rootKey).not.toEqual(state.rootKey);
            expect(newState.theirEphemeralPublicKey).toEqual(newBobEphemeralKeyPair.publicKey);
            expect(newState.ourEphemeralKeyPair.publicKey).not.toEqual(state.ourEphemeralKeyPair.publicKey);
            expect(newState.messageNumbers.sending).toBe(0);
            expect(newState.messageNumbers.receiving).toBe(0);
        });
    });
});

