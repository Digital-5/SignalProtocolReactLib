/**
 * Tests für Double Ratchet mit Header Encryption
 * Testet die vollständige Implementierung inkl. Verschlüsselung, Entschlüsselung und Ratchet Steps
 */
import { DR_Init_HE } from '../src/double-ratchet/DR_Init_HE';
import { ratchetEncryptHE, ratchetDecryptHE } from '../src/double-ratchet/DR_Ratchet_HE';
import { generateKeyPair, type KeyPair } from '../src/double-ratchet/CryptoUtils';

/**
 * Helper: Generiert initiale Header Keys für HE
 */
function generateHeaderKeys() {
    return {
        sendingHeaderKey: crypto.getRandomValues(new Uint8Array(32)),
        nextReceivingHeaderKey: crypto.getRandomValues(new Uint8Array(32))
    };
}

describe('Double Ratchet mit Header Encryption', () => {
    let aliceRatchetKeyPair: KeyPair;
    let bobRatchetKeyPair: KeyPair;
    let rootKey: Uint8Array;

    // Optimierung: Generiere Schlüsselpaare nur einmal für alle Tests
    beforeAll(async () => {
        aliceRatchetKeyPair = await generateKeyPair();
        bobRatchetKeyPair = await generateKeyPair();
    });

    beforeEach(() => {
        rootKey = crypto.getRandomValues(new Uint8Array(32));
    });

    describe('DR_Init_HE', () => {
        it('sollte einen gültigen Double Ratchet State mit Header Encryption initialisieren', async () => {
            const headerKeys = generateHeaderKeys();

            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceRatchetKeyPair,
                theirRatchetPublicKey: bobRatchetKeyPair.publicKey,
                HeaderKey: headerKeys.sendingHeaderKey,
                nextReceivingHeaderKey: headerKeys.nextReceivingHeaderKey,
                isInitiator: true
            });

            expect(aliceState).toBeDefined();
            expect(aliceState.rootKey).toBeInstanceOf(Uint8Array);
            expect(aliceState.sendingChainKey).toBeInstanceOf(Uint8Array);
            expect(aliceState.sendingHeaderKey).toEqual(headerKeys.sendingHeaderKey);
            expect(aliceState.nextReceivingHeaderKey).toEqual(headerKeys.nextReceivingHeaderKey);
            expect(aliceState.messageNumbers.sending).toBe(0);
            expect(aliceState.messageNumbers.receiving).toBe(0);
        });

        it('sollte verschiedene States für verschiedene Eingaben erzeugen', async () => {
            const headerKeys1 = generateHeaderKeys();
            const state1 = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceRatchetKeyPair,
                theirRatchetPublicKey: bobRatchetKeyPair.publicKey,
                HeaderKey: headerKeys1.sendingHeaderKey,
                nextReceivingHeaderKey: headerKeys1.nextReceivingHeaderKey,
                isInitiator: true
            });

            const differentRootKey = crypto.getRandomValues(new Uint8Array(32));
            const headerKeys2 = generateHeaderKeys();
            const state2 = await DR_Init_HE({
                rootKey: differentRootKey,
                ourRatchetKeyPair: aliceRatchetKeyPair,
                theirRatchetPublicKey: bobRatchetKeyPair.publicKey,
                HeaderKey: headerKeys2.sendingHeaderKey,
                nextReceivingHeaderKey: headerKeys2.nextReceivingHeaderKey,
                isInitiator: true
            });

            expect(state1.rootKey).not.toEqual(state2.rootKey);
            expect(state1.sendingChainKey).not.toEqual(state2.sendingChainKey);
        });
    });

    describe('ratchetEncryptHE & ratchetDecryptHE', () => {
        it('sollte eine Nachricht mit Header Encryption verschlüsseln und entschlüsseln können', async () => {
            // Gemeinsame Header Keys für beide Parteien
            const sharedHKA = crypto.getRandomValues(new Uint8Array(32));
            const sharedNHKB = crypto.getRandomValues(new Uint8Array(32));

            // Alice initialisiert (Initiator)
            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceRatchetKeyPair,
                theirRatchetPublicKey: bobRatchetKeyPair.publicKey,
                HeaderKey: sharedHKA,
                nextReceivingHeaderKey: sharedNHKB,
                isInitiator: true
            });

            // Bob initialisiert (Responder)
            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobRatchetKeyPair,
                theirRatchetPublicKey: aliceRatchetKeyPair.publicKey,
                HeaderKey: sharedNHKB,
                nextReceivingHeaderKey: sharedHKA,
                isInitiator: false
            });

            // Alice verschlüsselt eine Nachricht
            const plaintext = new TextEncoder().encode('Hallo Bob!');
            const [encryptedMessage, newAliceState] = await ratchetEncryptHE(aliceState, plaintext);

            expect(encryptedMessage).toBeDefined();
            expect(encryptedMessage.encryptedHeader).toBeInstanceOf(Uint8Array);
            expect(encryptedMessage.ciphertext).toBeInstanceOf(Uint8Array);

            // Bob entschlüsselt die Nachricht
            const [decryptedMessage, newBobState] = await ratchetDecryptHE(bobState, encryptedMessage);

            expect(decryptedMessage).toEqual(plaintext);
            expect(new TextDecoder().decode(decryptedMessage)).toBe('Hallo Bob!');
        });

        it('sollte mehrere Nachrichten nacheinander verschlüsseln können', async () => {
            const sharedHKA = crypto.getRandomValues(new Uint8Array(32));
            const sharedNHKB = crypto.getRandomValues(new Uint8Array(32));

            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceRatchetKeyPair,
                theirRatchetPublicKey: bobRatchetKeyPair.publicKey,
                HeaderKey: sharedHKA,
                nextReceivingHeaderKey: sharedNHKB,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobRatchetKeyPair,
                theirRatchetPublicKey: aliceRatchetKeyPair.publicKey,
                HeaderKey: sharedNHKB,
                nextReceivingHeaderKey: sharedHKA,
                isInitiator: false
            });

            // Sende 3 Nachrichten von Alice zu Bob
            let currentAliceState = aliceState;
            let currentBobState = bobState;

            for (let i = 0; i < 3; i++) {
                const plaintext = new TextEncoder().encode(`Nachricht ${i + 1}`);
                const [encryptedMessage, newAliceState] = await ratchetEncryptHE(currentAliceState, plaintext);
                currentAliceState = newAliceState;

                const [decryptedMessage, newBobState] = await ratchetDecryptHE(currentBobState, encryptedMessage);
                currentBobState = newBobState;

                expect(new TextDecoder().decode(decryptedMessage)).toBe(`Nachricht ${i + 1}`);
            }
        });

        it('sollte bidirektionale Kommunikation unterstützen', async () => {
            const sharedHKA = crypto.getRandomValues(new Uint8Array(32));
            const sharedNHKB = crypto.getRandomValues(new Uint8Array(32));

            let aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceRatchetKeyPair,
                theirRatchetPublicKey: bobRatchetKeyPair.publicKey,
                HeaderKey: sharedHKA,
                nextReceivingHeaderKey: sharedNHKB,
                isInitiator: true
            });

            let bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobRatchetKeyPair,
                theirRatchetPublicKey: aliceRatchetKeyPair.publicKey,
                HeaderKey: sharedNHKB,
                nextReceivingHeaderKey: sharedHKA,
                isInitiator: false
            });

            // Alice -> Bob
            const plaintext1 = new TextEncoder().encode('Hallo Bob!');
            let [msg1, newAliceState] = await ratchetEncryptHE(aliceState, plaintext1);
            aliceState = newAliceState;

            let [decrypted1, newBobState] = await ratchetDecryptHE(bobState, msg1);
            bobState = newBobState;
            expect(new TextDecoder().decode(decrypted1)).toBe('Hallo Bob!');

            // Bob -> Alice
            const plaintext2 = new TextEncoder().encode('Hallo Alice!');
            let [msg2, newBobState2] = await ratchetEncryptHE(bobState, plaintext2);
            bobState = newBobState2;

            let [decrypted2, newAliceState2] = await ratchetDecryptHE(aliceState, msg2);
            aliceState = newAliceState2;
            expect(new TextDecoder().decode(decrypted2)).toBe('Hallo Alice!');

            // Alice -> Bob (wieder)
            const plaintext3 = new TextEncoder().encode('Wie geht es dir?');
            let [msg3, newAliceState3] = await ratchetEncryptHE(aliceState, plaintext3);
            aliceState = newAliceState3;

            let [decrypted3, newBobState3] = await ratchetDecryptHE(bobState, msg3);
            bobState = newBobState3;
            expect(new TextDecoder().decode(decrypted3)).toBe('Wie geht es dir?');
        });

        it('sollte Message Numbers korrekt inkrementieren', async () => {
            const headerKeys = generateHeaderKeys();
            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceRatchetKeyPair,
                theirRatchetPublicKey: bobRatchetKeyPair.publicKey,
                HeaderKey: headerKeys.sendingHeaderKey,
                nextReceivingHeaderKey: headerKeys.nextReceivingHeaderKey,
                isInitiator: true
            });

            let currentState = aliceState;

            for (let i = 0; i < 5; i++) {
                const [msg, newState] = await ratchetEncryptHE(currentState, new Uint8Array([i]));
                expect(newState.messageNumbers.sending).toBe(i + 1);
                currentState = newState;
            }
        });
    });

    describe('Edge Cases', () => {
        it('sollte leere Nachrichten verarbeiten können', async () => {
            const sharedHKA = crypto.getRandomValues(new Uint8Array(32));
            const sharedNHKB = crypto.getRandomValues(new Uint8Array(32));

            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceRatchetKeyPair,
                theirRatchetPublicKey: bobRatchetKeyPair.publicKey,
                HeaderKey: sharedHKA,
                nextReceivingHeaderKey: sharedNHKB,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobRatchetKeyPair,
                theirRatchetPublicKey: aliceRatchetKeyPair.publicKey,
                HeaderKey: sharedNHKB,
                nextReceivingHeaderKey: sharedHKA,
                isInitiator: false
            });

            const emptyMessage = new Uint8Array(0);
            const [encrypted, newAliceState] = await ratchetEncryptHE(aliceState, emptyMessage);
            const [decrypted, newBobState] = await ratchetDecryptHE(bobState, encrypted);

            expect(decrypted).toEqual(emptyMessage);
        });

        it('sollte sehr lange Nachrichten verarbeiten können', async () => {
            const sharedHKA = crypto.getRandomValues(new Uint8Array(32));
            const sharedNHKB = crypto.getRandomValues(new Uint8Array(32));

            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceRatchetKeyPair,
                theirRatchetPublicKey: bobRatchetKeyPair.publicKey,
                HeaderKey: sharedHKA,
                nextReceivingHeaderKey: sharedNHKB,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobRatchetKeyPair,
                theirRatchetPublicKey: aliceRatchetKeyPair.publicKey,
                HeaderKey: sharedNHKB,
                nextReceivingHeaderKey: sharedHKA,
                isInitiator: false
            });

            const longMessage = new Uint8Array(10000).fill(42);
            const [encrypted, newAliceState] = await ratchetEncryptHE(aliceState, longMessage);
            const [decrypted, newBobState] = await ratchetDecryptHE(bobState, encrypted);

            expect(decrypted).toEqual(longMessage);
        });

        it('sollte bei manipulierter Nachricht einen Fehler werfen', async () => {
            const sharedHKA = crypto.getRandomValues(new Uint8Array(32));
            const sharedNHKB = crypto.getRandomValues(new Uint8Array(32));

            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceRatchetKeyPair,
                theirRatchetPublicKey: bobRatchetKeyPair.publicKey,
                HeaderKey: sharedHKA,
                nextReceivingHeaderKey: sharedNHKB,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobRatchetKeyPair,
                theirRatchetPublicKey: aliceRatchetKeyPair.publicKey,
                HeaderKey: sharedNHKB,
                nextReceivingHeaderKey: sharedHKA,
                isInitiator: false
            });

            const plaintext = new TextEncoder().encode('Geheime Nachricht');
            const [encrypted, newAliceState] = await ratchetEncryptHE(aliceState, plaintext);

            // Manipuliere die Nachricht
            encrypted.ciphertext[0] ^= 1;

            // Entschlüsselung sollte fehlschlagen
            await expect(ratchetDecryptHE(bobState, encrypted)).rejects.toThrow();
        });

        it('sollte mit Unicode-Nachrichten funktionieren', async () => {
            const sharedHKA = crypto.getRandomValues(new Uint8Array(32));
            const sharedNHKB = crypto.getRandomValues(new Uint8Array(32));

            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceRatchetKeyPair,
                theirRatchetPublicKey: bobRatchetKeyPair.publicKey,
                HeaderKey: sharedHKA,
                nextReceivingHeaderKey: sharedNHKB,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobRatchetKeyPair,
                theirRatchetPublicKey: aliceRatchetKeyPair.publicKey,
                HeaderKey: sharedNHKB,
                nextReceivingHeaderKey: sharedHKA,
                isInitiator: false
            });

            const unicodeMessage = new TextEncoder().encode('Hello 世界 🌍 مرحبا');
            const [encrypted, newAliceState] = await ratchetEncryptHE(aliceState, unicodeMessage);
            const [decrypted, newBobState] = await ratchetDecryptHE(bobState, encrypted);

            expect(new TextDecoder().decode(decrypted)).toBe('Hello 世界 🌍 مرحبا');
        });
    });
});

