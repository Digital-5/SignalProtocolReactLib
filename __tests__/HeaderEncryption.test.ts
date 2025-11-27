/**
 * Tests für Header Encryption (Signal Protocol Section 4)
 * Testet verschlüsselte Header und erweiterte State-Verwaltung
 */
import {
    DR_InitHE,
    ratchetEncryptHE,
    ratchetDecryptHE,
    DRStateHE,
    encryptHeader,
    decryptHeader,
    MessageHeader
} from '../src/double-ratchet';
import { generateKeyPair } from '../src/double-ratchet/CryptoUtils';

describe('Header Encryption (Section 4)', () => {
    let aliceIdentityKeyPair: any;
    let bobIdentityKeyPair: any;
    let aliceEphemeralKeyPair: any;
    let bobEphemeralKeyPair: any;
    let rootKey: Uint8Array;
    let sharedSendingHeaderKey: Uint8Array;
    let sharedNextReceivingHeaderKey: Uint8Array;

    // Optimierung: Generiere Schlüsselpaare nur einmal für alle Tests
    beforeAll(async () => {
        aliceIdentityKeyPair = await generateKeyPair();
        bobIdentityKeyPair = await generateKeyPair();
        aliceEphemeralKeyPair = await generateKeyPair();
        bobEphemeralKeyPair = await generateKeyPair();
    });

    beforeEach(() => {
        // Generiere neue Shared Secrets für jeden Test
        rootKey = crypto.getRandomValues(new Uint8Array(32));
        sharedSendingHeaderKey = crypto.getRandomValues(new Uint8Array(32));
        sharedNextReceivingHeaderKey = crypto.getRandomValues(new Uint8Array(32));
    });

    describe('Header Encryption Primitives', () => {
        it('sollte einen Header verschlüsseln und entschlüsseln können', async () => {
            const headerKey = crypto.getRandomValues(new Uint8Array(32));
            const header: MessageHeader = {
                dh: aliceEphemeralKeyPair.publicKey,
                pn: 5,
                n: 10
            };

            // Verschlüsseln
            const encryptedHeader = await encryptHeader(headerKey, header);
            expect(encryptedHeader).toBeInstanceOf(Uint8Array);
            expect(encryptedHeader.length).toBeGreaterThan(0);

            // Entschlüsseln
            const decryptedHeader = await decryptHeader(headerKey, encryptedHeader);
            expect(decryptedHeader).not.toBeNull();
            expect(decryptedHeader!.dh).toEqual(header.dh);
            expect(decryptedHeader!.pn).toBe(header.pn);
            expect(decryptedHeader!.n).toBe(header.n);
        });

        it('sollte bei falschem Header Key null zurückgeben', async () => {
            const correctKey = crypto.getRandomValues(new Uint8Array(32));
            const wrongKey = crypto.getRandomValues(new Uint8Array(32));
            const header: MessageHeader = {
                dh: aliceEphemeralKeyPair.publicKey,
                pn: 1,
                n: 2
            };

            const encryptedHeader = await encryptHeader(correctKey, header);

            // Versuch mit falschem Key
            const result = await decryptHeader(wrongKey, encryptedHeader);
            expect(result).toBeNull();
        });

        it('sollte bei null Header Key null zurückgeben', async () => {
            const header: MessageHeader = {
                dh: aliceEphemeralKeyPair.publicKey,
                pn: 0,
                n: 0
            };
            const headerKey = crypto.getRandomValues(new Uint8Array(32));
            const encryptedHeader = await encryptHeader(headerKey, header);

            // Signal Spec: "If header key hk is empty (None), returns None"
            const result = await decryptHeader(null, encryptedHeader);
            expect(result).toBeNull();
        });

        it('sollte unterschiedliche Ciphertexts für gleiche Header erzeugen (random IV)', async () => {
            const headerKey = crypto.getRandomValues(new Uint8Array(32));
            const header: MessageHeader = {
                dh: aliceEphemeralKeyPair.publicKey,
                pn: 3,
                n: 7
            };

            const encrypted1 = await encryptHeader(headerKey, header);
            const encrypted2 = await encryptHeader(headerKey, header);

            // Sollten unterschiedlich sein (random IV)
            expect(encrypted1).not.toEqual(encrypted2);

            // Aber beide sollten entschlüsselbar sein
            const decrypted1 = await decryptHeader(headerKey, encrypted1);
            const decrypted2 = await decryptHeader(headerKey, encrypted2);
            expect(decrypted1).toEqual(decrypted2);
        });
    });

    describe('DR_InitHE - Initialization', () => {
        it('sollte Alice State korrekt initialisieren', async () => {
            const aliceState = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            // Standard Double Ratchet State
            expect(aliceState.rootKey).toBeInstanceOf(Uint8Array);
            expect(aliceState.sendingChainKey).toBeInstanceOf(Uint8Array);
            expect(aliceState.messageNumbers.sending).toBe(0);
            expect(aliceState.messageNumbers.receiving).toBe(0);
            expect(aliceState.pn).toBe(0);

            // Header Encryption Keys
            expect(aliceState.sendingHeaderKey).toEqual(sharedSendingHeaderKey);
            expect(aliceState.receivingHeaderKey).toBeNull();
            expect(aliceState.nextSendingHeaderKey).toBeInstanceOf(Uint8Array);
            expect(aliceState.nextReceivingHeaderKey).toEqual(sharedNextReceivingHeaderKey);
        });

        it('sollte Bob State korrekt initialisieren', async () => {
            const bobState = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: bobIdentityKeyPair,
                theirIdentityPublicKey: aliceIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: bobEphemeralKeyPair,
                theirEphemeralPublicKey: aliceEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: false
            });

            // Bob's State ist anders als Alice
            expect(bobState.rootKey).toEqual(rootKey); // Bob behält Root Key initial
            expect(bobState.messageNumbers.sending).toBe(0);
            expect(bobState.messageNumbers.receiving).toBe(0);

            // Header Keys sind gespiegelt
            expect(bobState.nextSendingHeaderKey).toEqual(sharedNextReceivingHeaderKey);
            expect(bobState.nextReceivingHeaderKey).toEqual(sharedSendingHeaderKey);
        });

        it('sollte verschiedene States für verschiedene Shared Keys erzeugen', async () => {
            const state1 = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            const differentHeaderKey = crypto.getRandomValues(new Uint8Array(32));
            const state2 = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey: differentHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            expect(state1.sendingHeaderKey).not.toEqual(state2.sendingHeaderKey);
        });
    });

    describe('ratchetEncryptHE & ratchetDecryptHE', () => {
        it('sollte eine Nachricht mit verschlüsseltem Header verschlüsseln und entschlüsseln', async () => {
            const aliceState = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            const bobState = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: bobIdentityKeyPair,
                theirIdentityPublicKey: aliceIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: bobEphemeralKeyPair,
                theirEphemeralPublicKey: aliceEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: false
            });

            const plaintext = new TextEncoder().encode('Secret message with encrypted header!');

            // Alice verschlüsselt
            const [encryptedMessage, newAliceState] = await ratchetEncryptHE(aliceState, plaintext);

            // Header sollte verschlüsselt sein
            expect(encryptedMessage.encryptedHeader).toBeInstanceOf(Uint8Array);
            expect(encryptedMessage.ciphertext).toBeInstanceOf(Uint8Array);

            // Bob entschlüsselt
            const [decryptedMessage, _newBobState] = await ratchetDecryptHE(bobState, encryptedMessage);

            expect(new TextDecoder().decode(decryptedMessage)).toBe('Secret message with encrypted header!');
            expect(newAliceState.messageNumbers.sending).toBe(1);
        });

        it('sollte mehrere Nachrichten nacheinander verschlüsseln können', async () => {
            let aliceState = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            let bobState = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: bobIdentityKeyPair,
                theirIdentityPublicKey: aliceIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: bobEphemeralKeyPair,
                theirEphemeralPublicKey: aliceEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: false
            });

            for (let i = 0; i < 5; i++) {
                const plaintext = new TextEncoder().encode(`Message ${i}`);
                const [encrypted, newAliceState] = await ratchetEncryptHE(aliceState, plaintext);
                aliceState = newAliceState;

                const [decrypted, newBobState] = await ratchetDecryptHE(bobState, encrypted);
                bobState = newBobState;

                expect(new TextDecoder().decode(decrypted)).toBe(`Message ${i}`);
            }

            expect(aliceState.messageNumbers.sending).toBe(5);
            expect(bobState.messageNumbers.receiving).toBe(5);
        });

        it('sollte bidirektionale Kommunikation mit Header Encryption unterstützen', async () => {
            let aliceState = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            let bobState = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: bobIdentityKeyPair,
                theirIdentityPublicKey: aliceIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: bobEphemeralKeyPair,
                theirEphemeralPublicKey: aliceEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: false
            });

            // Alice -> Bob
            const [msgA1, newAliceState1] = await ratchetEncryptHE(
                aliceState,
                new TextEncoder().encode('Alice to Bob')
            );
            aliceState = newAliceState1;

            const [decA1, newBobState1] = await ratchetDecryptHE(bobState, msgA1);
            bobState = newBobState1;
            expect(new TextDecoder().decode(decA1)).toBe('Alice to Bob');

            // Bob -> Alice
            const [msgB1, newBobState2] = await ratchetEncryptHE(
                bobState,
                new TextEncoder().encode('Bob to Alice')
            );
            bobState = newBobState2;

            const [decB1, newAliceState2] = await ratchetDecryptHE(aliceState, msgB1);
            aliceState = newAliceState2;
            expect(new TextDecoder().decode(decB1)).toBe('Bob to Alice');
        });

        it('sollte mit Associated Data funktionieren', async () => {
            const aliceState = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            const bobState = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: bobIdentityKeyPair,
                theirIdentityPublicKey: aliceIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: bobEphemeralKeyPair,
                theirEphemeralPublicKey: aliceEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: false
            });

            const plaintext = new TextEncoder().encode('Message');
            const ad = new TextEncoder().encode('context-info');

            const [encrypted, _newAliceState] = await ratchetEncryptHE(aliceState, plaintext, ad);
            const [decrypted, _newBobState] = await ratchetDecryptHE(bobState, encrypted, ad);

            expect(new TextDecoder().decode(decrypted)).toBe('Message');
        });

        it('sollte bei falschem Associated Data fehlschlagen', async () => {
            const aliceState = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            const bobState = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: bobIdentityKeyPair,
                theirIdentityPublicKey: aliceIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: bobEphemeralKeyPair,
                theirEphemeralPublicKey: aliceEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: false
            });

            const plaintext = new TextEncoder().encode('Message');
            const ad1 = new TextEncoder().encode('context-1');
            const ad2 = new TextEncoder().encode('context-2');

            const [encrypted, _newAliceState] = await ratchetEncryptHE(aliceState, plaintext, ad1);

            // Versuch mit anderem AD zu entschlüsseln
            await expect(ratchetDecryptHE(bobState, encrypted, ad2)).rejects.toThrow();
        });
    });

    describe('Edge Cases', () => {
        it('sollte leere Nachrichten mit Header Encryption verarbeiten', async () => {
            const aliceState = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            const bobState = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: bobIdentityKeyPair,
                theirIdentityPublicKey: aliceIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: bobEphemeralKeyPair,
                theirEphemeralPublicKey: aliceEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: false
            });

            const emptyMessage = new Uint8Array(0);
            const [encrypted, _newAliceState] = await ratchetEncryptHE(aliceState, emptyMessage);
            const [decrypted, _newBobState] = await ratchetDecryptHE(bobState, encrypted);

            expect(decrypted.length).toBe(0);
        });

        it('sollte Unicode-Nachrichten mit Header Encryption verarbeiten', async () => {
            const aliceState = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            const bobState = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: bobIdentityKeyPair,
                theirIdentityPublicKey: aliceIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: bobEphemeralKeyPair,
                theirEphemeralPublicKey: aliceEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: false
            });

            const unicodeMessage = new TextEncoder().encode('Hello 👋 世界 🌍 مرحبا');
            const [encrypted, _newAliceState] = await ratchetEncryptHE(aliceState, unicodeMessage);
            const [decrypted, _newBobState] = await ratchetDecryptHE(bobState, encrypted);

            expect(new TextDecoder().decode(decrypted)).toBe('Hello 👋 世界 🌍 مرحبا');
        });

        it('sollte Header Keys korrekt rotieren nach mehreren Nachrichten', async () => {
            let aliceState = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            const initialSendingHeaderKey = aliceState.sendingHeaderKey;

            // Sende mehrere Nachrichten
            for (let i = 0; i < 3; i++) {
                const [_msg, newState] = await ratchetEncryptHE(
                    aliceState,
                    new TextEncoder().encode(`Message ${i}`)
                );
                aliceState = newState;
            }

            // Sending Header Key sollte sich NICHT geändert haben (nur bei DH Ratchet)
            expect(aliceState.sendingHeaderKey).toEqual(initialSendingHeaderKey);
        });
    });

    describe('Security Properties', () => {
        it('sollte unterschiedliche verschlüsselte Header für gleiche Nachrichten erzeugen', async () => {
            const aliceState = await DR_InitHE({
                rootKey,
                ourIdentityKeyPair: aliceIdentityKeyPair,
                theirIdentityPublicKey: bobIdentityKeyPair.publicKey,
                ourEphemeralKeyPair: aliceEphemeralKeyPair,
                theirEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
                sharedSendingHeaderKey,
                sharedNextReceivingHeaderKey,
                isInitiator: true
            });

            const plaintext = new TextEncoder().encode('Same message');

            const [msg1, _state1] = await ratchetEncryptHE(aliceState, plaintext);
            const [msg2, _state2] = await ratchetEncryptHE(aliceState, plaintext);

            // Header sollten unterschiedlich sein (random IV)
            expect(msg1.encryptedHeader).not.toEqual(msg2.encryptedHeader);
            // Ciphertext auch unterschiedlich
            expect(msg1.ciphertext).not.toEqual(msg2.ciphertext);
        });

        it('sollte Header nicht ohne korrekten Key entschlüsselbar sein', async () => {
            const correctKey = crypto.getRandomValues(new Uint8Array(32));
            const wrongKey = crypto.getRandomValues(new Uint8Array(32));

            const header: MessageHeader = {
                dh: aliceEphemeralKeyPair.publicKey,
                pn: 10,
                n: 20
            };

            const encrypted = await encryptHeader(correctKey, header);

            // Mit falschem Key
            const decrypted = await decryptHeader(wrongKey, encrypted);
            expect(decrypted).toBeNull();
        });
    });
});

