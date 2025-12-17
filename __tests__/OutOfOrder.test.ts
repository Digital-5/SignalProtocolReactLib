/**
 * Tests für Out-of-Order Messages mit Header Encryption
 * Testet Skipped Message Keys und verschiedene Reihenfolgen
 */
import { DR_Init_HE } from '../src/double-ratchet/DR_Init_HE';
import { ratchetEncryptHE, ratchetDecryptHE } from '../src/double-ratchet/DR_Ratchet_HE';
import { generateKeyPair } from '../src/double-ratchet/CryptoUtils';

describe('Out-of-Order Messages mit Header Encryption', () => {
    let aliceRatchetKeyPair: any;
    let bobRatchetKeyPair: any;
    let rootKey: Uint8Array;
    let sharedHKA: Uint8Array;
    let sharedNHKB: Uint8Array;

    // Optimierung: Generiere Schlüsselpaare nur einmal für alle Tests
    beforeAll(async () => {
        aliceRatchetKeyPair = await generateKeyPair();
        bobRatchetKeyPair = await generateKeyPair();
    });

    beforeEach(() => {
        // Nur Root Key und Header Keys neu generieren (schnell)
        rootKey = crypto.getRandomValues(new Uint8Array(32));
        sharedHKA = crypto.getRandomValues(new Uint8Array(32));
        sharedNHKB = crypto.getRandomValues(new Uint8Array(32));
    });

    describe('Delayed Messages', () => {
        it('sollte eine verspätete Nachricht entschlüsseln können', async () => {
            const aliceState = await DR_Init_HE({
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

            // Alice sendet 3 Nachrichten
            const [msg0, state1] = await ratchetEncryptHE(aliceState, new TextEncoder().encode('Message 0'));
            const [msg1, state2] = await ratchetEncryptHE(state1, new TextEncoder().encode('Message 1'));
            const [msg2, state3] = await ratchetEncryptHE(state2, new TextEncoder().encode('Message 2'));

            // Bob empfängt nur msg0 und msg2 (msg1 verspätet)
            const [decrypted0, bobState1] = await ratchetDecryptHE(bobState, msg0);
            expect(new TextDecoder().decode(decrypted0)).toBe('Message 0');

            // msg1 wird übersprungen, msg2 wird empfangen
            const [decrypted2, bobState2] = await ratchetDecryptHE(bobState1, msg2);
            expect(new TextDecoder().decode(decrypted2)).toBe('Message 2');

            // msg1 kommt verspätet an
            const [decrypted1, bobState3] = await ratchetDecryptHE(bobState2, msg1);
            expect(new TextDecoder().decode(decrypted1)).toBe('Message 1');

            // Prüfe, dass der skipped message key aus dem State entfernt wurde
            expect(bobState3.skippedMessageKeys.size).toBe(0);
        });

        it('sollte mehrere verspätete Nachrichten entschlüsseln können', async () => {
            const aliceState = await DR_Init_HE({
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

            // Alice sendet 5 Nachrichten
            let currentAliceState = aliceState;
            const messages = [];
            for (let i = 0; i < 5; i++) {
                const [msg, newState] = await ratchetEncryptHE(
                    currentAliceState,
                    new TextEncoder().encode(`Message ${i}`)
                );
                messages.push(msg);
                currentAliceState = newState;
            }

            // Bob empfängt nur msg0 und msg4 (msg1, msg2, msg3 verspätet)
            let [decrypted0, bobState1] = await ratchetDecryptHE(bobState, messages[0]);
            expect(new TextDecoder().decode(decrypted0)).toBe('Message 0');

            let [decrypted4, bobState2] = await ratchetDecryptHE(bobState1, messages[4]);
            expect(new TextDecoder().decode(decrypted4)).toBe('Message 4');

            // Verspätete Nachrichten kommen in umgekehrter Reihenfolge an
            let [decrypted3, bobState3] = await ratchetDecryptHE(bobState2, messages[3]);
            expect(new TextDecoder().decode(decrypted3)).toBe('Message 3');

            let [decrypted1, bobState4] = await ratchetDecryptHE(bobState3, messages[1]);
            expect(new TextDecoder().decode(decrypted1)).toBe('Message 1');

            let [decrypted2, bobState5] = await ratchetDecryptHE(bobState4, messages[2]);
            expect(new TextDecoder().decode(decrypted2)).toBe('Message 2');

            // Alle skipped message keys sollten jetzt entfernt sein
            expect(bobState5.skippedMessageKeys.size).toBe(0);
        });
    });

    describe('Out-of-Order in Bidirectional Communication', () => {
        it('sollte out-of-order Nachrichten in beide Richtungen verarbeiten', async () => {
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

            // Alice sendet 3 Nachrichten
            const [aliceMsg0, aliceState1] = await ratchetEncryptHE(aliceState, new TextEncoder().encode('Alice-0'));
            const [aliceMsg1, aliceState2] = await ratchetEncryptHE(aliceState1, new TextEncoder().encode('Alice-1'));
            const [aliceMsg2, aliceState3] = await ratchetEncryptHE(aliceState2, new TextEncoder().encode('Alice-2'));
            aliceState = aliceState3;

            // Bob empfängt msg0 und msg2 (msg1 verspätet)
            let [decrypted0, bobState1] = await ratchetDecryptHE(bobState, aliceMsg0);
            expect(new TextDecoder().decode(decrypted0)).toBe('Alice-0');

            let [decrypted2, bobState2] = await ratchetDecryptHE(bobState1, aliceMsg2);
            expect(new TextDecoder().decode(decrypted2)).toBe('Alice-2');
            bobState = bobState2;

            // Bob antwortet
            const [bobMsg0, bobState3] = await ratchetEncryptHE(bobState, new TextEncoder().encode('Bob-0'));
            bobState = bobState3;

            // Alice empfängt Bobs Antwort
            let [decryptedBob0, aliceState4] = await ratchetDecryptHE(aliceState, bobMsg0);
            expect(new TextDecoder().decode(decryptedBob0)).toBe('Bob-0');
            aliceState = aliceState4;

            // Verspätete Nachricht von Alice kommt an
            let [decrypted1, bobState4] = await ratchetDecryptHE(bobState, aliceMsg1);
            expect(new TextDecoder().decode(decrypted1)).toBe('Alice-1');
        });
    });

    describe('Skipped Message Keys Management', () => {
        it('sollte skipped message keys korrekt speichern und abrufen', async () => {
            const aliceState = await DR_Init_HE({
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

            // Alice sendet 10 Nachrichten
            let currentAliceState = aliceState;
            const messages = [];
            for (let i = 0; i < 10; i++) {
                const [msg, newState] = await ratchetEncryptHE(
                    currentAliceState,
                    new TextEncoder().encode(`Message ${i}`)
                );
                messages.push(msg);
                currentAliceState = newState;
            }

            // Bob empfängt nur die erste und letzte Nachricht
            let [decrypted0, bobState1] = await ratchetDecryptHE(bobState, messages[0]);
            expect(new TextDecoder().decode(decrypted0)).toBe('Message 0');

            let [decrypted9, bobState2] = await ratchetDecryptHE(bobState1, messages[9]);
            expect(new TextDecoder().decode(decrypted9)).toBe('Message 9');

            // 8 Nachrichten wurden übersprungen, also sollten 8 skipped keys gespeichert sein
            expect(bobState2.skippedMessageKeys.size).toBe(8);

            // Empfange alle übersprungenen Nachrichten
            let currentBobState = bobState2;
            for (let i = 1; i < 9; i++) {
                const [decrypted, newState] = await ratchetDecryptHE(currentBobState, messages[i]);
                expect(new TextDecoder().decode(decrypted)).toBe(`Message ${i}`);
                currentBobState = newState;
            }

            // Alle skipped keys sollten jetzt entfernt sein
            expect(currentBobState.skippedMessageKeys.size).toBe(0);
        });

        it('sollte sehr viele skipped message keys verarbeiten können', async () => {
            const aliceState = await DR_Init_HE({
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

            // Alice sendet 50 Nachrichten
            let currentAliceState = aliceState;
            const messages = [];
            for (let i = 0; i < 50; i++) {
                const [msg, newState] = await ratchetEncryptHE(
                    currentAliceState,
                    new TextEncoder().encode(`Message ${i}`)
                );
                messages.push(msg);
                currentAliceState = newState;
            }

            // Bob empfängt nur die erste und letzte Nachricht
            let [decrypted0, bobState1] = await ratchetDecryptHE(bobState, messages[0]);
            let [decrypted49, bobState2] = await ratchetDecryptHE(bobState1, messages[49]);

            // 48 Nachrichten wurden übersprungen
            expect(bobState2.skippedMessageKeys.size).toBe(48);

            // Empfange einige zufällige übersprungene Nachrichten
            let currentBobState = bobState2;
            const indicesToReceive = [5, 10, 20, 25, 30, 40];
            for (const i of indicesToReceive) {
                const [decrypted, newState] = await ratchetDecryptHE(currentBobState, messages[i]);
                expect(new TextDecoder().decode(decrypted)).toBe(`Message ${i}`);
                currentBobState = newState;
            }

            // Skipped keys sollten entsprechend reduziert sein
            expect(currentBobState.skippedMessageKeys.size).toBe(48 - indicesToReceive.length);
        });
    });

    describe('Edge Cases', () => {
        it('sollte duplizierte Nachrichten erkennen und ablehnen', async () => {
            const aliceState = await DR_Init_HE({
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

            // Alice sendet eine Nachricht
            const [msg, newAliceState] = await ratchetEncryptHE(aliceState, new TextEncoder().encode('Test'));

            // Bob empfängt die Nachricht
            let [decrypted, bobState1] = await ratchetDecryptHE(bobState, msg);
            expect(new TextDecoder().decode(decrypted)).toBe('Test');

            // Versuch, die gleiche Nachricht nochmal zu entschlüsseln sollte fehlschlagen
            await expect(ratchetDecryptHE(bobState1, msg)).rejects.toThrow();
        });

        it('sollte mit sehr langen Verzögerungen umgehen können', async () => {
            const aliceState = await DR_Init_HE({
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

            // Alice sendet 100 Nachrichten
            let currentAliceState = aliceState;
            const messages = [];
            for (let i = 0; i < 100; i++) {
                const [msg, newState] = await ratchetEncryptHE(
                    currentAliceState,
                    new TextEncoder().encode(`Message ${i}`)
                );
                messages.push(msg);
                currentAliceState = newState;
            }

            // Bob empfängt nur msg0, msg99, und dann msg50 (sehr verzögert)
            let [decrypted0, bobState1] = await ratchetDecryptHE(bobState, messages[0]);
            expect(new TextDecoder().decode(decrypted0)).toBe('Message 0');

            let [decrypted99, bobState2] = await ratchetDecryptHE(bobState1, messages[99]);
            expect(new TextDecoder().decode(decrypted99)).toBe('Message 99');

            let [decrypted50, bobState3] = await ratchetDecryptHE(bobState2, messages[50]);
            expect(new TextDecoder().decode(decrypted50)).toBe('Message 50');
        });

        it('sollte out-of-order Nachrichten nach DH Ratchet Step verarbeiten', async () => {
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

            // Alice sendet 3 Nachrichten
            const [aliceMsg0, aliceState1] = await ratchetEncryptHE(aliceState, new TextEncoder().encode('Alice-0'));
            const [aliceMsg1, aliceState2] = await ratchetEncryptHE(aliceState1, new TextEncoder().encode('Alice-1'));
            const [aliceMsg2, aliceState3] = await ratchetEncryptHE(aliceState2, new TextEncoder().encode('Alice-2'));
            aliceState = aliceState3;

            // Bob empfängt msg0
            let [decrypted0, bobState1] = await ratchetDecryptHE(bobState, aliceMsg0);
            expect(new TextDecoder().decode(decrypted0)).toBe('Alice-0');

            // Bob antwortet (DH Ratchet Step)
            const [bobMsg0, bobState2] = await ratchetEncryptHE(bobState1, new TextEncoder().encode('Bob-0'));
            bobState = bobState2;

            // Alice empfängt
            let [decryptedBob0, aliceState4] = await ratchetDecryptHE(aliceState, bobMsg0);
            aliceState = aliceState4;

            // Bob empfängt verspätete Nachrichten aus vorherigem Ratchet
            let [decrypted2, bobState3] = await ratchetDecryptHE(bobState, aliceMsg2);
            expect(new TextDecoder().decode(decrypted2)).toBe('Alice-2');

            let [decrypted1, bobState4] = await ratchetDecryptHE(bobState3, aliceMsg1);
            expect(new TextDecoder().decode(decrypted1)).toBe('Alice-1');
        });
    });

    describe('Performance', () => {
        it('sollte viele out-of-order Nachrichten effizient verarbeiten', async () => {
            const aliceState = await DR_Init_HE({
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

            const startTime = performance.now();

            // Alice sendet 200 Nachrichten
            let currentAliceState = aliceState;
            const messages = [];
            for (let i = 0; i < 200; i++) {
                const [msg, newState] = await ratchetEncryptHE(
                    currentAliceState,
                    new TextEncoder().encode(`Message ${i}`)
                );
                messages.push(msg);
                currentAliceState = newState;
            }

            // Bob empfängt alle Nachrichten in zufälliger Reihenfolge
            const shuffledIndices = Array.from({ length: 200 }, (_, i) => i)
                .sort(() => Math.random() - 0.5);

            let currentBobState = bobState;
            for (const i of shuffledIndices) {
                const [decrypted, newState] = await ratchetDecryptHE(currentBobState, messages[i]);
                expect(new TextDecoder().decode(decrypted)).toBe(`Message ${i}`);
                currentBobState = newState;
            }

            const endTime = performance.now();
            const duration = endTime - startTime;

            // Performance Check: sollte unter 2 Sekunden sein
            expect(duration).toBeLessThan(2000);

            console.log(`200 out-of-order Nachrichten in ${duration.toFixed(2)}ms verarbeitet`);
        });
    });
});

