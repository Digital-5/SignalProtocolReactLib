/**
 * Tests für Out-of-Order Messages
 * Testet Skipped Message Keys und verschiedene Reihenfolgen
 */
import { DR_Init } from '../src/double-ratchet/DR_Init';
import { ratchetEncrypt, ratchetDecrypt } from '../src/double-ratchet/DR_Ratchet';
import { generateKeyPair } from '../src/double-ratchet/CryptoUtils';

describe('Out-of-Order Messages', () => {
    let aliceIdentityKeyPair: any;
    let bobIdentityKeyPair: any;
    let aliceEphemeralKeyPair: any;
    let bobEphemeralKeyPair: any;
    let rootKey: Uint8Array;

    beforeEach(async () => {
        aliceIdentityKeyPair = await generateKeyPair();
        bobIdentityKeyPair = await generateKeyPair();
        aliceEphemeralKeyPair = await generateKeyPair();
        bobEphemeralKeyPair = await generateKeyPair();
        rootKey = crypto.getRandomValues(new Uint8Array(32));
    });

    describe('Delayed Messages', () => {
        it('sollte eine verspätete Nachricht entschlüsseln können', async () => {
            const aliceState = await DR_Init({
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

            // Alice sendet 3 Nachrichten
            const [msg0, state1] = await ratchetEncrypt(aliceState, new TextEncoder().encode('Message 0'));
            const [msg1, state2] = await ratchetEncrypt(state1, new TextEncoder().encode('Message 1'));
            const [msg2, state3] = await ratchetEncrypt(state2, new TextEncoder().encode('Message 2'));

            // Bob empfängt: 0, 2, dann 1 (out-of-order)
            let [dec0, bobState1] = await ratchetDecrypt(bobState, msg0);
            expect(new TextDecoder().decode(dec0)).toBe('Message 0');

            // Message 2 überspringt Message 1
            let [dec2, bobState2] = await ratchetDecrypt(bobState1, msg2);
            expect(new TextDecoder().decode(dec2)).toBe('Message 2');
            expect(bobState2.skippedMessageKeys.size).toBe(1); // Message 1 wurde übersprungen

            // Jetzt kommt Message 1 an (verspätet)
            let [dec1, bobState3] = await ratchetDecrypt(bobState2, msg1);
            expect(new TextDecoder().decode(dec1)).toBe('Message 1');
            expect(bobState3.skippedMessageKeys.size).toBe(0); // Skipped Key wurde verwendet
        });

        it('sollte mehrere verspätete Nachrichten verarbeiten können', async () => {
            const aliceState = await DR_Init({
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

            // Alice sendet 5 Nachrichten
            const messages = [];
            let currentState = aliceState;
            for (let i = 0; i < 5; i++) {
                const [msg, newState] = await ratchetEncrypt(
                    currentState,
                    new TextEncoder().encode(`Message ${i}`)
                );
                messages.push(msg);
                currentState = newState;
            }

            // Bob empfängt: 0, 4, dann 1, 2, 3
            let [dec0, bobState1] = await ratchetDecrypt(bobState, messages[0]);
            expect(new TextDecoder().decode(dec0)).toBe('Message 0');

            // Message 4 überspringt 1, 2, 3
            let [dec4, bobState2] = await ratchetDecrypt(bobState1, messages[4]);
            expect(new TextDecoder().decode(dec4)).toBe('Message 4');
            expect(bobState2.skippedMessageKeys.size).toBe(3); // Messages 1, 2, 3

            // Empfange verspätete Nachrichten in beliebiger Reihenfolge
            let [dec2, bobState3] = await ratchetDecrypt(bobState2, messages[2]);
            expect(new TextDecoder().decode(dec2)).toBe('Message 2');
            expect(bobState3.skippedMessageKeys.size).toBe(2);

            let [dec1, bobState4] = await ratchetDecrypt(bobState3, messages[1]);
            expect(new TextDecoder().decode(dec1)).toBe('Message 1');
            expect(bobState4.skippedMessageKeys.size).toBe(1);

            let [dec3, bobState5] = await ratchetDecrypt(bobState4, messages[3]);
            expect(new TextDecoder().decode(dec3)).toBe('Message 3');
            expect(bobState5.skippedMessageKeys.size).toBe(0);
        });
    });

    describe('Reverse Order', () => {
        it('sollte Nachrichten in umgekehrter Reihenfolge verarbeiten können', async () => {
            const aliceState = await DR_Init({
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

            // Alice sendet 3 Nachrichten
            const [msg0, state1] = await ratchetEncrypt(aliceState, new TextEncoder().encode('Message 0'));
            const [msg1, state2] = await ratchetEncrypt(state1, new TextEncoder().encode('Message 1'));
            const [msg2, state3] = await ratchetEncrypt(state2, new TextEncoder().encode('Message 2'));

            // Bob empfängt in umgekehrter Reihenfolge: 2, 1, 0
            let [dec2, bobState1] = await ratchetDecrypt(bobState, msg2);
            expect(new TextDecoder().decode(dec2)).toBe('Message 2');
            expect(bobState1.skippedMessageKeys.size).toBe(2);

            let [dec1, bobState2] = await ratchetDecrypt(bobState1, msg1);
            expect(new TextDecoder().decode(dec1)).toBe('Message 1');
            expect(bobState2.skippedMessageKeys.size).toBe(1);

            let [dec0, bobState3] = await ratchetDecrypt(bobState2, msg0);
            expect(new TextDecoder().decode(dec0)).toBe('Message 0');
            expect(bobState3.skippedMessageKeys.size).toBe(0);
        });
    });

    describe('Random Order', () => {
        it('sollte Nachrichten in zufälliger Reihenfolge verarbeiten können', async () => {
            const aliceState = await DR_Init({
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

            // Alice sendet 10 Nachrichten
            const messages = [];
            let currentState = aliceState;
            for (let i = 0; i < 10; i++) {
                const [msg, newState] = await ratchetEncrypt(
                    currentState,
                    new TextEncoder().encode(`Message ${i}`)
                );
                messages.push(msg);
                currentState = newState;
            }

            // Bob empfängt in zufälliger Reihenfolge: 5, 2, 8, 0, 9, 3, 1, 7, 4, 6
            const order = [5, 2, 8, 0, 9, 3, 1, 7, 4, 6];
            const decrypted = [];

            for (const index of order) {
                const [dec, newBobState] = await ratchetDecrypt(bobState, messages[index]);
                bobState = newBobState;
                decrypted.push({ index, text: new TextDecoder().decode(dec) });
            }

            // Verifiziere, dass alle Nachrichten korrekt entschlüsselt wurden
            for (const { index, text } of decrypted) {
                expect(text).toBe(`Message ${index}`);
            }

            // Alle Skipped Keys sollten aufgebraucht sein
            expect(bobState.skippedMessageKeys.size).toBe(0);
        });
    });

    describe('DoS Protection', () => {
        it('sollte zu viele Skipped Keys ablehnen (DoS-Schutz)', async () => {
            const aliceState = await DR_Init({
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

            // Setze maxSkippedMessageKeys auf 10
            bobState = { ...bobState, maxSkippedMessageKeys: 10 };

            // Alice sendet Nachricht mit hoher Message Number (> 10)
            let currentState = aliceState;
            for (let i = 0; i < 20; i++) {
                const [msg, newState] = await ratchetEncrypt(
                    currentState,
                    new TextEncoder().encode(`Message ${i}`)
                );
                currentState = newState;

                // Nur die letzte Nachricht (Message 19)
                if (i === 19) {
                    // Bob versucht zu empfangen, sollte fehlschlagen
                    await expect(ratchetDecrypt(bobState, msg)).rejects.toThrow('Too many skipped messages');
                }
            }
        });
    });

    describe('Duplicate Messages', () => {
        it('sollte doppelte Nachrichten nicht entschlüsseln können', async () => {
            const aliceState = await DR_Init({
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

            // Alice sendet eine Nachricht
            const [msg0, _] = await ratchetEncrypt(aliceState, new TextEncoder().encode('Message 0'));

            // Bob empfängt die Nachricht
            let [dec0, bobState1] = await ratchetDecrypt(bobState, msg0);
            expect(new TextDecoder().decode(dec0)).toBe('Message 0');

            // Bob versucht die gleiche Nachricht nochmal zu empfangen
            // Das sollte fehlschlagen, da der Message Key nicht mehr vorhanden ist
            await expect(ratchetDecrypt(bobState1, msg0)).rejects.toThrow();
        });
    });

    describe('Mixed Scenarios', () => {
        it('sollte bidirektionale out-of-order Kommunikation unterstützen', async () => {
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

            // Alice sendet 3 Nachrichten
            const [aliceMsg0, aliceState1] = await ratchetEncrypt(aliceState, new TextEncoder().encode('Alice 0'));
            const [aliceMsg1, aliceState2] = await ratchetEncrypt(aliceState1, new TextEncoder().encode('Alice 1'));
            const [aliceMsg2, aliceState3] = await ratchetEncrypt(aliceState2, new TextEncoder().encode('Alice 2'));

            // Bob sendet 3 Nachrichten
            const [bobMsg0, bobState1] = await ratchetEncrypt(bobState, new TextEncoder().encode('Bob 0'));
            const [bobMsg1, bobState2] = await ratchetEncrypt(bobState1, new TextEncoder().encode('Bob 1'));
            const [bobMsg2, bobState3] = await ratchetEncrypt(bobState2, new TextEncoder().encode('Bob 2'));

            // Beide empfangen out-of-order
            // Bob empfängt: Alice 2, Alice 0, Alice 1
            let [decA2, bobStateA] = await ratchetDecrypt(bobState3, aliceMsg2);
            expect(new TextDecoder().decode(decA2)).toBe('Alice 2');

            let [decA0, bobStateB] = await ratchetDecrypt(bobStateA, aliceMsg0);
            expect(new TextDecoder().decode(decA0)).toBe('Alice 0');

            let [decA1, bobStateC] = await ratchetDecrypt(bobStateB, aliceMsg1);
            expect(new TextDecoder().decode(decA1)).toBe('Alice 1');

            // Alice empfängt: Bob 1, Bob 2, Bob 0
            let [decB1, aliceStateA] = await ratchetDecrypt(aliceState3, bobMsg1);
            expect(new TextDecoder().decode(decB1)).toBe('Bob 1');

            let [decB2, aliceStateB] = await ratchetDecrypt(aliceStateA, bobMsg2);
            expect(new TextDecoder().decode(decB2)).toBe('Bob 2');

            let [decB0, aliceStateC] = await ratchetDecrypt(aliceStateB, bobMsg0);
            expect(new TextDecoder().decode(decB0)).toBe('Bob 0');
        });
    });
});

