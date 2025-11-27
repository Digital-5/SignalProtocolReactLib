/**
 * Lokale Messaging Tests - Alice und Bob Kommunikation
 * Testet vollständige End-to-End Nachrichtenaustausch ohne Server
 * Simuliert realistische Messaging-Szenarien
 */
import {
    DR_Init,
    ratchetEncrypt,
    ratchetDecrypt,
    generateKeyPair,
    DRState,
    RatchetMessage
} from '../src/double-ratchet';

describe('Lokale Messaging - Alice und Bob', () => {
    /**
     * Simuliert lokale Nachrichten-Queue (anstatt Server)
     */
    class LocalMessageQueue {
        private aliceMessages: RatchetMessage[] = [];
        private bobMessages: RatchetMessage[] = [];

        // Alice sendet an Bob
        sendFromAlice(message: RatchetMessage): void {
            this.bobMessages.push(message);
        }

        // Bob sendet an Alice
        sendFromBob(message: RatchetMessage): void {
            this.aliceMessages.push(message);
        }

        // Bob empfängt Nachricht von Alice
        receiveForBob(): RatchetMessage | null {
            return this.bobMessages.shift() || null;
        }

        // Alice empfängt Nachricht von Bob
        receiveForAlice(): RatchetMessage | null {
            return this.aliceMessages.shift() || null;
        }

        // Prüfe ob Nachrichten vorhanden sind
        hasMessagesForBob(): boolean {
            return this.bobMessages.length > 0;
        }

        hasMessagesForAlice(): boolean {
            return this.aliceMessages.length > 0;
        }

        // Statistik
        getStats() {
            return {
                aliceQueueSize: this.aliceMessages.length,
                bobQueueSize: this.bobMessages.length
            };
        }
    }

    describe('Einfache Nachrichtenübertragung', () => {
        it('sollte Alice eine Nachricht an Bob senden können', async () => {
            // Setup: Generiere Schlüssel
            const aliceIdentity = await generateKeyPair();
            const bobIdentity = await generateKeyPair();
            const aliceEphemeral = await generateKeyPair();
            const bobEphemeral = await generateKeyPair();
            const sharedRootKey = crypto.getRandomValues(new Uint8Array(32));

            // Initialisiere Alice (Initiator)
            let aliceState: DRState = await DR_Init({
                rootKey: sharedRootKey,
                ourIdentityKeyPair: aliceIdentity,
                theirIdentityPublicKey: bobIdentity.publicKey,
                ourEphemeralKeyPair: aliceEphemeral,
                theirEphemeralPublicKey: bobEphemeral.publicKey,
                isInitiator: true
            });

            // Initialisiere Bob (Responder)
            let bobState: DRState = await DR_Init({
                rootKey: sharedRootKey,
                ourIdentityKeyPair: bobIdentity,
                theirIdentityPublicKey: aliceIdentity.publicKey,
                ourEphemeralKeyPair: bobEphemeral,
                theirEphemeralPublicKey: aliceEphemeral.publicKey,
                isInitiator: false
            });

            // Lokale Message Queue (statt Server)
            const messageQueue = new LocalMessageQueue();

            // Alice verschlüsselt und sendet Nachricht
            const alicePlaintext = new TextEncoder().encode('Hallo Bob! 👋');
            const [aliceEncrypted, newAliceState] = await ratchetEncrypt(aliceState, alicePlaintext);
            aliceState = newAliceState;

            // "Sende" über lokale Queue (statt Netzwerk)
            messageQueue.sendFromAlice(aliceEncrypted);

            // Bob empfängt und entschlüsselt
            const receivedMessage = messageQueue.receiveForBob();
            expect(receivedMessage).not.toBeNull();

            const [bobDecrypted, newBobState] = await ratchetDecrypt(bobState, receivedMessage!);
            bobState = newBobState;

            expect(new TextDecoder().decode(bobDecrypted)).toBe('Hallo Bob! 👋');
        });

        it('sollte bidirektionale Kommunikation unterstützen', async () => {
            // Setup
            const aliceIdentity = await generateKeyPair();
            const bobIdentity = await generateKeyPair();
            const aliceEphemeral = await generateKeyPair();
            const bobEphemeral = await generateKeyPair();
            const sharedRootKey = crypto.getRandomValues(new Uint8Array(32));

            let aliceState: DRState = await DR_Init({
                rootKey: sharedRootKey,
                ourIdentityKeyPair: aliceIdentity,
                theirIdentityPublicKey: bobIdentity.publicKey,
                ourEphemeralKeyPair: aliceEphemeral,
                theirEphemeralPublicKey: bobEphemeral.publicKey,
                isInitiator: true
            });

            let bobState: DRState = await DR_Init({
                rootKey: sharedRootKey,
                ourIdentityKeyPair: bobIdentity,
                theirIdentityPublicKey: aliceIdentity.publicKey,
                ourEphemeralKeyPair: bobEphemeral,
                theirEphemeralPublicKey: aliceEphemeral.publicKey,
                isInitiator: false
            });

            const messageQueue = new LocalMessageQueue();

            // Alice -> Bob
            const [msg1, newAliceState1] = await ratchetEncrypt(
                aliceState,
                new TextEncoder().encode('Hi Bob!')
            );
            aliceState = newAliceState1;
            messageQueue.sendFromAlice(msg1);

            const received1 = messageQueue.receiveForBob()!;
            const [decrypted1, newBobState1] = await ratchetDecrypt(bobState, received1);
            bobState = newBobState1;
            expect(new TextDecoder().decode(decrypted1)).toBe('Hi Bob!');

            // Bob -> Alice
            const [msg2, newBobState2] = await ratchetEncrypt(
                bobState,
                new TextEncoder().encode('Hi Alice!')
            );
            bobState = newBobState2;
            messageQueue.sendFromBob(msg2);

            const received2 = messageQueue.receiveForAlice()!;
            const [decrypted2, newAliceState2] = await ratchetDecrypt(aliceState, received2);
            aliceState = newAliceState2;
            expect(new TextDecoder().decode(decrypted2)).toBe('Hi Alice!');
        });
    });

    describe('Mehrere Nachrichten', () => {
        it('sollte mehrere aufeinanderfolgende Nachrichten verarbeiten', async () => {
            // Setup
            const aliceIdentity = await generateKeyPair();
            const bobIdentity = await generateKeyPair();
            const aliceEphemeral = await generateKeyPair();
            const bobEphemeral = await generateKeyPair();
            const sharedRootKey = crypto.getRandomValues(new Uint8Array(32));

            let aliceState: DRState = await DR_Init({
                rootKey: sharedRootKey,
                ourIdentityKeyPair: aliceIdentity,
                theirIdentityPublicKey: bobIdentity.publicKey,
                ourEphemeralKeyPair: aliceEphemeral,
                theirEphemeralPublicKey: bobEphemeral.publicKey,
                isInitiator: true
            });

            let bobState: DRState = await DR_Init({
                rootKey: sharedRootKey,
                ourIdentityKeyPair: bobIdentity,
                theirIdentityPublicKey: aliceIdentity.publicKey,
                ourEphemeralKeyPair: bobEphemeral,
                theirEphemeralPublicKey: aliceEphemeral.publicKey,
                isInitiator: false
            });

            const messageQueue = new LocalMessageQueue();
            const messages = [
                'Nachricht 1',
                'Nachricht 2',
                'Nachricht 3',
                'Nachricht 4',
                'Nachricht 5'
            ];

            // Alice sendet alle Nachrichten
            for (const msg of messages) {
                const [encrypted, newState] = await ratchetEncrypt(
                    aliceState,
                    new TextEncoder().encode(msg)
                );
                aliceState = newState;
                messageQueue.sendFromAlice(encrypted);
            }

            // Bob empfängt und entschlüsselt alle
            const received: string[] = [];
            while (messageQueue.hasMessagesForBob()) {
                const encryptedMsg = messageQueue.receiveForBob()!;
                const [decrypted, newState] = await ratchetDecrypt(bobState, encryptedMsg);
                bobState = newState;
                received.push(new TextDecoder().decode(decrypted));
            }

            expect(received).toEqual(messages);
        });

        it('sollte eine Konversation zwischen Alice und Bob simulieren', async () => {
            // Setup
            const aliceIdentity = await generateKeyPair();
            const bobIdentity = await generateKeyPair();
            const aliceEphemeral = await generateKeyPair();
            const bobEphemeral = await generateKeyPair();
            const sharedRootKey = crypto.getRandomValues(new Uint8Array(32));

            let aliceState: DRState = await DR_Init({
                rootKey: sharedRootKey,
                ourIdentityKeyPair: aliceIdentity,
                theirIdentityPublicKey: bobIdentity.publicKey,
                ourEphemeralKeyPair: aliceEphemeral,
                theirEphemeralPublicKey: bobEphemeral.publicKey,
                isInitiator: true
            });

            let bobState: DRState = await DR_Init({
                rootKey: sharedRootKey,
                ourIdentityKeyPair: bobIdentity,
                theirIdentityPublicKey: aliceIdentity.publicKey,
                ourEphemeralKeyPair: bobEphemeral,
                theirEphemeralPublicKey: aliceEphemeral.publicKey,
                isInitiator: false
            });

            const messageQueue = new LocalMessageQueue();
            const conversation: Array<{ sender: string; message: string }> = [];

            // Simuliere Konversation
            const exchanges = [
                { from: 'Alice', to: 'Bob', text: 'Hey Bob, wie geht es dir?' },
                { from: 'Bob', to: 'Alice', text: 'Mir geht es gut, danke! Und dir?' },
                { from: 'Alice', to: 'Bob', text: 'Auch gut! Hast du heute Zeit?' },
                { from: 'Bob', to: 'Alice', text: 'Ja, ab 15 Uhr. Treffen?' },
                { from: 'Alice', to: 'Bob', text: 'Perfekt! Bis später 👋' }
            ];

            for (const exchange of exchanges) {
                if (exchange.from === 'Alice') {
                    // Alice sendet
                    const [encrypted, newState] = await ratchetEncrypt(
                        aliceState,
                        new TextEncoder().encode(exchange.text)
                    );
                    aliceState = newState;
                    messageQueue.sendFromAlice(encrypted);

                    // Bob empfängt
                    const received = messageQueue.receiveForBob()!;
                    const [decrypted, newBobState] = await ratchetDecrypt(bobState, received);
                    bobState = newBobState;
                    conversation.push({
                        sender: 'Alice',
                        message: new TextDecoder().decode(decrypted)
                    });
                } else {
                    // Bob sendet
                    const [encrypted, newState] = await ratchetEncrypt(
                        bobState,
                        new TextEncoder().encode(exchange.text)
                    );
                    bobState = newState;
                    messageQueue.sendFromBob(encrypted);

                    // Alice empfängt
                    const received = messageQueue.receiveForAlice()!;
                    const [decrypted, newAliceState] = await ratchetDecrypt(aliceState, received);
                    aliceState = newAliceState;
                    conversation.push({
                        sender: 'Bob',
                        message: new TextDecoder().decode(decrypted)
                    });
                }
            }

            // Verifiziere Konversation
            expect(conversation.length).toBe(5);
            expect(conversation[0]).toEqual({ sender: 'Alice', message: 'Hey Bob, wie geht es dir?' });
            expect(conversation[1]).toEqual({ sender: 'Bob', message: 'Mir geht es gut, danke! Und dir?' });
            expect(conversation[4]).toEqual({ sender: 'Alice', message: 'Perfekt! Bis später 👋' });
        });
    });

    describe('Out-of-Order Nachrichten', () => {
        it('sollte Nachrichten in falscher Reihenfolge verarbeiten können', async () => {
            // Setup
            const aliceIdentity = await generateKeyPair();
            const bobIdentity = await generateKeyPair();
            const aliceEphemeral = await generateKeyPair();
            const bobEphemeral = await generateKeyPair();
            const sharedRootKey = crypto.getRandomValues(new Uint8Array(32));

            let aliceState: DRState = await DR_Init({
                rootKey: sharedRootKey,
                ourIdentityKeyPair: aliceIdentity,
                theirIdentityPublicKey: bobIdentity.publicKey,
                ourEphemeralKeyPair: aliceEphemeral,
                theirEphemeralPublicKey: bobEphemeral.publicKey,
                isInitiator: true
            });

            let bobState: DRState = await DR_Init({
                rootKey: sharedRootKey,
                ourIdentityKeyPair: bobIdentity,
                theirIdentityPublicKey: aliceIdentity.publicKey,
                ourEphemeralKeyPair: bobEphemeral,
                theirEphemeralPublicKey: aliceEphemeral.publicKey,
                isInitiator: false
            });

            // Alice sendet 3 Nachrichten
            const [msg1, state1] = await ratchetEncrypt(aliceState, new TextEncoder().encode('Message 1'));
            const [msg2, state2] = await ratchetEncrypt(state1, new TextEncoder().encode('Message 2'));
            const [msg3, state3] = await ratchetEncrypt(state2, new TextEncoder().encode('Message 3'));
            aliceState = state3;

            // Bob empfängt in falscher Reihenfolge: 3, 1, 2
            const [dec3, bobState1] = await ratchetDecrypt(bobState, msg3);
            expect(new TextDecoder().decode(dec3)).toBe('Message 3');

            const [dec1, bobState2] = await ratchetDecrypt(bobState1, msg1);
            expect(new TextDecoder().decode(dec1)).toBe('Message 1');

            const [dec2, bobState3] = await ratchetDecrypt(bobState2, msg2);
            expect(new TextDecoder().decode(dec2)).toBe('Message 2');

            bobState = bobState3;
        });
    });

    describe('Edge Cases', () => {
        it('sollte leere Nachrichten übertragen können', async () => {
            const aliceIdentity = await generateKeyPair();
            const bobIdentity = await generateKeyPair();
            const aliceEphemeral = await generateKeyPair();
            const bobEphemeral = await generateKeyPair();
            const sharedRootKey = crypto.getRandomValues(new Uint8Array(32));

            let aliceState: DRState = await DR_Init({
                rootKey: sharedRootKey,
                ourIdentityKeyPair: aliceIdentity,
                theirIdentityPublicKey: bobIdentity.publicKey,
                ourEphemeralKeyPair: aliceEphemeral,
                theirEphemeralPublicKey: bobEphemeral.publicKey,
                isInitiator: true
            });

            let bobState: DRState = await DR_Init({
                rootKey: sharedRootKey,
                ourIdentityKeyPair: bobIdentity,
                theirIdentityPublicKey: aliceIdentity.publicKey,
                ourEphemeralKeyPair: bobEphemeral,
                theirEphemeralPublicKey: aliceEphemeral.publicKey,
                isInitiator: false
            });

            const messageQueue = new LocalMessageQueue();

            // Leere Nachricht
            const [encrypted, newAliceState] = await ratchetEncrypt(aliceState, new Uint8Array(0));
            aliceState = newAliceState;
            messageQueue.sendFromAlice(encrypted);

            const received = messageQueue.receiveForBob()!;
            const [decrypted, newBobState] = await ratchetDecrypt(bobState, received);
            bobState = newBobState;

            expect(decrypted.length).toBe(0);
        });

        it('sollte sehr lange Nachrichten übertragen können', async () => {
            const aliceIdentity = await generateKeyPair();
            const bobIdentity = await generateKeyPair();
            const aliceEphemeral = await generateKeyPair();
            const bobEphemeral = await generateKeyPair();
            const sharedRootKey = crypto.getRandomValues(new Uint8Array(32));

            let aliceState: DRState = await DR_Init({
                rootKey: sharedRootKey,
                ourIdentityKeyPair: aliceIdentity,
                theirIdentityPublicKey: bobIdentity.publicKey,
                ourEphemeralKeyPair: aliceEphemeral,
                theirEphemeralPublicKey: bobEphemeral.publicKey,
                isInitiator: true
            });

            let bobState: DRState = await DR_Init({
                rootKey: sharedRootKey,
                ourIdentityKeyPair: bobIdentity,
                theirIdentityPublicKey: aliceIdentity.publicKey,
                ourEphemeralKeyPair: bobEphemeral,
                theirEphemeralPublicKey: aliceEphemeral.publicKey,
                isInitiator: false
            });

            const messageQueue = new LocalMessageQueue();

            // Lange Nachricht (10KB)
            const longText = 'A'.repeat(10000);
            const [encrypted, newAliceState] = await ratchetEncrypt(
                aliceState,
                new TextEncoder().encode(longText)
            );
            aliceState = newAliceState;
            messageQueue.sendFromAlice(encrypted);

            const received = messageQueue.receiveForBob()!;
            const [decrypted, newBobState] = await ratchetDecrypt(bobState, received);
            bobState = newBobState;

            expect(new TextDecoder().decode(decrypted)).toBe(longText);
        });

        it('sollte Unicode-Zeichen korrekt übertragen', async () => {
            const aliceIdentity = await generateKeyPair();
            const bobIdentity = await generateKeyPair();
            const aliceEphemeral = await generateKeyPair();
            const bobEphemeral = await generateKeyPair();
            const sharedRootKey = crypto.getRandomValues(new Uint8Array(32));

            let aliceState: DRState = await DR_Init({
                rootKey: sharedRootKey,
                ourIdentityKeyPair: aliceIdentity,
                theirIdentityPublicKey: bobIdentity.publicKey,
                ourEphemeralKeyPair: aliceEphemeral,
                theirEphemeralPublicKey: bobEphemeral.publicKey,
                isInitiator: true
            });

            let bobState: DRState = await DR_Init({
                rootKey: sharedRootKey,
                ourIdentityKeyPair: bobIdentity,
                theirIdentityPublicKey: aliceIdentity.publicKey,
                ourEphemeralKeyPair: bobEphemeral,
                theirEphemeralPublicKey: aliceEphemeral.publicKey,
                isInitiator: false
            });

            const messageQueue = new LocalMessageQueue();

            const unicodeText = '👋 Hello 世界 مرحبا Привет 🌍';
            const [encrypted, newAliceState] = await ratchetEncrypt(
                aliceState,
                new TextEncoder().encode(unicodeText)
            );
            aliceState = newAliceState;
            messageQueue.sendFromAlice(encrypted);

            const received = messageQueue.receiveForBob()!;
            const [decrypted, newBobState] = await ratchetDecrypt(bobState, received);
            bobState = newBobState;

            expect(new TextDecoder().decode(decrypted)).toBe(unicodeText);
        });
    });

    describe('Performance & Statistiken', () => {
        it('sollte 100 Nachrichten schnell verarbeiten können', async () => {
            const aliceIdentity = await generateKeyPair();
            const bobIdentity = await generateKeyPair();
            const aliceEphemeral = await generateKeyPair();
            const bobEphemeral = await generateKeyPair();
            const sharedRootKey = crypto.getRandomValues(new Uint8Array(32));

            let aliceState: DRState = await DR_Init({
                rootKey: sharedRootKey,
                ourIdentityKeyPair: aliceIdentity,
                theirIdentityPublicKey: bobIdentity.publicKey,
                ourEphemeralKeyPair: aliceEphemeral,
                theirEphemeralPublicKey: bobEphemeral.publicKey,
                isInitiator: true
            });

            let bobState: DRState = await DR_Init({
                rootKey: sharedRootKey,
                ourIdentityKeyPair: bobIdentity,
                theirIdentityPublicKey: aliceIdentity.publicKey,
                ourEphemeralKeyPair: bobEphemeral,
                theirEphemeralPublicKey: aliceEphemeral.publicKey,
                isInitiator: false
            });

            const messageQueue = new LocalMessageQueue();
            const startTime = Date.now();

            // Alice sendet 100 Nachrichten
            for (let i = 0; i < 100; i++) {
                const [encrypted, newState] = await ratchetEncrypt(
                    aliceState,
                    new TextEncoder().encode(`Message ${i}`)
                );
                aliceState = newState;
                messageQueue.sendFromAlice(encrypted);
            }

            // Bob empfängt alle
            let received = 0;
            while (messageQueue.hasMessagesForBob()) {
                const msg = messageQueue.receiveForBob()!;
                const [decrypted, newState] = await ratchetDecrypt(bobState, msg);
                bobState = newState;
                received++;
            }

            const endTime = Date.now();
            const duration = endTime - startTime;

            expect(received).toBe(100);
            expect(duration).toBeLessThan(5000); // Sollte unter 5 Sekunden dauern
        });
    });
});

