/**
 * Lokale Messaging Tests mit Header Encryption - Alice und Bob Kommunikation
 * Testet vollständige End-to-End Nachrichtenaustausch ohne Server
 * Simuliert realistische Messaging-Szenarien
 */
import { DR_Init_HE } from '../src/double-ratchet/DR_Init_HE';
import { ratchetEncryptHE, ratchetDecryptHE } from '../src/double-ratchet/DR_Ratchet_HE';
import { generateKeyPair } from '../src/double-ratchet/CryptoUtils';
import { DRState } from '../src/double-ratchet/DR_Interfaces';
import { RatchetMessageHE } from '../src/double-ratchet/DR_Ratchet_HE';

describe('Lokale Messaging mit Header Encryption - Alice und Bob', () => {
    /**
     * Simuliert lokale Nachrichten-Queue (anstatt Server)
     */
    class LocalMessageQueue {
        private aliceMessages: RatchetMessageHE[] = [];
        private bobMessages: RatchetMessageHE[] = [];

        // Alice sendet an Bob
        sendFromAlice(message: RatchetMessageHE): void {
            this.bobMessages.push(message);
        }

        // Bob sendet an Alice
        sendFromBob(message: RatchetMessageHE): void {
            this.aliceMessages.push(message);
        }

        // Bob empfängt Nachricht von Alice
        receiveForBob(): RatchetMessageHE | null {
            return this.bobMessages.shift() || null;
        }

        // Alice empfängt Nachricht von Bob
        receiveForAlice(): RatchetMessageHE | null {
            return this.aliceMessages.shift() || null;
        }

        // Prüfe ob Nachrichten vorhanden sind
        hasMessagesForBob(): boolean {
            return this.bobMessages.length > 0;
        }

        hasMessagesForAlice(): boolean {
            return this.aliceMessages.length > 0;
        }

        // Statistiken
        getStats() {
            return {
                forAlice: this.aliceMessages.length,
                forBob: this.bobMessages.length
            };
        }
    }

    /**
     * Simuliert eine vollständige Session zwischen Alice und Bob
     */
    class MessagingSession {
        private aliceState: DRState;
        private bobState: DRState;
        private messageQueue: LocalMessageQueue;

        constructor(aliceState: DRState, bobState: DRState) {
            this.aliceState = aliceState;
            this.bobState = bobState;
            this.messageQueue = new LocalMessageQueue();
        }

        async aliceSends(message: string): Promise<void> {
            const plaintext = new TextEncoder().encode(message);
            const [encrypted, newState] = await ratchetEncryptHE(this.aliceState, plaintext);
            this.aliceState = newState;
            this.messageQueue.sendFromAlice(encrypted);
        }

        async bobSends(message: string): Promise<void> {
            const plaintext = new TextEncoder().encode(message);
            const [encrypted, newState] = await ratchetEncryptHE(this.bobState, plaintext);
            this.bobState = newState;
            this.messageQueue.sendFromBob(encrypted);
        }

        async bobReceives(): Promise<string | null> {
            const encrypted = this.messageQueue.receiveForBob();
            if (!encrypted) return null;

            const [decrypted, newState] = await ratchetDecryptHE(this.bobState, encrypted);
            this.bobState = newState;
            return new TextDecoder().decode(decrypted);
        }

        async aliceReceives(): Promise<string | null> {
            const encrypted = this.messageQueue.receiveForAlice();
            if (!encrypted) return null;

            const [decrypted, newState] = await ratchetDecryptHE(this.aliceState, encrypted);
            this.aliceState = newState;
            return new TextDecoder().decode(decrypted);
        }

        hasMessagesForBob(): boolean {
            return this.messageQueue.hasMessagesForBob();
        }

        hasMessagesForAlice(): boolean {
            return this.messageQueue.hasMessagesForAlice();
        }

        getQueueStats() {
            return this.messageQueue.getStats();
        }
    }

    describe('Basis-Kommunikation', () => {
        it('sollte eine einfache Nachricht von Alice zu Bob übertragen', async () => {
            // Setup
            const rootKey = crypto.getRandomValues(new Uint8Array(32));
            const aliceKeyPair = await generateKeyPair();
            const bobKeyPair = await generateKeyPair();
            const sharedHKA = crypto.getRandomValues(new Uint8Array(32));
            const sharedNHKB = crypto.getRandomValues(new Uint8Array(32));

            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceKeyPair,
                theirRatchetPublicKey: bobKeyPair.publicKey,
                HeaderKey: sharedHKA,
                nextReceivingHeaderKey: sharedNHKB,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobKeyPair,
                theirRatchetPublicKey: aliceKeyPair.publicKey,
                HeaderKey: sharedNHKB,
                nextReceivingHeaderKey: sharedHKA,
                isInitiator: false
            });

            const session = new MessagingSession(aliceState, bobState);

            // Alice sendet
            await session.aliceSends('Hallo Bob!');
            expect(session.hasMessagesForBob()).toBe(true);

            // Bob empfängt
            const received = await session.bobReceives();
            expect(received).toBe('Hallo Bob!');
            expect(session.hasMessagesForBob()).toBe(false);
        });

        it('sollte eine Nachricht von Bob zu Alice übertragen', async () => {
            const rootKey = crypto.getRandomValues(new Uint8Array(32));
            const aliceKeyPair = await generateKeyPair();
            const bobKeyPair = await generateKeyPair();
            const sharedHKA = crypto.getRandomValues(new Uint8Array(32));
            const sharedNHKB = crypto.getRandomValues(new Uint8Array(32));

            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceKeyPair,
                theirRatchetPublicKey: bobKeyPair.publicKey,
                HeaderKey: sharedHKA,
                nextReceivingHeaderKey: sharedNHKB,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobKeyPair,
                theirRatchetPublicKey: aliceKeyPair.publicKey,
                HeaderKey: sharedNHKB,
                nextReceivingHeaderKey: sharedHKA,
                isInitiator: false
            });

            const session = new MessagingSession(aliceState, bobState);

            // Bob sendet (nachdem Alice initiiert hat)
            await session.aliceSends('Hi Bob');
            await session.bobReceives();

            await session.bobSends('Hallo Alice!');
            expect(session.hasMessagesForAlice()).toBe(true);

            // Alice empfängt
            const received = await session.aliceReceives();
            expect(received).toBe('Hallo Alice!');
        });

        it('sollte bidirektionale Kommunikation unterstützen', async () => {
            const rootKey = crypto.getRandomValues(new Uint8Array(32));
            const aliceKeyPair = await generateKeyPair();
            const bobKeyPair = await generateKeyPair();
            const sharedHKA = crypto.getRandomValues(new Uint8Array(32));
            const sharedNHKB = crypto.getRandomValues(new Uint8Array(32));

            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceKeyPair,
                theirRatchetPublicKey: bobKeyPair.publicKey,
                HeaderKey: sharedHKA,
                nextReceivingHeaderKey: sharedNHKB,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobKeyPair,
                theirRatchetPublicKey: aliceKeyPair.publicKey,
                HeaderKey: sharedNHKB,
                nextReceivingHeaderKey: sharedHKA,
                isInitiator: false
            });

            const session = new MessagingSession(aliceState, bobState);

            // Alice -> Bob
            await session.aliceSends('Hallo Bob!');
            expect(await session.bobReceives()).toBe('Hallo Bob!');

            // Bob -> Alice
            await session.bobSends('Hallo Alice!');
            expect(await session.aliceReceives()).toBe('Hallo Alice!');

            // Alice -> Bob
            await session.aliceSends('Wie geht es dir?');
            expect(await session.bobReceives()).toBe('Wie geht es dir?');

            // Bob -> Alice
            await session.bobSends('Gut, danke!');
            expect(await session.aliceReceives()).toBe('Gut, danke!');
        });
    });

    describe('Multiple Nachrichten', () => {
        it('sollte mehrere Nachrichten hintereinander von Alice senden können', async () => {
            const rootKey = crypto.getRandomValues(new Uint8Array(32));
            const aliceKeyPair = await generateKeyPair();
            const bobKeyPair = await generateKeyPair();
            const sharedHKA = crypto.getRandomValues(new Uint8Array(32));
            const sharedNHKB = crypto.getRandomValues(new Uint8Array(32));

            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceKeyPair,
                theirRatchetPublicKey: bobKeyPair.publicKey,
                HeaderKey: sharedHKA,
                nextReceivingHeaderKey: sharedNHKB,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobKeyPair,
                theirRatchetPublicKey: aliceKeyPair.publicKey,
                HeaderKey: sharedNHKB,
                nextReceivingHeaderKey: sharedHKA,
                isInitiator: false
            });

            const session = new MessagingSession(aliceState, bobState);

            // Alice sendet 5 Nachrichten
            const messages = ['Msg1', 'Msg2', 'Msg3', 'Msg4', 'Msg5'];
            for (const msg of messages) {
                await session.aliceSends(msg);
            }

            // Bob empfängt alle 5 Nachrichten in Reihenfolge
            for (const expectedMsg of messages) {
                const received = await session.bobReceives();
                expect(received).toBe(expectedMsg);
            }

            expect(session.hasMessagesForBob()).toBe(false);
        });

        it('sollte 100 Nachrichten in beide Richtungen senden können', async () => {
            const rootKey = crypto.getRandomValues(new Uint8Array(32));
            const aliceKeyPair = await generateKeyPair();
            const bobKeyPair = await generateKeyPair();
            const sharedHKA = crypto.getRandomValues(new Uint8Array(32));
            const sharedNHKB = crypto.getRandomValues(new Uint8Array(32));

            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceKeyPair,
                theirRatchetPublicKey: bobKeyPair.publicKey,
                HeaderKey: sharedHKA,
                nextReceivingHeaderKey: sharedNHKB,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobKeyPair,
                theirRatchetPublicKey: aliceKeyPair.publicKey,
                HeaderKey: sharedNHKB,
                nextReceivingHeaderKey: sharedHKA,
                isInitiator: false
            });

            const session = new MessagingSession(aliceState, bobState);

            // Wechselnde Nachrichten
            for (let i = 0; i < 100; i++) {
                if (i % 2 === 0) {
                    await session.aliceSends(`Alice-${i}`);
                    expect(await session.bobReceives()).toBe(`Alice-${i}`);
                } else {
                    await session.bobSends(`Bob-${i}`);
                    expect(await session.aliceReceives()).toBe(`Bob-${i}`);
                }
            }
        });
    });

    describe('Realistische Szenarien', () => {
        it('sollte eine vollständige Konversation simulieren können', async () => {
            const rootKey = crypto.getRandomValues(new Uint8Array(32));
            const aliceKeyPair = await generateKeyPair();
            const bobKeyPair = await generateKeyPair();
            const sharedHKA = crypto.getRandomValues(new Uint8Array(32));
            const sharedNHKB = crypto.getRandomValues(new Uint8Array(32));

            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceKeyPair,
                theirRatchetPublicKey: bobKeyPair.publicKey,
                HeaderKey: sharedHKA,
                nextReceivingHeaderKey: sharedNHKB,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobKeyPair,
                theirRatchetPublicKey: aliceKeyPair.publicKey,
                HeaderKey: sharedNHKB,
                nextReceivingHeaderKey: sharedHKA,
                isInitiator: false
            });

            const session = new MessagingSession(aliceState, bobState);

            // Konversation
            await session.aliceSends('Hey Bob, bist du da?');
            expect(await session.bobReceives()).toBe('Hey Bob, bist du da?');

            await session.bobSends('Ja, hallo Alice!');
            expect(await session.aliceReceives()).toBe('Ja, hallo Alice!');

            await session.aliceSends('Wollen wir uns später treffen?');
            expect(await session.bobReceives()).toBe('Wollen wir uns später treffen?');

            await session.bobSends('Gerne! Um 18 Uhr?');
            expect(await session.aliceReceives()).toBe('Gerne! Um 18 Uhr?');

            await session.aliceSends('Perfekt, bis dann!');
            expect(await session.bobReceives()).toBe('Perfekt, bis dann!');
        });

        it('sollte lange Nachrichten unterstützen', async () => {
            const rootKey = crypto.getRandomValues(new Uint8Array(32));
            const aliceKeyPair = await generateKeyPair();
            const bobKeyPair = await generateKeyPair();
            const sharedHKA = crypto.getRandomValues(new Uint8Array(32));
            const sharedNHKB = crypto.getRandomValues(new Uint8Array(32));

            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceKeyPair,
                theirRatchetPublicKey: bobKeyPair.publicKey,
                HeaderKey: sharedHKA,
                nextReceivingHeaderKey: sharedNHKB,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobKeyPair,
                theirRatchetPublicKey: aliceKeyPair.publicKey,
                HeaderKey: sharedNHKB,
                nextReceivingHeaderKey: sharedHKA,
                isInitiator: false
            });

            const session = new MessagingSession(aliceState, bobState);

            // Sehr lange Nachricht
            const longMessage = 'A'.repeat(10000);
            await session.aliceSends(longMessage);
            const received = await session.bobReceives();
            expect(received).toBe(longMessage);
            expect(received?.length).toBe(10000);
        });

        it('sollte Unicode und Emojis unterstützen', async () => {
            const rootKey = crypto.getRandomValues(new Uint8Array(32));
            const aliceKeyPair = await generateKeyPair();
            const bobKeyPair = await generateKeyPair();
            const sharedHKA = crypto.getRandomValues(new Uint8Array(32));
            const sharedNHKB = crypto.getRandomValues(new Uint8Array(32));

            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceKeyPair,
                theirRatchetPublicKey: bobKeyPair.publicKey,
                HeaderKey: sharedHKA,
                nextReceivingHeaderKey: sharedNHKB,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobKeyPair,
                theirRatchetPublicKey: aliceKeyPair.publicKey,
                HeaderKey: sharedNHKB,
                nextReceivingHeaderKey: sharedHKA,
                isInitiator: false
            });

            const session = new MessagingSession(aliceState, bobState);

            const unicodeMessage = 'Hello 世界 🌍 مرحبا 👋';
            await session.aliceSends(unicodeMessage);
            const received = await session.bobReceives();
            expect(received).toBe(unicodeMessage);
        });
    });

    describe('Edge Cases', () => {
        it('sollte leere Nachrichten verarbeiten können', async () => {
            const rootKey = crypto.getRandomValues(new Uint8Array(32));
            const aliceKeyPair = await generateKeyPair();
            const bobKeyPair = await generateKeyPair();
            const sharedHKA = crypto.getRandomValues(new Uint8Array(32));
            const sharedNHKB = crypto.getRandomValues(new Uint8Array(32));

            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceKeyPair,
                theirRatchetPublicKey: bobKeyPair.publicKey,
                HeaderKey: sharedHKA,
                nextReceivingHeaderKey: sharedNHKB,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobKeyPair,
                theirRatchetPublicKey: aliceKeyPair.publicKey,
                HeaderKey: sharedNHKB,
                nextReceivingHeaderKey: sharedHKA,
                isInitiator: false
            });

            const session = new MessagingSession(aliceState, bobState);

            await session.aliceSends('');
            const received = await session.bobReceives();
            expect(received).toBe('');
        });

        it('sollte null zurückgeben wenn keine Nachricht vorhanden ist', async () => {
            const rootKey = crypto.getRandomValues(new Uint8Array(32));
            const aliceKeyPair = await generateKeyPair();
            const bobKeyPair = await generateKeyPair();
            const sharedHKA = crypto.getRandomValues(new Uint8Array(32));
            const sharedNHKB = crypto.getRandomValues(new Uint8Array(32));

            const aliceState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: aliceKeyPair,
                theirRatchetPublicKey: bobKeyPair.publicKey,
                HeaderKey: sharedHKA,
                nextReceivingHeaderKey: sharedNHKB,
                isInitiator: true
            });

            const bobState = await DR_Init_HE({
                rootKey,
                ourRatchetKeyPair: bobKeyPair,
                theirRatchetPublicKey: aliceKeyPair.publicKey,
                HeaderKey: sharedNHKB,
                nextReceivingHeaderKey: sharedHKA,
                isInitiator: false
            });

            const session = new MessagingSession(aliceState, bobState);

            // Keine Nachricht vorhanden
            const received = await session.bobReceives();
            expect(received).toBeNull();
        });
    });
});

