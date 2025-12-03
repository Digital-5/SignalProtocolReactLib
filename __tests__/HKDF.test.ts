/**
 * Tests für HKDF
 * Testet die Schlüsselableitung nach RFC 5869
 */
import { HKDF } from '../src/double-ratchet/HKDF';

describe('HKDF', () => {
    let hkdf: HKDF;

    beforeEach(() => {
        hkdf = new HKDF('SHA-512');
    });

    describe('deriveKeys', () => {
        it('sollte Schlüsselmaterial mit der gewünschten Länge ableiten', async () => {
            const salt = new Uint8Array(32).fill(1);
            const ikm = new Uint8Array(32).fill(2);
            const length = 64;

            const derived = await hkdf.deriveKeys(salt, ikm, length);

            expect(derived).toBeInstanceOf(Uint8Array);
            expect(derived.length).toBe(length);
        });

        it('sollte unterschiedliche Ausgaben für verschiedene Salts erzeugen', async () => {
            const salt1 = new Uint8Array(32).fill(1);
            const salt2 = new Uint8Array(32).fill(2);
            const ikm = new Uint8Array(32).fill(3);

            const derived1 = await hkdf.deriveKeys(salt1, ikm, 32);
            const derived2 = await hkdf.deriveKeys(salt2, ikm, 32);

            expect(derived1).not.toEqual(derived2);
        });

        it('sollte unterschiedliche Ausgaben für verschiedene Input Key Materials erzeugen', async () => {
            const salt = new Uint8Array(32).fill(1);
            const ikm1 = new Uint8Array(32).fill(2);
            const ikm2 = new Uint8Array(32).fill(3);

            const derived1 = await hkdf.deriveKeys(salt, ikm1, 32);
            const derived2 = await hkdf.deriveKeys(salt, ikm2, 32);

            expect(derived1).not.toEqual(derived2);
        });

        it('sollte deterministisch sein (gleiche Eingaben = gleiche Ausgabe)', async () => {
            const salt = new Uint8Array(32).fill(1);
            const ikm = new Uint8Array(32).fill(2);

            const derived1 = await hkdf.deriveKeys(salt, ikm, 64);
            const derived2 = await hkdf.deriveKeys(salt, ikm, 64);

            expect(derived1).toEqual(derived2);
        });

        it('sollte mit kurzen Längen funktionieren', async () => {
            const salt = new Uint8Array(16).fill(1);
            const ikm = new Uint8Array(16).fill(2);

            const derived = await hkdf.deriveKeys(salt, ikm, 16);

            expect(derived.length).toBe(16);
        });

        it('sollte mit langen Längen funktionieren (> Hash-Länge)', async () => {
            const salt = new Uint8Array(32).fill(1);
            const ikm = new Uint8Array(32).fill(2);

            const derived = await hkdf.deriveKeys(salt, ikm, 128); // 4x Hash-Länge

            expect(derived.length).toBe(128);
        });

        it('sollte mit leeren Salts funktionieren', async () => {
            const salt = new Uint8Array(32); // Alle Nullen
            const ikm = new Uint8Array(32).fill(1);

            const derived = await hkdf.deriveKeys(salt, ikm, 32);

            expect(derived.length).toBe(32);
        });
    });

    describe('Edge Cases', () => {
        it('sollte mit minimaler Länge (1 Byte) funktionieren', async () => {
            const salt = new Uint8Array(32).fill(1);
            const ikm = new Uint8Array(32).fill(2);

            const derived = await hkdf.deriveKeys(salt, ikm, 1);

            expect(derived.length).toBe(1);
        });

        it('sollte mit sehr großen Längen funktionieren', async () => {
            const salt = new Uint8Array(32).fill(1);
            const ikm = new Uint8Array(32).fill(2);

            const derived = await hkdf.deriveKeys(salt, ikm, 255); // Maximum für HKDF

            expect(derived.length).toBe(255);
        });
    });
});

