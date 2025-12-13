/**
 * HKDF (HMAC-based Key Derivation Function) Implementierung
 * Basierend auf RFC 5869 für sichere Schlüsselableitung
 * Verwendet SHA-512 als Standard-Hash-Algorithmus für Post-Quantum Sicherheit
 */
export class HKDF {
    private readonly hash: string;

    /**
     * Erstellt eine neue HKDF-Instanz
     * @param hash - Der zu verwendende Hash-Algorithmus (Standard: SHA-256)
     */
    constructor(hash: string = 'SHA-512') {
        this.hash = hash;
    }

    /**
     * Leitet Schlüsselmaterial mit HKDF ab
     * @param salt - Salt-Wert für die Extraktion (sollte zufällig sein)
     * @param inputKeyMaterial - Das Eingabeschlüsselmaterial
     * @param length - Die gewünschte Länge des abgeleiteten Schlüssels in Bytes
     * @returns Das abgeleitete Schlüsselmaterial
     */
    async deriveKeys(salt: Uint8Array, inputKeyMaterial: Uint8Array, length: number): Promise<Uint8Array> {
        const prk = await this.extract(salt, inputKeyMaterial);
        return this.expand(prk, length);
    }

    /**
     * HKDF-Extract: Extrahiert einen Pseudozufallsschlüssel aus dem Eingabematerial
     * @param salt - Salt-Wert für HMAC
     * @param ikm - Input Key Material
     * @returns Pseudozufallsschlüssel (PRK)
     */
    private async extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
        // Importiere den Salt als HMAC-Schlüssel
        const key = await crypto.subtle.importKey(
            'raw',
            salt as BufferSource,
            {name: 'HMAC', hash: this.hash},
            false,
            ['sign']
        );

        // Berechne HMAC über das Eingabematerial
        const hmac = await crypto.subtle.sign('HMAC', key, ikm as BufferSource);
        return new Uint8Array(hmac);
    }

    /**
     * HKDF-Expand: Erweitert den PRK auf die gewünschte Länge
     * @param prk - Pseudozufallsschlüssel aus Extract
     * @param length - Gewünschte Ausgabelänge in Bytes
     * @returns Das erweiterte Schlüsselmaterial (OKM)
     */
    private async expand(prk: Uint8Array, length: number): Promise<Uint8Array> {
        const hashLength = 32; // SHA-256 produziert 32-Byte-Hashes
        const n = Math.ceil(length / hashLength);
        let okm: Uint8Array = new Uint8Array(0);
        let previousBlock = new Uint8Array(0);

        // Iteriere und generiere Blöcke bis zur gewünschten Länge
        for (let i = 1; i <= n; i++) {
            // Erstelle Input: previousBlock || info || counter
            const input = new Uint8Array(previousBlock.length + 1);
            input.set(previousBlock);
            input[input.length - 1] = i; // Counter-Byte

            // Importiere PRK als HMAC-Schlüssel
            const key = await crypto.subtle.importKey(
                'raw',
                prk as BufferSource,
                {name: 'HMAC', hash: this.hash},
                false,
                ['sign']
            );

            // Berechne HMAC über den Input
            const hmac = await crypto.subtle.sign('HMAC', key, input as BufferSource);
            previousBlock = new Uint8Array(hmac);
            okm = this.concatUint8Arrays(okm, previousBlock);
        }

        // Schneide auf die gewünschte Länge zu
        return okm.slice(0, length);
    }

    /**
     * Leitet Schlüssel für Header Encryption ab (KDF_RK_HE aus Signal Spec Section 4.2)
     * Gibt Root Key + Chain Key + Next Header Key zurück
     *
     * @param salt - Salt für HKDF (z.B. Root Key)
     * @param inputKeyMaterial - Input Key Material (z.B. DH Output)
     * @returns Tuple mit [Root Key (32 Bytes), Chain Key (32 Bytes), Next Header Key (32 Bytes)]
     */
    async deriveKeysHE(
        salt: Uint8Array,
        inputKeyMaterial: Uint8Array
    ): Promise<[Uint8Array, Uint8Array, Uint8Array]> {
        // Signal Spec Section 4.2: KDF_RK_HE(rk, dh_out) returns (RK, CK, NHK)
        const derived = await this.deriveKeys(salt, inputKeyMaterial, 96); // 32 + 32 + 32 = 96 Bytes

        const rootKey = derived.slice(0, 32);
        const chainKey = derived.slice(32, 64);
        const nextHeaderKey = derived.slice(64, 96);

        return [rootKey, chainKey, nextHeaderKey];
    }

    /**
     * Konkateniert zwei Uint8Arrays
     * @param a - Erstes Array
     * @param b - Zweites Array
     * @returns Konkateniertes Array
     */
    private concatUint8Arrays(a: Uint8Array, b: Uint8Array): Uint8Array {
        const c = new Uint8Array(a.length + b.length);
        c.set(a);
        c.set(b, a.length);
        return c;
    }
}