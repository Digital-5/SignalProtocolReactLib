/**
 * HKDF (HMAC-based Key Derivation Function) Implementierung
 * Basierend auf RFC 5869 für sichere Schlüsselableitung
 * Verwendet SHA-512 als Standard-Hash-Algorithmus für Post-Quantum Sicherheit
 */
export declare class HKDF {
    private hash;
    /**
     * Erstellt eine neue HKDF-Instanz
     * @param hash - Der zu verwendende Hash-Algorithmus (Standard: SHA-256)
     */
    constructor(hash?: string);
    /**
     * Leitet Schlüsselmaterial mit HKDF ab
     * @param salt - Salt-Wert für die Extraktion (sollte zufällig sein)
     * @param inputKeyMaterial - Das Eingabeschlüsselmaterial
     * @param length - Die gewünschte Länge des abgeleiteten Schlüssels in Bytes
     * @returns Das abgeleitete Schlüsselmaterial
     */
    deriveKeys(salt: Uint8Array, inputKeyMaterial: Uint8Array, length: number): Promise<Uint8Array>;
    /**
     * HKDF-Extract: Extrahiert einen Pseudozufallsschlüssel aus dem Eingabematerial
     * @param salt - Salt-Wert für HMAC
     * @param ikm - Input Key Material
     * @returns Pseudozufallsschlüssel (PRK)
     */
    private extract;
    /**
     * HKDF-Expand: Erweitert den PRK auf die gewünschte Länge
     * @param prk - Pseudozufallsschlüssel aus Extract
     * @param length - Gewünschte Ausgabelänge in Bytes
     * @returns Das erweiterte Schlüsselmaterial (OKM)
     */
    private expand;
    /**
     * Leitet Schlüssel für Header Encryption ab (KDF_RK_HE aus Signal Spec Section 4.2)
     * Gibt Root Key + Chain Key + Next Header Key zurück
     *
     * @param salt - Salt für HKDF (z.B. Root Key)
     * @param inputKeyMaterial - Input Key Material (z.B. DH Output)
     * @returns Tuple mit [Root Key (32 Bytes), Chain Key (32 Bytes), Next Header Key (32 Bytes)]
     */
    deriveKeysHE(salt: Uint8Array, inputKeyMaterial: Uint8Array): Promise<[Uint8Array, Uint8Array, Uint8Array]>;
    /**
     * Konkateniert zwei Uint8Arrays
     * @param a - Erstes Array
     * @param b - Zweites Array
     * @returns Konkateniertes Array
     */
    private concatUint8Arrays;
}
