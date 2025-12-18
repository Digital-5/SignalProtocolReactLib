import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512,sha256 } from '@noble/hashes/sha2.js';

export class HKDF {
    private readonly hashFn: typeof sha512 | typeof sha256;

    constructor(hash: string = 'SHA-512') {
        this.hashFn = hash === 'SHA-512' ? sha512 : sha256;
    }

    async deriveKeys(salt: Uint8Array, inputKeyMaterial: Uint8Array, length: number): Promise<Uint8Array> {
        return hkdf(this.hashFn, inputKeyMaterial, salt, undefined, length);
    }

    async deriveKeysHE(
        salt: Uint8Array,
        inputKeyMaterial: Uint8Array
    ): Promise<[Uint8Array, Uint8Array, Uint8Array]> {
        const derived = await this.deriveKeys(salt, inputKeyMaterial, 96);

        const rootKey = derived.slice(0, 32);
        const chainKey = derived.slice(32, 64);
        const nextHeaderKey = derived.slice(64, 96);

        return [rootKey, chainKey, nextHeaderKey];
    }
}
