import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512,sha256 } from '@noble/hashes/sha2.js';

const TEXT_ENCODER = new TextEncoder();
const INFO_ROOT_KEY = TEXT_ENCODER.encode('DR-Root-Key');
const INFO_CHAIN_KEY = TEXT_ENCODER.encode('DR-Chain-Key');
const INFO_MESSAGE_KEY = TEXT_ENCODER.encode('DR-Message-Key');

export class HKDF {
    private readonly hashFn: typeof sha512 | typeof sha256;

    constructor(hash: string = 'SHA-512') {
        this.hashFn = hash === 'SHA-512' ? sha512 : sha256;
    }

    async deriveKeys(salt: Uint8Array, inputKeyMaterial: Uint8Array, length: number, info?: Uint8Array): Promise<Uint8Array> {
        return hkdf(this.hashFn, inputKeyMaterial, salt, info, length);
    }

    async deriveMessageKey(salt: Uint8Array, inputKeyMaterial: Uint8Array, length: number): Promise<Uint8Array> {
        return hkdf(this.hashFn, inputKeyMaterial, salt, INFO_MESSAGE_KEY, length);
    }

    async deriveChainKey(salt: Uint8Array, inputKeyMaterial: Uint8Array, length: number): Promise<Uint8Array> {
        return hkdf(this.hashFn, inputKeyMaterial, salt, INFO_CHAIN_KEY, length);
    }

    async deriveKeysHE(
        salt: Uint8Array,
        inputKeyMaterial: Uint8Array
    ): Promise<[Uint8Array, Uint8Array, Uint8Array]> {
        const derived = await this.deriveKeys(salt, inputKeyMaterial, 96, INFO_ROOT_KEY);

        const rootKey = derived.slice(0, 32);
        const chainKey = derived.slice(32, 64);
        const nextHeaderKey = derived.slice(64, 96);

        return [rootKey, chainKey, nextHeaderKey];
    }
}
