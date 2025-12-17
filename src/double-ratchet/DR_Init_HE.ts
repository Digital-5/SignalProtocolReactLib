import {KeyPair, deriveSharedSecret} from './CryptoUtils';
import {DRState, SkippedMessageKey} from './DR_State';
import {HKDF} from './HKDF';

//Das bekomme ich von PQXDH
export interface DRInitParamsHE {
    rootKey: Uint8Array; //SharedSecret from PQXDH 32 bit
    ourRatchetKeyPair: KeyPair; // One-Time Keypair used in PQXDH X25519
    theirRatchetPublicKey: Uint8Array; // Ephemeral key from sender PQXDH
    HeaderKey: Uint8Array; // ist ein initial ss todo 128 bytes von pqxdh?
    nextHeaderKey: Uint8Array; //ist ein inital ss 128 bytes
    isInitiator: boolean;
}

/**
 * Initialisiert einen Double Ratchet State mit Header Encryption
 * Signal Protocol Specification Section 4.4 als ob das jemand nachschlagen wuerde...
 */
export async function DR_Init_HE(params: DRInitParamsHE): Promise<DRState> {
    const skippedKeys = new Map<string, SkippedMessageKey>();

    if (params.isInitiator) {
        // Alice initialisiert - Signal Spec Section 4.4 RatchetInitAliceHE
        // Alice generiert ihre DH Keys und führt DH mit Bob's Public Key durch
        const dhOutput = await deriveSharedSecret(
            params.ourRatchetKeyPair.privateKey,
            params.theirRatchetPublicKey
        );

        const [RK, CKs, NHKs] = await KDF_RK_HE(params.rootKey, dhOutput); // gibt den rootkey chainkey und nextsendingheaderkey zurück

        const state: DRState = { //todo update!
            rootKey: RK,
            sendingChainKey: CKs,
            receivingChainKey: null, // Signal Spec: CKr = None (wird beim ersten Empfang gesetzt)
            ourEphemeralKeyPair: params.ourRatchetKeyPair,
            theirEphemeralPublicKey: params.theirRatchetPublicKey,
            messageNumbers: {
                sending: 0,
                receiving: 0
            },
            pn: 0,
            skippedMessageKeys: skippedKeys,
            HeaderKeys: {
                sendingHeaderKey: params.HeaderKey,
                sendingNextHeaderKey: params.nextHeaderKey,
                receivingHeaderKey: null, //null da sie erst wenn das gegenüber antwortet es braucht
                receivingNextHeaderKey: null
            }
        };

        return state;
    } else {
        // Bob initialisiert - Signal Spec Section 4.4 RatchetInitBobHE
        // Signal Spec: Bob's NHKr = Alice's HKs (wird als nextReceivingHeaderKey übergeben)
        //             Bob's NHKs = shared_nhkb (wird als sendingHeaderKey übergeben)
        const state: DRState = {
            rootKey: params.rootKey,
            sendingChainKey: null, // Signal Spec: CKs = None (wird beim ersten DH Ratchet Step gesetzt)
            receivingChainKey: null, // Signal Spec: CKr = None (wird beim ersten DH Ratchet Step gesetzt)
            ourEphemeralKeyPair: params.ourRatchetKeyPair,
            theirEphemeralPublicKey: params.theirRatchetPublicKey,
            messageNumbers: {
                sending: 0,
                receiving: 0
            },
            pn: 0,
            skippedMessageKeys: skippedKeys,
            HeaderKeys: {
                sendingHeaderKey: null, // Signal Spec: HKs = None (wird beim ersten DH Ratchet Step gesetzt)
                nextSendingHeaderKey: params.HeaderKey, // NHKs = shared_nhkb
                receivingHeaderKey: null, // Signal Spec: HKr = None todo rausfinden warum die beiden leer sind
                nextReceivingHeaderKey: params.nextHeaderKey // NHKr = shared_hka (Alice's HKs)
            }
        };

        return state;
    }
}

// KDF_RK_HE für Header Encryption
async function KDF_RK_HE(rk: Uint8Array, dhOutput: Uint8Array): Promise<[Uint8Array, Uint8Array, Uint8Array]> {
    // Verwende HKDF mit SHA-512 zur Ableitung von RK, CK und NHK
    // Signal Spec: KDF keyed by RK with DH output as input
    const hkdf = new HKDF('SHA-512');
    const derived = await hkdf.deriveKeys(
        rk, // salt = root key
        dhOutput, // input key material = DH output
        192// 2 x 32 bytes + 128 bytes = RK + CK + NHK
    );

    // Teile in 3 x 32 Bytes auf
    const RK = derived.slice(0, 32);
    const CK = derived.slice(32, 64);
    const NHK = derived.slice(64, 192);

    return [RK, CK, NHK];
}

