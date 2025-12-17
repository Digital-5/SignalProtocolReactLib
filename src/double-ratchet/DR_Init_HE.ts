import {KeyPair, deriveSharedSecret} from './CryptoUtils';
import {DRState, SkippedMessageKey} from './DR_Interfaces';
import {HKDF} from './HKDF';

//Das bekomme ich von PQXDH
export interface DRInitParamsHE {
    rootKey: Uint8Array; //SharedSecret from PQXDH 32 bit
    ourRatchetKeyPair: KeyPair; // One-Time Keypair used in PQXDH X25519
    theirRatchetPublicKey: Uint8Array; // Ephemeral key from sender PQXDH
    HeaderKey: Uint8Array; // Initial shared secret (32 bytes) von PQXDH - für Initiator: sendingHeaderKey, für Responder: nextSendingHeaderKey
    nextReceivingHeaderKey: Uint8Array; // Initial shared secret (32 bytes) von PQXDH - für beide: der receiving header key
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
                sendingNextHeaderKey: NHKs,
                receivingHeaderKey: null, //null da sie erst wenn das gegenüber antwortet es braucht
                receivingNextHeaderKey: params.nextReceivingHeaderKey,
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
                sendingNextHeaderKey: params.HeaderKey, // NHKs = shared_nhkb
                receivingHeaderKey: null, // Signal Spec: HKr = None todo rausfinden warum die beiden leer sind
                receivingNextHeaderKey: params.nextReceivingHeaderKey // NHKr = shared_hka (Alice's HKs)
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
        96 // 3 x 32 bytes = RK (32) + CK (32) + NHK (32) für AES-256-GCM
    );

    // Teile in 3 x 32 Bytes auf
    const RK = derived.slice(0, 32);
    const CK = derived.slice(32, 64);
    const NHK = derived.slice(64, 96); // 32 Bytes für AES-256-GCM Header Encryption

    return [RK, CK, NHK];
}

