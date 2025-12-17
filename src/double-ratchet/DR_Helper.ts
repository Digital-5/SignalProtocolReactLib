import {DRState, SkippedMessageKey} from "./DR_Interfaces";

// erstellt ein DR_state und nimmt string keys für unser schlüsselpaar an

export function createDRState(
    rootKey: string,
    //sendingChainKey: Uint8Array | null, das wurde noch nicht berechnet
    //receivingChainKey: Uint8Array | null, ^^
    ourEphemeralKeyPair: { publicKey: string; privateKey: string },
    theirEphemeralPublicKey: string,
    messageNumbers: { sending: number; receiving: number },
    pn: number,
    skippedMessageKeys: Map<string, SkippedMessageKey>,
    sendingHeaderKey: string | null, //eines von beiden ist am anfang null
    receivingHeaderKey: string | null, // da eins durch pqxdh kommt (Je nachdem wer initiiert)
    nextSendingHeaderKey: string | null, //^ aber das andere kann mit dem rootkey und das ss erzeugt werden
    nextReceivingHeaderKey: string | null, // ^^ wenn man antwortet
): DRState {

    // @ts-ignore
    return {
        rootKey: stringToUint8Array(rootKey),
        sendingChainKey: null,
        receivingChainKey: null,
        ourEphemeralKeyPair: convertStringsToUint8Array(ourEphemeralKeyPair), //error kann ignoriert werden da wir sicher sind das es konvertierbar ist
        theirEphemeralPublicKey: stringToUint8Array(theirEphemeralPublicKey),
        messageNumbers,
        pn,
        skippedMessageKeys,
        HeaderKeys: {
            sendingHeaderKey: sendingHeaderKey ? stringToUint8Array(sendingHeaderKey) : null,
            sendingNextHeaderKey: nextSendingHeaderKey ? stringToUint8Array(nextSendingHeaderKey) : null,
            receivingHeaderKey: receivingHeaderKey ? stringToUint8Array(receivingHeaderKey) : null,
            receivingNextHeaderKey: nextReceivingHeaderKey ? stringToUint8Array(nextReceivingHeaderKey) : null
        }
    };
}

//gibt ein object als speicherbaren string zurück
export function toJson(state: DRState): string {
    try {
        return JSON.stringify(state);
    } catch (error) {
        console.error(`Error: Circular reference detected: ${error}`);
    }
    return '';
}

//Hilfsfunktion um string in Uint8Array zu konvertieren
export function stringToUint8Array(str: string): Uint8Array {
    const encoder = new TextEncoder();
    return encoder.encode(str);
}

//Hilfsfunktion um aus einem beliebigen Objekt alle string Werte in Uint8Array zu konvertieren
export function convertStringsToUint8Array<T>(obj: T): T {
    // Primitiver Typ oder null
    if (obj === null || obj === undefined) {
        return obj;
    }

    const objType = typeof obj;

    switch (objType) {
        case 'string':
            // String → Uint8Array konvertieren
            return stringToUint8Array(obj as string) as any;


        case 'object':
            // Uint8Array bereits vorhanden → nicht ändern
        {
            if (obj instanceof Uint8Array) {
                return obj;
            }

            // Array rekursiv verarbeiten
            if (Array.isArray(obj)) {
                return obj.map(item => convertStringsToUint8Array(item)) as any;
            }

            // Map speziell behandeln
            if (obj instanceof Map) {
                const newMap = new Map();
                obj.forEach((value, key) => {
                    newMap.set(key, convertStringsToUint8Array(value));
                });
                return newMap as any;
            }

            // Objekt rekursiv verarbeiten
            const result: any = {};
            for (const key in obj) {
                if (obj.hasOwnProperty(key)) {
                    result[key] = convertStringsToUint8Array(obj[key]);
                }
            }
            return result;
        }

        default:
            return obj;
    }
}

export function cleanUnusedMessageKeys(state: DRState) {
    const MAX_AGE = 1000 * 60 * 60 * 24 * 7 * 4; //ein monat in ms
    const jetztZeit = Date.now();
    for (const [keyId, skippedKey] of state.skippedMessageKeys.entries()) {
        if (jetztZeit - skippedKey.timestamp> MAX_AGE) {
            state.skippedMessageKeys.delete(keyId);
        }
    }
}

//für ratchet encryption und decryption siehe dr_ratchet_he

