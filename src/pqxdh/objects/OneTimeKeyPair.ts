import {SignedKyberPublic} from "./SignedKyberPublic";
import {generateKyberKeyPair, generateX25519Keys} from "../interfaces/CryptoInterface";
import {randomUUID} from "node:crypto";

export class OneTimeKeyPair {
    oneTimeKem: SignedKyberPublic
    oneTimeCurve: string;
    identifier: string;

    constructor(oneTimeKem: SignedKyberPublic, oneTimeCurve: string,  identifier: string) {
        this.oneTimeKem = oneTimeKem;
        this.oneTimeCurve = oneTimeCurve;
        this.identifier = identifier;
    }

    async generate(privateKey: string) {
        const X25519KeyPair = generateX25519Keys();
        const KyberKeyPair = await generateKyberKeyPair();
        this.oneTimeKem = new SignedKyberPublic(KyberKeyPair.publicKey, privateKey);
        this.oneTimeCurve = X25519KeyPair.publicKey;
        this.identifier = randomUUID().toString();
        return {
            X25519PrivateKey: X25519KeyPair.privateKey,
            KyberPrivateKey: KyberKeyPair.privateKey,
            identifier: this.identifier
        }

    }

}