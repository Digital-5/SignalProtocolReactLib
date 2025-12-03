import {signKey} from "../interfaces/CryptoInterface";

export class SignedKyberPublic {
	KyberPublicKey: string;
	Signature: string;

    constructor(kyberPublicKey: string, X25519SignatureKey: string) {
        this.KyberPublicKey = kyberPublicKey;
        const signature = signKey(X25519SignatureKey, kyberPublicKey);
        this.Signature = signature;
    }

}
