import {generateX25519KeyPair} from "./algorithms/X25519";
//import {X25519EncodedKeyPair} from "./objects/X25519EncodedKeyPair";

export function createIdentityKey() {
    const keyPair = generateX25519KeyPair();
    return new X25519EncodedKeyPair(keyPair);
}
