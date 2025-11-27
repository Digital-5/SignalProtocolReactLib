/**
 * Header Encryption für Double Ratchet
 * Implementiert Signal Protocol Specification Section 4
 * https://signal.org/docs/specifications/doubleratchet/
 */
import { MessageHeader } from './DR_Ratchet';
/**
 * Verschlüsselt einen Message Header mit AES-256-GCM
 * Signal Spec Section 4.2: HENCRYPT(hk, plaintext)
 *
 * @param headerKey - Der Header Key für die Verschlüsselung (32 Bytes)
 * @param header - Der zu verschlüsselnde Header
 * @returns Verschlüsselter Header (inkl. IV)
 */
export declare function encryptHeader(headerKey: Uint8Array, header: MessageHeader): Promise<Uint8Array>;
/**
 * Entschlüsselt einen verschlüsselten Message Header
 * Signal Spec Section 4.2: HDECRYPT(hk, ciphertext)
 *
 * @param headerKey - Der Header Key für die Entschlüsselung (32 Bytes)
 * @param encryptedHeader - Der verschlüsselte Header (inkl. IV)
 * @returns Entschlüsselter Header oder null bei Fehler
 */
export declare function decryptHeader(headerKey: Uint8Array | null, encryptedHeader: Uint8Array): Promise<MessageHeader | null>;
