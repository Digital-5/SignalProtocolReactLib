# Double Ratchet Module

Dieses Modul enthält die vollständige Implementierung des Double Ratchet Algorithmus nach dem Signal Protocol.

## Module

### CryptoUtils.ts
- **generateKeyPair()**: Generiert ECDH-Schlüsselpaare (P-256)
- **deriveSharedSecret()**: Leitet gemeinsame Geheimnisse mittels ECDH ab

### HKDF.ts
- **HKDF**: HMAC-based Key Derivation Function nach RFC 5869
- Verwendet für sichere Schlüsselableitung

### DR_State.ts
- **DRState**: Interface für den Double Ratchet State
- Enthält Root Key, Chain Keys, Ephemeral Keys und Message Numbers

### DR_Init.ts
- **DR_Init()**: Initialisiert den Double Ratchet State
- Unterscheidet zwischen Initiator und Responder
- Führt initiale DH-Schlüsselvereinbarung durch

### DR_Ratchet.ts
- **ratchetEncrypt()**: Verschlüsselt Nachrichten und führt Symmetric Ratchet durch
- **ratchetDecrypt()**: Entschlüsselt Nachrichten und führt bei Bedarf DH Ratchet durch
- **performDHRatchet()**: Führt einen DH Ratchet Step aus (Schlüsselrotation)

## Verwendung

```typescript
import { 
  generateKeyPair, 
  DR_Init, 
  ratchetEncrypt, 
  ratchetDecrypt 
} from 'signal-protocol-react-lib';

// 1. Generiere Schlüsselpaare
const aliceIdentity = await generateKeyPair();
const bobIdentity = await generateKeyPair();
const aliceEphemeral = await generateKeyPair();
const bobEphemeral = await generateKeyPair();

// 2. Initialisiere States
const aliceState = await DR_Init({
  rootKey: sharedRootKey,
  ourIdentityKeyPair: aliceIdentity,
  theirIdentityPublicKey: bobIdentity.publicKey,
  ourEphemeralKeyPair: aliceEphemeral,
  theirEphemeralPublicKey: bobEphemeral.publicKey,
  isInitiator: true
});

// 3. Verschlüssele und sende Nachricht
const plaintext = new TextEncoder().encode('Hello!');
const [encrypted, newState] = await ratchetEncrypt(aliceState, plaintext);

// 4. Empfange und entschlüssele
const [decrypted, bobNewState] = await ratchetDecrypt(bobState, encrypted);
```

## Sicherheitsfeatures

- ✅ Forward Secrecy
- ✅ Post-Compromise Security
- ✅ Authenticated Encryption (AES-256-GCM)
- ✅ Replay Protection
- ✅ DH Ratchet für Schlüsselrotation
- ✅ Symmetric Ratchet für Message Keys

## Tests

Siehe `__tests__/DoubleRatchet.test.ts` für umfassende Tests.

