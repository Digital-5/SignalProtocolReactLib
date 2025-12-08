# Signal Protocol React Library

Eine TypeScript-Implementierung des **Signal Protocol** für sichere End-to-End-Verschlüsselung.

## 📋 Inhaltsverzeichnis

- [Features](#features)
- [Installation](#installation)
- [Verwendung](#verwendung)
- [Verwendungsanleitungen](./USAGE.md) 📖 **Detaillierte Szenarien**
- [API-Dokumentation](#api-dokumentation)
- [Signal Spec Compliance](#signal-spec-compliance)
- [Sicherheitshinweise](#sicherheitshinweise)
- [Entwicklung](#entwicklung)
- [Lizenz](#lizenz)

## ✨ Features

- ✅ **Double Ratchet Algorithm**: Vollständige Implementierung gemäß Signal Protocol Spec (Section 3)
- ✅ **X25519 (Curve25519)**: ECDH mit X25519 gemäß RFC 7748 (Signal-Standard)
- ✅ **HKDF-SHA512**: Schlüsselableitung gemäß RFC 5869 mit SHA-512
- ✅ **AES-256-GCM**: Authenticated Encryption with Associated Data
- ✅ **Out-of-Order Messages**: Unterstützung für verspätete/ungeordnete Nachrichten
- ✅ **PN (Previous Number)**: Korrekte Behandlung von Chain-Übergängen
- ✅ **Associated Data**: Header-Authentifizierung
- ✅ **TypeScript**: Vollständig typisiert für bessere IDE-Unterstützung
- ✅ **32 Tests**: 97% Code Coverage

## 📦 Installation

### Für lokale Entwicklung:

```bash
# Repository klonen
git clone ...
cd SignalProtocolReactLib

# Dependencies installieren
npm install

# Tests ausführen
npm test

# Build erstellen
npm run build
```

### In ein anderes Projekt einbinden:

**Option 1: npm link (Entwicklung)**

```bash
# Im SignalProtocolReactLib Verzeichnis:
npm link

# In deinem Projekt:
npm link signal-protocol-react-lib
```

**Option 2: Direkter Pfad in package.json**

```json
{
  "dependencies": {
    "signal-protocol-react-lib": "file:../SignalProtocolReactLib"
  }
}
```
## 🚀 Verwendung

### Grundlegende Verwendung

```typescript
// Bei lokaler Entwicklung (innerhalb des Projekts):
import {generateKeyPair, deriveSharedSecret, HKDF, DR_Init} from './src/double-ratchet';

// Oder wenn als Package eingebunden:
// import { generateKeyPair, deriveSharedSecret, HKDF, DR_Init } from 'signal-protocol-react-lib';

// 1. Generiere Schlüsselpaare
const ourIdentityKeyPair = await generateKeyPair();
const ourEphemeralKeyPair = await generateKeyPair();

// 2. Empfange öffentliche Schlüssel der Gegenseite
const theirIdentityPublicKey = /* ... */;
const theirEphemeralPublicKey = /* ... */;

// 3. Initialisiere den Root Key (z.B. aus einem X3DH Handshake)
const rootKey = new Uint8Array(32); // 32 zufällige Bytes

// 4. Initialisiere den Double Ratchet State
const drState = await DR_Init({
    rootKey,
    ourIdentityKeyPair,
    theirIdentityPublicKey,
    ourEphemeralKeyPair,
    theirEphemeralPublicKey
});

console.log('Double Ratchet State initialisiert:', drState);
```

### ECDH Schlüsselaustausch

```typescript
import {generateKeyPair, deriveSharedSecret} from 'signal-protocol-react-lib';

// Generiere zwei Schlüsselpaare
const aliceKeyPair = await generateKeyPair();
const bobKeyPair = await generateKeyPair();

// Beide Seiten können dasselbe gemeinsame Geheimnis ableiten
const aliceSharedSecret = await deriveSharedSecret(
    aliceKeyPair.privateKey,
    bobKeyPair.publicKey
);

const bobSharedSecret = await deriveSharedSecret(
    bobKeyPair.privateKey,
    aliceKeyPair.publicKey
);

// aliceSharedSecret === bobSharedSecret
```

### HKDF Schlüsselableitung

```typescript
import {HKDF} from 'signal-protocol-react-lib';

const hkdf = new HKDF('SHA-256');

// Leite Schlüsselmaterial ab
const salt = new Uint8Array(32); // Zufälliger Salt
const inputKeyMaterial = new Uint8Array(32); // Eingabeschlüssel
const derivedKeys = await hkdf.deriveKeys(salt, inputKeyMaterial, 64);

// Teile die abgeleiteten Schlüssel auf
const key1 = derivedKeys.slice(0, 32);
const key2 = derivedKeys.slice(32, 64);
```

## 📚 API-Dokumentation

### `generateKeyPair(): Promise<KeyPair>`

Generiert ein neues ECDH-Schlüsselpaar (P-256).

**Rückgabe:**

- `Promise<KeyPair>`: Ein Objekt mit `publicKey` und `privateKey` als `Uint8Array`

### `deriveSharedSecret(privateKeyBytes: Uint8Array, publicKeyBytes: Uint8Array): Promise<Uint8Array>`

Leitet ein gemeinsames Geheimnis mittels ECDH ab.

**Parameter:**

- `privateKeyBytes`: Unser privater Schlüssel (PKCS#8 Format)
- `publicKeyBytes`: Öffentlicher Schlüssel der Gegenseite (Raw Format)

**Rückgabe:**

- `Promise<Uint8Array>`: Das abgeleitete gemeinsame Geheimnis (32 Bytes)

### `HKDF`

Klasse für HMAC-based Key Derivation Function.

#### `constructor(hash?: string)`

Erstellt eine neue HKDF-Instanz.

**Parameter:**

- `hash` (optional): Der zu verwendende Hash-Algorithmus (Standard: `'SHA-256'`)

#### `deriveKeys(salt: Uint8Array, inputKeyMaterial: Uint8Array, length: number): Promise<Uint8Array>`

Leitet Schlüsselmaterial mit HKDF ab.

**Parameter:**

- `salt`: Salt-Wert für die Extraktion
- `inputKeyMaterial`: Das Eingabeschlüsselmaterial
- `length`: Die gewünschte Länge des abgeleiteten Schlüssels in Bytes

**Rückgabe:**

- `Promise<Uint8Array>`: Das abgeleitete Schlüsselmaterial

### `DR_Init(params: DRInitParams): Promise<DRState>`

Initialisiert den Double Ratchet State.

**Parameter:**

- `params.rootKey`: Root Key für die Schlüsselableitung
- `params.ourIdentityKeyPair`: Unser Identity-Schlüsselpaar
- `params.theirIdentityPublicKey`: Öffentlicher Identity-Schlüssel der Gegenseite
- `params.ourEphemeralKeyPair`: Unser ephemerer Schlüssel
- `params.theirEphemeralPublicKey`: Öffentlicher ephemerer Schlüssel der Gegenseite

**Rückgabe:**

- `Promise<DRState>`: Der initialisierte Double Ratchet State

## 🔒 Sicherheitshinweise

- **Zufällige Schlüssel**: Verwende immer kryptographisch sichere Zufallszahlen für Schlüssel und Salts
- **Schlüsselverwaltung**: Bewahre private Schlüssel sicher auf und gebe sie niemals weiter
- **Forward Secrecy**: Die Library implementiert Forward Secrecy durch regelmäßige Schlüsselrotation
- **Authentifizierung**: Stelle sicher, dass öffentliche Schlüssel authentifiziert sind (z.B. durch
  Fingerprint-Vergleich)

## 🛠️ Entwicklung

### Projekt klonen

```bash
git clone https://github.com/yourusername/signal-protocol-react-lib.git
cd signal-protocol-react-lib
```

### Dependencies installieren

```bash
npm install
```

### Build

```bash
npm run build
```

### Tests ausführen

```bash
npm test
```

## 📄 Lizenz

MIT

## 🤝 Beitragen

Beiträge sind willkommen! Bitte erstelle einen Pull Request oder öffne ein Issue.

## 📖 Weitere Ressourcen

- [Signal Protocol Dokumentation](https://signal.org/docs/)
- [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [X3DH Key Agreement](https://signal.org/docs/specifications/x3dh/)
- [RFC 5869 (HKDF)](https://tools.ietf.org/html/rfc5869)

