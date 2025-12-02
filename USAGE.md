# Verwendungsanleitungen

Diese Datei erklärt verschiedene Szenarien, wie du die Signal Protocol React Library verwenden kannst.

---

## 📋 Inhaltsverzeichnis

1. [Szenario 1: Lokale Entwicklung im Projekt](#szenario-1-lokale-entwicklung-im-projekt)
2. [Szenario 2: In ein anderes Projekt einbinden](#szenario-2-in-ein-anderes-projekt-einbinden)
3. [Szenario 3: React Native Integration](#szenario-3-react-native-integration)
4. [Szenario 4: Web App Integration](#szenario-4-web-app-integration)
5. [Szenario 5: Node.js Backend](#szenario-5-nodejs-backend)

---

## React Native Integration

**Wann:** Du baust eine mobile App mit React Native.

### Schritt 1: Library einbinden

```bash
# In deinem React Native Projekt
npm install git linkhier
```

### Schritt 2: Polyfills installieren (falls nötig)

React Native benötigt eventuell Crypto-Polyfills:

```bash
npm install react-native-get-random-values
npm install @react-native-community/async-storage
```

### Schritt 3: Polyfills importieren

**App.tsx (oder index.js):**
```typescript
import 'react-native-get-random-values'; // MUSS vor anderen Imports sein!

import {
  generateKeyPair,
  DR_Init,
  ratchetEncrypt,
  ratchetDecrypt
} from 'signal-protocol-react-lib';

// Rest deiner App...
```

### Schritt 4: Secure Storage verwenden

```typescript
import AsyncStorage from '@react-native-community/async-storage';

// State speichern
async function saveState(state: DRState) {
  const serialized = JSON.stringify({
    rootKey: Array.from(state.rootKey),
    sendingChainKey: Array.from(state.sendingChainKey),
    // ...
  });

  await AsyncStorage.setItem('dr-state', serialized);
}

// State laden
async function loadState(): Promise<DRState | null> {
  const data = await AsyncStorage.getItem('dr-state');
  if (!data) return null;

  const parsed = JSON.parse(data);
  return {
    rootKey: new Uint8Array(parsed.rootKey),
    sendingChainKey: new Uint8Array(parsed.sendingChainKey),
    // ...
  };
}
```

### Beispiel: Secure Chat Component

```typescript
import React, { useState, useEffect } from 'react';
import { View, TextInput, Button, FlatList } from 'react-native';
import { generateKeyPair, DR_Init, ratchetEncrypt, ratchetDecrypt } from 'signal-protocol-react-lib';

export function SecureChatScreen() {
  const [state, setState] = useState<DRState | null>(null);
  const [messages, setMessages] = useState<string[]>([]);

  useEffect(() => {
    // Initialisiere Double Ratchet
    initializeChat();
  }, []);

  async function initializeChat() {
    const identity = await generateKeyPair();
    const ephemeral = await generateKeyPair();
    // ... weitere Initialisierung
  }

  async function sendMessage(text: string) {
    if (!state) return;

    const plaintext = new TextEncoder().encode(text);
    const [encrypted, newState] = await ratchetEncrypt(state, plaintext);
    setState(newState);

    // Sende verschlüsselte Nachricht an Server...
  }

  return (
    <View>
      {/* Deine UI hier */}
    </View>
  );
}
```

---

## 🔧 Troubleshooting

### Problem: "Module not found"

**Lösung:**
```bash
# Stelle sicher, dass Dependencies installiert sind
npm install

# Bei npm link Problemen:
npm unlink signal-protocol-react-lib
npm link

# Build erstellen
npm run build
```

### Problem: "crypto is not defined" (React Native)

**Lösung:**
```typescript
// Importiere Polyfill VOR allen anderen Imports
import 'react-native-get-random-values';
```

### Problem: "Cannot find module './src/double-ratchet'"

**Lösung:**
```typescript
// Bei lokaler Entwicklung:
import { ... } from './src/double-ratchet';

// Bei Package-Installation:
import { ... } from 'signal-protocol-react-lib';
```

---

## 📚 Weitere Ressourcen

- [Double Ratchet README](./src/double-ratchet/README.md)
- [X25519 zu Ed25519 Docs](./src/pqxdh/X25519_TO_ED25519.md)
- [Signal Protocol Specification](https://signal.org/docs/specifications/doubleratchet/)

---

**Fragen?** Erstelle ein Issue auf GitHub!

