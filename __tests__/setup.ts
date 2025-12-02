/**
 * Jest Setup für WebCrypto Polyfill
 * Node.js hat crypto.subtle seit Version 15.0.0
 */
import {webcrypto} from 'node:crypto';

// Polyfill für globalThis.crypto (falls nicht vorhanden)
if (!globalThis.crypto) {
    (globalThis as any).crypto = webcrypto;
}

