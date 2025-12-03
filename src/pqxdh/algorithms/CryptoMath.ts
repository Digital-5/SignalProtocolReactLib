import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';

/*
Cryptographic Utilities needed for PQXDH and XEdDSA implementations.
Includes constants for Curve25519 and helper functions for hashing,
modular arithmetic, and conversions between BigInt and Uint8Array.
 */

// Curve25519 domain parameters as per RFC 7748
export const CURVE25519_PARAMS = {
	/** Field prime: p = 2^255 - 19 */
	p: BigInt(
		'0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed',
	),

	/** Order of base point (prime; q < p; qB = I): q = 2^252 + 27742317777372353535851937790883648493 */
	q: BigInt(
		'0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed',
	),

	/** Cofactor: c = 8 */
	c: BigInt(8),

	/** Twisted Edwards curve constant: d = -121665/121666 (mod p) */
	d: BigInt(
		'0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3',
	),

	/** Twisted Edwards curve constant: a = -1 (mod p) */
	a: BigInt(
		'0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec',
	),

	/** Montgomery curve constant: A = 486662 */
	A: BigInt(486662),

	/** Nonsquare integer modulo p: n = 2 (used for point compression/decompression) */
	n: BigInt(2),

	/** |p| = ceil(log2(p)) = 255 bits */
	pBits: 255,

	/** |q| = ceil(log2(q)) = 253 bits */
	qBits: 253,

	/** b = 8 * ceil((|p| + 1)/8) = 8 * ceil(256/8) = 8 * 32 = 256 bits (bitlength for encoded point or integer) */
	b: 256,

	/** Byte length for encoded points and scalars: 256/8 = 32 bytes */
	byteLength: 32,
} as const;

export function getBasePoint() {
	return ed25519.Point.BASE;
}

export function mod(n: bigint, m: bigint): bigint {
	return ((n % m) + m) % m;
}

// Domain-separated hash function for XEdDSA
// Basically just SHA-512 with b/8 prefix bytes 0xFF (32 for Curve25519)
// first byte being 0xFF - 1 - i
export function hash_i(data: Uint8Array, i: number): any {
	if (i < 0 || i > 255) {
		throw new Error('Parameter i must be in range [0, 255]');
	}

	// Calculate prefix byte: 2^b - 1 - i
	const prefixByte = BigInt(2n ** 256n) - BigInt(1 + i);
	const prefix = bigintToUint8ArrayLE(prefixByte);
	const combined = concatenateUint8Arrays([prefix, data]);
	return hash(combined);
}

export function hash(data: Uint8Array): Uint8Array {
	return sha512(data);
}

export function bigintToUint8ArrayLE(bigint: bigint, targetLength: number = 32): Uint8Array {
	if (bigint < 0n) {
		throw new Error('Cannot convert negative BigInt to Uint8Array for unsigned representation.');
	}
	const uint8Array = new Uint8Array(targetLength).fill(0); // Initialize with zeros
	let i = 0;
	let tempBigint = bigint;

	while (tempBigint > 0n && i < targetLength) {
		uint8Array[i] = Number(tempBigint & 0xffn); // Get the last byte
		tempBigint >>= 8n; // Shift right by 8 bits
		i++;
	}
	// If tempBigint is still > 0n here, it means the number is too large for targetLength
	if (tempBigint > 0n) {
		throw new Error(`BigInt ${bigint} is too large to fit into a ${targetLength}-byte Uint8Array.`);
	}
	return uint8Array;
}

export function Uint8ArrayToBigintLE(uint8array: Uint8Array): bigint {
	let result = 0n;
	let powerOf256 = 1n; // Represents 256^i

	// Iterate through the Uint8Array from the first byte (least significant)
	for (let i = 0; i < uint8array.length; i++) {
		// Add the current byte (converted to BigInt) multiplied by its corresponding power of 256
		result += BigInt(uint8array[i]) * powerOf256;
		// For the next iteration, the power of 256 increases
		powerOf256 *= 256n;
	}

	return result;
}

export function UInt8ArrayToHexString(uint8array: Uint8Array): string {
	let hex = "";
	for (let i = 0; i < uint8array.length; i++) {
		const byte = uint8array[i];
		hex += byte.toString(16).padStart(2, "0");
	}
	return hex;
}

export function HexStringToUInt8Array(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) {
        throw new Error("Invalid hex string");
    }
    const uint8array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        uint8array[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    return uint8array;
}

// Birational map from Montgomery u to Edwards y according to RFC 7748, Section 4.1:
export function u_to_y(u: bigint) {
	const Fp = ed25519.Point.Fp;
	const one = BigInt(1);
	const numerator = Fp.sub(u, one); // u - 1
	const denominator = Fp.add(u, one); // u + 1
	const y = Fp.div(numerator, denominator); // (u - 1) / (u + 1)
	return y;
}

export function concatenateUint8Arrays(arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.byteLength;
    }
    return result;
}

export function stringToUint8Array(str: string): Uint8Array {
    const encoder = new TextEncoder();
    return encoder.encode(str);
}