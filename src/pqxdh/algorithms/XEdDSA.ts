import {
    bigintToUint8ArrayLE,
    concatenateUint8Arrays,
    CURVE25519_PARAMS,
    getBasePoint,
    hash,
    hash_i,
    mod,
    u_to_y,
    Uint8ArrayToBigintLE,
    UInt8ArrayToHexString
} from './CryptoMath.js'
import {ed25519} from '@noble/curves/ed25519.js';

/*
XEdDSA Key Pair Calculation, Signing, and Verification
This module implements the XEdDSA signature scheme, according to the signal XEdDSA specification.
Also following the EdDSA signature scheme as defined in RFC 8032 and Curve25519 standards from RFC 7748.
https://signal.org/docs/specifications/xeddsa/xeddsa.pdf
 */

// Includes fancy JSDoc comments :)

/**
 * Constant-time comparison of two hex strings.
 * Prevents timing side-channel attacks by always comparing every character
 * regardless of where the first difference occurs.
 */
function constantTimeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) {
        return false;
    }
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        // eslint-disable-next-line no-bitwise
        diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return diff === 0;
}

/**
 * Convert a Montgomery u-coordinate to an Edwards point encoding (y-coordinate with sign bit = 0)
 * @param u - Montgomery u-coordinate
 * @returns Edwards point encoding
 */
export function convert_mont(u: Uint8Array): Uint8Array {
    let uBigint = Uint8ArrayToBigintLE(u)

    // 1. u_masked = u mod 2^|p|
    // |p| = ceil(log2(p)) = 255
    let u_masked = mod(uBigint, BigInt(2) ** BigInt(255));

    // 2. P.y = u_to_y(u_masked)
    // Birational map from Montgomery u to Edwards y according to RFC 7748, Section 4.1:
    const y = u_to_y(u_masked);

    // 3. P.s = 0
    // We need to construct a point with y-coordinate and sign bit = 0
    // Convert y to bytes (little-endian, 32 bytes)
    const yBytes = bigintToUint8ArrayLE(y);

    // Ensure sign bit (bit 255, MSB of byte 31) is 0
    // eslint-disable-next-line no-bitwise
    yBytes[31] &= 0x7f;

    // Return the Edwards point encoding (y-coordinate with sign bit = 0)
    return yBytes;
}

/**
 * Calculate XEdDSA key pair from X25519 private key.
 * Per the XEdDSA spec (https://signal.org/docs/specifications/xeddsa/xeddsa.pdf):
 * 1. Take the clamped X25519 private key as-is (bit 254 set, bits 0-2 cleared)
 * 2. Compute E = scalar * B on the Edwards curve
 * 3. If E's sign bit is 1, negate the scalar to produce sign bit 0
 * 4. Return the signing scalar and public key (y-coordinate with sign 0)
 *
 * @param k - Clamped X25519 private key (32 bytes)
 * @returns Object containing publicKey (y-coordinate) and privateKey (signing scalar)
 */
export function calculate_key_pair(k: Uint8Array): {
    publicKey: bigint;
    privateKey: bigint;
} {
    const kBigint = Uint8ArrayToBigintLE(k);
    const CURVE_ORDER_Q = CURVE25519_PARAMS.q;

    // Per XEdDSA spec: use the full clamped scalar for the Edwards computation.
    // Since the Ed25519 base point B has order q, k*B = (k mod q)*B mathematically.
    // We reduce here only because the library requires scalar in [1, q].
    // The sign determination and scalar derivation use the ORIGINAL key below.
    const scalarForMul = mod(kBigint, CURVE_ORDER_Q);
    const E = getBasePoint().multiply(scalarForMul);

    // Determine E.s (the sign bit of E's x-coordinate).
    // In Ed25519 encoding: y-coordinate (255 bits) + sign bit of x (1 bit).
    // eslint-disable-next-line no-bitwise
    const Es = Number(E.x & 1n); // Sign bit is the LSB of x-coordinate

    let a: bigint;
    let A: bigint;

    // Per XEdDSA spec: if sign bit is 1, negate the scalar so A has sign 0.
    // The signing scalar is derived from the ORIGINAL clamped key (not pre-reduced).
    if (Es === 1) {
        // a = -k (mod q): negate the original key's scalar
        a = mod(-kBigint, CURVE_ORDER_Q);
        const negE = E.negate();
        A = negE.y;
    } else {
        // a = k (mod q): reduce the original key for signing arithmetic
        a = mod(kBigint, CURVE_ORDER_Q);
        A = E.y;
    }

    return { publicKey: A, privateKey: a };
}

/**
 * XEdDSA Signing
 * @param k - Private key as bigint
 * @param M - Message to be signed
 * @param Z - Random data (64 bytes)
 * @returns Signature as Uint8Array (R || s)
 */
export function xeddsa_sign(k:Uint8Array, M:Uint8Array, Z:Uint8Array) {
    // 1. Calculate key pair (A, a) from k

    const keyPair = calculate_key_pair(k);
    const a = bigintToUint8ArrayLE(keyPair.privateKey);
    const A = bigintToUint8ArrayLE(keyPair.publicKey);

    // r = hash_i(a, M, Z) mod q, where hash_i uses i=1
    // hash_i returns 64 bytes, interpret as little-endian integer
    const hashResult = hash_i(concatenateUint8Arrays([a, M, Z]), 1);
    let r = Uint8ArrayToBigintLE(hashResult);
    r = mod(r, CURVE25519_PARAMS.q);

    // R = rB (point on the curve)
    const R_point = getBasePoint().multiply(r);
    const R = R_point.y;

    // h = hash(R, A, M) mod q
    // Encode R properly: y-coordinate with sign bit
    const R_encoded = bigintToUint8ArrayLE(R);
    // eslint-disable-next-line no-bitwise
    R_encoded[31] |= (Number(R_point.x & 1n) << 7); // Add sign bit of x-coordinate

    const hashInput = concatenateUint8Arrays([R_encoded, A, M]);
    const hBytes = hash(hashInput)
    let h = Uint8ArrayToBigintLE(hBytes);
    h = mod(h, CURVE25519_PARAMS.q);

    // s = (r + h*a) mod q
    const s = mod(r + h * keyPair.privateKey, CURVE25519_PARAMS.q);

    // Signature is (R || s)
    return concatenateUint8Arrays([R_encoded, bigintToUint8ArrayLE(s)]);
}

/**
 * XEdDSA Verification
 * @param u - Public key to verify
 * @param M - Signed message
 * @param Signature - Signature provided
 * @returns boolean - isValid
 */
export function xeddsa_verify(u:Uint8Array, M:Uint8Array, Signature:Uint8Array) {
    // Extract R and s from signature, convert u
    const R_encoded = Signature.slice(0, 32);
    const s_bytes = Signature.slice(32, 64);
    const s = Uint8ArrayToBigintLE(s_bytes);
    const u_converted = Uint8ArrayToBigintLE(u);

    // Extract R y-coordinate without sign bit for validation
    const R_encoded_copy = new Uint8Array(R_encoded);
    // eslint-disable-next-line no-bitwise
    R_encoded_copy[31] &= 0x7f; // Clear sign bit
    const R = Uint8ArrayToBigintLE(R_encoded_copy);

    // 1. Check if u and Signature are of correct length
    if (u_converted >= CURVE25519_PARAMS.p || R >= 2n ** BigInt(CURVE25519_PARAMS.pBits) || s >= 2n ** BigInt(CURVE25519_PARAMS.qBits)) {
        return false;
    }

    // 2. Convert Montgomery u-coordinate to Edwards point A
    const A_encoded = convert_mont(u);

    // 3. Check if points are on the curve aka. valid
    // Reconstruct points from encoded bytes
    const BASE = getBasePoint();
    let R_point;
    let A_point;
    try {
        // For Ed25519, we need to recover the full point from the encoded form
        // The encoding includes y-coordinate (255 bits) + sign bit of x (1 bit)
        const R_hex = UInt8ArrayToHexString(R_encoded);
        const A_hex = UInt8ArrayToHexString(A_encoded);
        // Convert Uint8Array to hex string for fromHex method
        R_point = ed25519.Point.fromHex(R_hex);
        A_point = ed25519.Point.fromHex(A_hex);
    } catch (e) {
        // This happens when the points are not valid
        console.error("Failed to decode points:", e);
        return false;
    }

    // 4. h = hash(R || A || M) mod q
    const hashInput = concatenateUint8Arrays([R_encoded, A_encoded, M]);
    const hBytes = hash(hashInput);
    let h = Uint8ArrayToBigintLE(hBytes);
    h = mod(h, CURVE25519_PARAMS.q);

    // 5. Verify: R_check = sB - hA
    const sB = BASE.multiply(s);
    const hA = A_point.multiply(h);
    const R_check = sB.add(hA.negate());

    // Constant-time comparison of encoded points to prevent timing side-channels.
    // Encode both points to their canonical 32-byte representations and compare.
    const R_check_hex = R_check.toHex();
    const R_point_hex = R_point.toHex();

    return constantTimeEqual(R_check_hex, R_point_hex);
}
