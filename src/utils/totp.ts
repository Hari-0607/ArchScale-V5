import crypto from 'crypto';

/**
 * Pure Node.js TOTP (RFC 6238 / RFC 4226) implementation using built-in crypto.
 * No external dependencies needed.
 */
function base32Decode(base32: string): Buffer {
    const cleaned = base32.toUpperCase().replace(/=+$/, '');
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0;
    let value = 0;
    const output: number[] = [];

    for (let i = 0; i < cleaned.length; i++) {
        const idx = alphabet.indexOf(cleaned[i]);
        if (idx === -1) continue;
        value = (value << 5) | idx;
        bits += 5;

        if (bits >= 8) {
            output.push((value >>> (bits - 8)) & 255);
            bits -= 8;
        }
    }

    return Buffer.from(output);
}

export function generateTotpCode(secret: string, timestampSeconds: number = Math.floor(Date.now() / 1000), timeStep: number = 30): string {
    const key = base32Decode(secret);
    const counter = Math.floor(timestampSeconds / timeStep);

    const buf = Buffer.alloc(8);
    buf.writeBigUInt64BE(BigInt(counter), 0);

    const hmac = crypto.createHmac('sha1', key).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0xf;
    const binary =
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);

    const otp = (binary % 1_000_000).toString();
    return otp.padStart(6, '0');
}
