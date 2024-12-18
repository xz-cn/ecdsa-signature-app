// Import libraries
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import * as elliptic from 'elliptic';

// Set up SHA-512 for noble-ed25519
ed25519.etc.sha512Sync = (...messages) => {
    // Convert all inputs to Uint8Arrays and concatenate
    const arrays = messages.map(msg => {
        if (typeof msg === 'string') {
            return new TextEncoder().encode(msg);
        }
        if (msg instanceof Uint8Array) {
            return msg;
        }
        throw new Error('Invalid message type');
    });

    // Concatenate all arrays
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const concatenated = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        concatenated.set(arr, offset);
        offset += arr.length;
    }

    // Use noble-hashes sha512
    return sha512(concatenated);
};

// Make libraries available globally
window.nobleEd25519 = ed25519;
window.elliptic = elliptic;
