import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import elliptic from 'elliptic';
import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

// Set up SHA-512 for noble-ed25519
ed25519.etc.sha512Sync = (...messages) => {
    // Concatenate all input messages
    let totalLength = 0;
    for (const message of messages) {
        if (!(message instanceof Uint8Array)) {
            throw new Error('Expected Uint8Array');
        }
        totalLength += message.length;
    }
    const concatenated = new Uint8Array(totalLength);
    let offset = 0;
    for (const message of messages) {
        concatenated.set(message, offset);
        offset += message.length;
    }
    return sha512(concatenated);
};

// Initialize elliptic curve for ECDSA
const EC = elliptic.ec;
const ec = new EC('secp256k1');

// Helper function to convert string to Uint8Array
function stringToBytes(str) {
    return new TextEncoder().encode(str);
}

// Helper function to convert hex to Uint8Array
function hexToBytes(hex) {
    if (typeof hex !== 'string') {
        throw new Error('Expected string');
    }
    if (hex.length % 2) {
        hex = '0' + hex;
    }
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
    }
    return array;
}

// Helper function to convert Uint8Array to hex
function bytesToHex(bytes) {
    if (!(bytes instanceof Uint8Array)) {
        throw new Error('Expected Uint8Array');
    }
    let hex = '';
    for (const byte of bytes) {
        hex += byte.toString(16).padStart(2, '0');
    }
    return hex;
}

// Generate random private key based on scheme
async function generatePrivateKey(scheme) {
    switch (scheme) {
        case 'ecdsa': {
            const keyPair = ec.genKeyPair();
            return keyPair.getPrivate('hex');
        }
        case 'ed25519': {
            const privateBytes = ed25519.utils.randomPrivateKey();
            return bytesToHex(privateBytes);
        }
        case 'schnorr': {
            const privateBytes = secp256k1.utils.randomPrivateKey();
            return bytesToHex(privateBytes);
        }
        default:
            throw new Error('Unsupported signature scheme');
    }
}

// Generate public key based on scheme and private key
async function generatePublicKey(scheme, privateKey) {
    if (typeof privateKey !== 'string') {
        throw new Error('Private key must be a hex string');
    }
    
    switch (scheme) {
        case 'ecdsa': {
            const keyPair = ec.keyFromPrivate(privateKey, 'hex');
            return keyPair.getPublic('hex');
        }
        case 'ed25519': {
            const publicKey = await ed25519.getPublicKey(hexToBytes(privateKey));
            return bytesToHex(publicKey);
        }
        case 'schnorr': {
            const publicKey = secp256k1.getPublicKey(hexToBytes(privateKey), true);
            return bytesToHex(publicKey);
        }
        default:
            throw new Error('Unsupported signature scheme');
    }
}

// Sign message based on scheme
async function signMessage(scheme, message, privateKey) {
    if (typeof message !== 'string') {
        throw new Error('Message must be a string');
    }
    if (typeof privateKey !== 'string') {
        throw new Error('Private key must be a hex string');
    }

    const messageBytes = stringToBytes(message);
    
    switch (scheme) {
        case 'ecdsa': {
            const keyPair = ec.keyFromPrivate(privateKey, 'hex');
            const signature = keyPair.sign(messageBytes);
            return signature.toDER('hex');
        }
        case 'ed25519': {
            const signature = await ed25519.sign(messageBytes, hexToBytes(privateKey));
            return bytesToHex(signature);
        }
        case 'schnorr': {
            const messageHash = sha256(messageBytes);
            const signature = await secp256k1.schnorr.sign(messageHash, hexToBytes(privateKey));
            return bytesToHex(signature);
        }
        default:
            throw new Error('Unsupported signature scheme');
    }
}

// Verify signature based on scheme
async function verifySignature(scheme, message, signature, publicKey) {
    try {
        if (typeof message !== 'string') {
            throw new Error('Message must be a string');
        }
        if (typeof signature !== 'string') {
            throw new Error('Signature must be a hex string');
        }
        if (typeof publicKey !== 'string') {
            throw new Error('Public key must be a hex string');
        }

        const messageBytes = stringToBytes(message);
        
        switch (scheme) {
            case 'ecdsa': {
                const key = ec.keyFromPublic(publicKey, 'hex');
                return key.verify(messageBytes, signature);
            }
            case 'ed25519': {
                return await ed25519.verify(
                    hexToBytes(signature),
                    messageBytes,
                    hexToBytes(publicKey)
                );
            }
            case 'schnorr': {
                const messageHash = sha256(messageBytes);
                return await secp256k1.schnorr.verify(
                    hexToBytes(signature),
                    messageHash,
                    hexToBytes(publicKey.slice(2)) // Remove '02' or '03' prefix for x-only pubkey
                );
            }
            default:
                throw new Error('Unsupported signature scheme');
        }
    } catch (error) {
        console.error('Verification error:', error);
        return false;
    }
}

// Make libraries available globally
window.ellipticLib = elliptic;
window.nobleEd25519 = ed25519;
window.nobleSecp256k1 = secp256k1;
window.cryptoUtils = {
    generatePrivateKey,
    generatePublicKey,
    signMessage,
    verifySignature,
    hexToBytes,
    bytesToHex,
    stringToBytes
};

export {
    generatePrivateKey,
    generatePublicKey,
    signMessage,
    verifySignature
};
