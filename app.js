// Initialize signature schemes
const ec = new elliptic.ec('secp256k1');

// DOM elements
const signatureSchemeSelect = document.getElementById('signatureScheme');
const signButton = document.getElementById('signButton');
const verifyButton = document.getElementById('verifyButton');
const copySignatureButton = document.getElementById('copySignature');
const copyPrivateKeyButton = document.getElementById('copyPrivateKey');
const copyPublicKeyButton = document.getElementById('copyPublicKey');
const generateNewKeyButton = document.getElementById('generateNewKey');
const messageInput = document.getElementById('message');
const signatureOutput = document.getElementById('signature');
const signatureToVerifyInput = document.getElementById('signatureToVerify');
const verificationResultOutput = document.getElementById('verificationResult');
const privateKeyOutput = document.getElementById('privateKey');
const publicKeyOutput = document.getElementById('publicKey');

// Current key pair and scheme
let currentKeyPair = null;
let currentScheme = 'ecdsa';

// Utility functions
function buf2hex(buffer) {
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

function hex2buf(hex) {
    return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

// Signature scheme implementations
const signatureSchemes = {
    ecdsa: {
        async generateKeyPair() {
            const keyPair = ec.genKeyPair();
            return {
                privateKey: keyPair.getPrivate('hex'),
                publicKey: keyPair.getPublic('hex'),
                keyPair
            };
        },
        async sign(message, keyPair) {
            const msgHash = await window.nobleSecp256k1.utils.sha256(message);
            const signature = keyPair.keyPair.sign(msgHash);
            return signature.toDER('hex');
        },
        async verify(message, signature, keyPair) {
            try {
                const msgHash = await window.nobleSecp256k1.utils.sha256(message);
                return keyPair.keyPair.verify(msgHash, signature);
            } catch (error) {
                return false;
            }
        }
    },
    ed25519: {
        async generateKeyPair() {
            const privateKey = window.ed25519.utils.randomPrivateKey();
            const publicKey = await window.ed25519.getPublicKey(privateKey);
            return {
                privateKey: buf2hex(privateKey),
                publicKey: buf2hex(publicKey),
                keyPair: { privateKey, publicKey }
            };
        },
        async sign(message, keyPair) {
            const signature = await window.ed25519.sign(
                new TextEncoder().encode(message),
                hex2buf(keyPair.privateKey)
            );
            return buf2hex(signature);
        },
        async verify(message, signature, keyPair) {
            try {
                return await window.ed25519.verify(
                    hex2buf(signature),
                    new TextEncoder().encode(message),
                    hex2buf(keyPair.publicKey)
                );
            } catch (error) {
                return false;
            }
        }
    },
    schnorr: {
        async generateKeyPair() {
            const privateKey = window.nobleSecp256k1.utils.randomPrivateKey();
            const publicKey = await window.nobleSecp256k1.getPublicKey(privateKey);
            return {
                privateKey: buf2hex(privateKey),
                publicKey: buf2hex(publicKey),
                keyPair: { privateKey, publicKey }
            };
        },
        async sign(message, keyPair) {
            const signature = await window.nobleSecp256k1.schnorr.sign(
                new TextEncoder().encode(message),
                hex2buf(keyPair.privateKey)
            );
            return buf2hex(signature);
        },
        async verify(message, signature, keyPair) {
            try {
                return await window.nobleSecp256k1.schnorr.verify(
                    hex2buf(signature),
                    new TextEncoder().encode(message),
                    hex2buf(keyPair.publicKey)
                );
            } catch (error) {
                return false;
            }
        }
    }
};

// Function to generate new key pair and update UI
async function generateNewKeyPair() {
    try {
        currentKeyPair = await signatureSchemes[currentScheme].generateKeyPair();
        privateKeyOutput.value = currentKeyPair.privateKey;
        publicKeyOutput.value = currentKeyPair.publicKey;
        // Clear previous signatures
        signatureOutput.value = '';
        signatureToVerifyInput.value = '';
        verificationResultOutput.innerHTML = '';
    } catch (error) {
        alert('Error generating key pair: ' + error.message);
    }
}

// Generic copy function
async function copyToClipboard(text, button) {
    try {
        await navigator.clipboard.writeText(text);
        const originalHtml = button.innerHTML;
        button.innerHTML = '<i class="fas fa-check"></i>';
        setTimeout(() => {
            button.innerHTML = originalHtml;
        }, 2000);
    } catch (error) {
        alert('Failed to copy: ' + error.message);
    }
}

// Event Listeners
signatureSchemeSelect.addEventListener('change', (e) => {
    currentScheme = e.target.value;
    generateNewKeyPair();
});

signButton.addEventListener('click', async () => {
    try {
        const msg = messageInput.value;
        if (!msg) {
            alert('Please enter a message to sign');
            return;
        }
        const signature = await signatureSchemes[currentScheme].sign(msg, currentKeyPair);
        signatureOutput.value = signature;
    } catch (error) {
        alert('Error signing message: ' + error.message);
    }
});

verifyButton.addEventListener('click', async () => {
    try {
        const msg = messageInput.value;
        const signatureHex = signatureToVerifyInput.value;
        
        if (!msg || !signatureHex) {
            alert('Please enter both message and signature');
            return;
        }

        const isValid = await signatureSchemes[currentScheme].verify(msg, signatureHex, currentKeyPair);
        verificationResultOutput.className = 'verification-result ' + (isValid ? 'valid' : 'invalid');
        verificationResultOutput.innerHTML = isValid 
            ? '<i class="fas fa-check-circle"></i> Valid Signature'
            : '<i class="fas fa-times-circle"></i> Invalid Signature';
    } catch (error) {
        verificationResultOutput.className = 'verification-result invalid';
        verificationResultOutput.innerHTML = '<i class="fas fa-exclamation-circle"></i> Invalid Signature Format';
    }
});

// Copy button handlers
copySignatureButton.addEventListener('click', () => {
    copyToClipboard(signatureOutput.value, copySignatureButton);
});

copyPrivateKeyButton.addEventListener('click', () => {
    copyToClipboard(privateKeyOutput.value, copyPrivateKeyButton);
});

copyPublicKeyButton.addEventListener('click', () => {
    copyToClipboard(publicKeyOutput.value, copyPublicKeyButton);
});

// Generate new key pair
generateNewKeyButton.addEventListener('click', generateNewKeyPair);

// Initialize with default key pair
generateNewKeyPair();
