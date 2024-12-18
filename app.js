// Global variables for cryptographic operations
let ec = null;

// Initialize libraries
async function initializeLibraries() {
    return new Promise((resolve, reject) => {
        console.log('Checking library initialization...');
        console.log('Elliptic available:', !!window.elliptic);
        console.log('Noble-ed25519 available:', !!window.nobleEd25519);
        
        // Check if libraries are available
        if (!window.elliptic) {
            reject(new Error('Elliptic library not loaded'));
            return;
        }
        
        if (!window.nobleEd25519) {
            // Try alternative global names
            if (typeof ed25519 !== 'undefined') {
                console.log('Found ed25519 global, using it...');
                window.nobleEd25519 = ed25519;
            } else {
                reject(new Error('Noble-ed25519 library not loaded'));
                return;
            }
        }

        try {
            // Initialize elliptic curve
            ec = new window.elliptic.ec('secp256k1');
            console.log('Successfully initialized elliptic curve');
            
            // Verify noble-ed25519 is working
            if (typeof window.nobleEd25519.getPublicKey !== 'function') {
                reject(new Error('Noble-ed25519 library is not properly initialized'));
                return;
            }
            
            resolve();
        } catch (error) {
            reject(new Error('Failed to initialize elliptic curve: ' + error.message));
        }
    });
}

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
let currentScheme = 'ecdsa';
let keyPair = null;

// Helper functions
function hexToUint8Array(hex) {
    if (!hex) return new Uint8Array(0);
    return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

function uint8ArrayToHex(uint8Array) {
    return Array.from(uint8Array)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}

// Function to generate random bytes for Ed25519
function getRandomBytes(length) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return array;
}

// Function to generate new key pair based on selected scheme
async function generateNewKeyPair() {
    if (!ec) {
        console.error('Cryptographic libraries not initialized');
        await initializeApp();
    }

    const scheme = signatureSchemeSelect.value;
    currentScheme = scheme;

    try {
        if (scheme === 'ecdsa') {
            keyPair = ec.genKeyPair();
            privateKeyOutput.value = keyPair.getPrivate('hex');
            publicKeyOutput.value = keyPair.getPublic('hex');
        } else if (scheme === 'ed25519') {
            const privateKeyBytes = getRandomBytes(32);
            const publicKeyBytes = await window.nobleEd25519.getPublicKey(privateKeyBytes);
            keyPair = {
                privateKey: privateKeyBytes,
                publicKey: publicKeyBytes
            };
            privateKeyOutput.value = uint8ArrayToHex(privateKeyBytes);
            publicKeyOutput.value = uint8ArrayToHex(publicKeyBytes);
        }

        // Clear previous signatures
        signatureOutput.value = '';
        signatureToVerifyInput.value = '';
        verificationResultOutput.innerHTML = '';
    } catch (error) {
        console.error('Error generating key pair:', error);
        alert('Error generating key pair: ' + error.message);
    }
}

// Initialize the app
async function initializeApp() {
    try {
        await initializeLibraries();
        console.log('Libraries initialized successfully');
        await generateNewKeyPair();
        console.log('Initial key pair generated');
    } catch (error) {
        console.error('Failed to initialize app:', error);
        alert('Failed to initialize app: ' + error.message);
    }
}

// Start initialization when DOM is loaded
document.addEventListener('DOMContentLoaded', initializeApp);

// Handle scheme change
signatureSchemeSelect.addEventListener('change', generateNewKeyPair);

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

// Sign message
signButton.addEventListener('click', async () => {
    if (!keyPair) {
        alert('Please wait for key pair generation');
        return;
    }

    try {
        const msg = messageInput.value;
        if (!msg) {
            alert('Please enter a message to sign');
            return;
        }

        let signature;
        if (currentScheme === 'ecdsa') {
            signature = keyPair.sign(msg);
            signatureOutput.value = signature.toDER('hex');
        } else if (currentScheme === 'ed25519') {
            const messageBytes = new TextEncoder().encode(msg);
            const signatureBytes = await window.nobleEd25519.sign(messageBytes, keyPair.privateKey);
            signatureOutput.value = uint8ArrayToHex(signatureBytes);
        }
    } catch (error) {
        console.error('Error signing message:', error);
        alert('Error signing message: ' + error.message);
    }
});

// Copy handlers
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

// Verify signature
verifyButton.addEventListener('click', async () => {
    if (!keyPair) {
        alert('Please wait for key pair generation');
        return;
    }

    try {
        const msg = messageInput.value;
        const signatureHex = signatureToVerifyInput.value;
        
        if (!msg || !signatureHex) {
            alert('Please enter both message and signature');
            return;
        }

        let isValid;
        if (currentScheme === 'ecdsa') {
            isValid = keyPair.verify(msg, signatureHex);
        } else if (currentScheme === 'ed25519') {
            const messageBytes = new TextEncoder().encode(msg);
            const signatureBytes = hexToUint8Array(signatureHex);
            isValid = await window.nobleEd25519.verify(signatureBytes, messageBytes, keyPair.publicKey);
        }

        verificationResultOutput.className = 'verification-result ' + (isValid ? 'valid' : 'invalid');
        verificationResultOutput.innerHTML = isValid 
            ? '<i class="fas fa-check-circle"></i> Valid Signature'
            : '<i class="fas fa-times-circle"></i> Invalid Signature';
    } catch (error) {
        console.error('Error verifying signature:', error);
        verificationResultOutput.className = 'verification-result invalid';
        verificationResultOutput.innerHTML = '<i class="fas fa-exclamation-circle"></i> Invalid Signature Format';
    }
});
