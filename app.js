// Global variables for cryptographic operations
let ec = null;

// Initialize libraries
async function initializeLibraries() {
    return new Promise((resolve, reject) => {
        console.log('Checking library initialization...');
        console.log('Elliptic available:', !!window.ellipticLib);
        console.log('Noble-ed25519 available:', !!window.nobleEd25519);
        console.log('Noble-secp256k1 available:', !!window.nobleSecp256k1);
        console.log('CryptoUtils available:', !!window.cryptoUtils);
        
        // Check if libraries are available
        if (!window.ellipticLib) {
            reject(new Error('Elliptic library not loaded'));
            return;
        }
        
        if (!window.nobleEd25519) {
            reject(new Error('Noble-ed25519 library not loaded'));
            return;
        }

        if (!window.nobleSecp256k1) {
            reject(new Error('Noble-secp256k1 library not loaded'));
            return;
        }

        if (!window.cryptoUtils) {
            reject(new Error('CryptoUtils not loaded'));
            return;
        }

        try {
            // Initialize elliptic curve
            ec = new window.ellipticLib.ec('secp256k1');
            console.log('Successfully initialized elliptic curve');
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
const generateNewKeyButton = document.getElementById('generateNewKey');
const copySignatureButton = document.getElementById('copySignature');
const copyPrivateKeyButton = document.getElementById('copyPrivateKey');
const copyPublicKeyButton = document.getElementById('copyPublicKey');
const messageInput = document.getElementById('message');
const privateKeyDisplay = document.getElementById('privateKey');
const publicKeyDisplay = document.getElementById('publicKey');
const signatureDisplay = document.getElementById('signature');
const signatureToVerifyInput = document.getElementById('signatureToVerify');
const verificationResult = document.getElementById('verificationResult');

// Global key pair
let keyPair = null;

// Function to generate new key pair based on selected scheme
async function generateNewKeyPair() {
    const scheme = signatureSchemeSelect.value;
    try {
        const privateKey = await window.cryptoUtils.generatePrivateKey(scheme);
        const publicKey = await window.cryptoUtils.generatePublicKey(scheme, privateKey);
        
        keyPair = { privateKey, publicKey };
        privateKeyDisplay.value = privateKey;
        publicKeyDisplay.value = publicKey;
        
        console.log(`Generated new ${scheme.toUpperCase()} key pair`);
    } catch (error) {
        console.error('Error generating key pair:', error);
        alert('Failed to generate key pair: ' + error.message);
    }
}

// Initialize the app
async function initializeApp() {
    try {
        await initializeLibraries();
        console.log('Libraries initialized successfully');
        await generateNewKeyPair();
    } catch (error) {
        console.error('Failed to initialize app:', error);
        alert('Failed to initialize app: ' + error.message);
    }
}

// Start initialization when DOM is loaded
document.addEventListener('DOMContentLoaded', initializeApp);

// Handle scheme change
signatureSchemeSelect.addEventListener('change', generateNewKeyPair);

// Handle generate new key pair button click
generateNewKeyButton.addEventListener('click', generateNewKeyPair);

// Generic copy function
function copyToClipboard(text, button) {
    navigator.clipboard.writeText(text).then(() => {
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        setTimeout(() => {
            button.textContent = originalText;
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy:', err);
        alert('Failed to copy to clipboard');
    });
}

// Sign message
signButton.addEventListener('click', async () => {
    if (!keyPair) {
        alert('Please wait for key pair generation');
        return;
    }

    const message = messageInput.value;
    if (!message) {
        alert('Please enter a message to sign');
        return;
    }

    try {
        const scheme = signatureSchemeSelect.value;
        const signature = await window.cryptoUtils.signMessage(scheme, message, keyPair.privateKey);
        signatureDisplay.value = signature;
        signatureToVerifyInput.value = signature; // Auto-fill the verification input
        console.log(`Message signed with ${scheme.toUpperCase()}`);
    } catch (error) {
        console.error('Error signing message:', error);
        alert('Failed to sign message: ' + error.message);
    }
});

// Verify signature
verifyButton.addEventListener('click', async () => {
    const signature = signatureToVerifyInput.value; // Use the verification input field
    const message = messageInput.value;
    const publicKey = publicKeyDisplay.value;

    if (!signature || !message || !publicKey) {
        alert('Please ensure all fields are filled');
        return;
    }

    try {
        const scheme = signatureSchemeSelect.value;
        const isValid = await window.cryptoUtils.verifySignature(scheme, message, signature, publicKey);
        
        verificationResult.innerHTML = isValid 
            ? '<i class="fas fa-check-circle"></i> Signature Valid' 
            : '<i class="fas fa-times-circle"></i> Signature Invalid';
        verificationResult.className = isValid ? 'verification-result valid' : 'verification-result invalid';
    } catch (error) {
        console.error('Error verifying signature:', error);
        alert('Failed to verify signature: ' + error.message);
        verificationResult.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Verification Error';
        verificationResult.className = 'verification-result error';
    }
});

// Copy buttons
copyPrivateKeyButton.addEventListener('click', () => {
    copyToClipboard(privateKeyDisplay.value, copyPrivateKeyButton);
});

copyPublicKeyButton.addEventListener('click', () => {
    copyToClipboard(publicKeyDisplay.value, copyPublicKeyButton);
});

copySignatureButton.addEventListener('click', () => {
    copyToClipboard(signatureDisplay.value, copySignatureButton);
});
