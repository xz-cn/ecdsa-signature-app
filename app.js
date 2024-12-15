// Initialize elliptic curve
const ec = new elliptic.ec('secp256k1');

// DOM elements
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

// Current key pair
let keyPair = null;

// Function to generate new key pair and update UI
function generateNewKeyPair() {
    keyPair = ec.genKeyPair();
    privateKeyOutput.value = keyPair.getPrivate('hex');
    publicKeyOutput.value = keyPair.getPublic('hex');
    // Clear previous signatures
    signatureOutput.value = '';
    signatureToVerifyInput.value = '';
    verificationResultOutput.innerHTML = '';
}

// Initialize with a new key pair
generateNewKeyPair();

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
signButton.addEventListener('click', () => {
    try {
        const msg = messageInput.value;
        if (!msg) {
            alert('Please enter a message to sign');
            return;
        }
        const signature = keyPair.sign(msg);
        signatureOutput.value = signature.toDER('hex');
    } catch (error) {
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
verifyButton.addEventListener('click', () => {
    try {
        const msg = messageInput.value;
        const signatureHex = signatureToVerifyInput.value;
        
        if (!msg || !signatureHex) {
            alert('Please enter both message and signature');
            return;
        }

        const isValid = keyPair.verify(msg, signatureHex);
        verificationResultOutput.className = 'verification-result ' + (isValid ? 'valid' : 'invalid');
        verificationResultOutput.innerHTML = isValid 
            ? '<i class="fas fa-check-circle"></i> Valid Signature'
            : '<i class="fas fa-times-circle"></i> Invalid Signature';
    } catch (error) {
        verificationResultOutput.className = 'verification-result invalid';
        verificationResultOutput.innerHTML = '<i class="fas fa-exclamation-circle"></i> Invalid Signature Format';
    }
});
