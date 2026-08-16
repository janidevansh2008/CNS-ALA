// ==========================================
// SECURE MESSAGING SYSTEM
// AES-GCM + RSA-OAEP
// ==========================================

// RSA key pair
let rsaPublicKey = null;
let rsaPrivateKey = null;

// AES key generated for the current message
let aesKey = null;

// IV used by AES-GCM
let iv = null;

// Encrypted AES key
let encryptedAESKeyBuffer = null;

// Encrypted message
let encryptedMessageBuffer = null;


// ==========================================
// HELPER FUNCTIONS
// ==========================================

// Convert ArrayBuffer to Base64
function arrayBufferToBase64(buffer) {

    const bytes = new Uint8Array(buffer);

    let binary = "";

    bytes.forEach(byte => {
        binary += String.fromCharCode(byte);
    });

    return btoa(binary);
}


// Convert Base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {

    const binary = atob(base64);

    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
}


// Display bytes in hexadecimal format
function arrayBufferToHex(buffer) {

    const bytes = new Uint8Array(buffer);

    return Array.from(bytes)
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}


// Convert hexadecimal to ArrayBuffer
function hexToArrayBuffer(hex) {

    const bytes = new Uint8Array(hex.length / 2);

    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(
            hex.substr(i * 2, 2),
            16
        );
    }

    return bytes.buffer;
}


// ==========================================
// 1. RSA KEY GENERATION
// ==========================================

async function generateRSAKeys() {

    try {

        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256"
            },
            true,
            ["encrypt", "decrypt"]
        );

        rsaPublicKey = keyPair.publicKey;
        rsaPrivateKey = keyPair.privateKey;

        document.getElementById("keyStatus").textContent =
            "✓ RSA 2048-bit public/private key pair generated successfully.";

    } catch (error) {

        console.error(error);

        document.getElementById("keyStatus").textContent =
            "Error generating RSA keys.";
    }
}


// ==========================================
// 2. ENCRYPT MESSAGE
// ==========================================

async function encryptMessage() {

    try {

        // Check RSA keys
        if (!rsaPublicKey) {

            alert("Please generate RSA keys first.");

            return;
        }

        const message =
            document.getElementById("messageInput").value.trim();

        if (!message) {

            alert("Please enter a message.");

            return;
        }


        // --------------------------------------
        // Generate AES-256 key
        // --------------------------------------

        aesKey = await window.crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );


        // --------------------------------------
        // Generate random IV
        // --------------------------------------

        iv = window.crypto.getRandomValues(
            new Uint8Array(12)
        );


        // --------------------------------------
        // Convert message to bytes
        // --------------------------------------

        const encoder = new TextEncoder();

        const messageData =
            encoder.encode(message);


        // --------------------------------------
        // AES-GCM encryption
        // --------------------------------------

        encryptedMessageBuffer =
            await window.crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                aesKey,
                messageData
            );


        // --------------------------------------
        // Export AES key
        // --------------------------------------

        const rawAESKey =
            await window.crypto.subtle.exportKey(
                "raw",
                aesKey
            );


        // --------------------------------------
        // RSA encrypt AES key
        // --------------------------------------

        encryptedAESKeyBuffer =
            await window.crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP"
                },
                rsaPublicKey,
                rawAESKey
            );


        // --------------------------------------
        // Display results
        // --------------------------------------

        document.getElementById("originalMessage").value =
            message;

        document.getElementById("aesKeyOutput").value =
            arrayBufferToBase64(rawAESKey);

        document.getElementById("encryptedMessage").value =
            "IV: " +
            arrayBufferToBase64(iv.buffer) +
            "\n\nCiphertext:\n" +
            arrayBufferToBase64(encryptedMessageBuffer);

        document.getElementById("encryptedAESKey").value =
            arrayBufferToBase64(encryptedAESKeyBuffer);


        // Clear old decrypted output
        document.getElementById("decryptedAESKey").value = "";

        document.getElementById("decryptedMessage").value = "";


        alert("Message encrypted successfully!");

    } catch (error) {

        console.error(error);

        alert(
            "Encryption failed. Check the browser console for details."
        );
    }
}


// ==========================================
// 3. DECRYPT MESSAGE
// ==========================================

async function decryptMessage() {

    try {

        // Check keys
        if (!rsaPrivateKey) {

            alert("RSA private key is not available.");

            return;
        }

        // Check encrypted data
        if (
            !encryptedAESKeyBuffer ||
            !encryptedMessageBuffer ||
            !iv
        ) {

            alert("Please encrypt a message first.");

            return;
        }


        // --------------------------------------
        // RSA decrypt AES key
        // --------------------------------------

        const decryptedAESKeyBuffer =
            await window.crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP"
                },
                rsaPrivateKey,
                encryptedAESKeyBuffer
            );


        // --------------------------------------
        // Import recovered AES key
        // --------------------------------------

        const recoveredAESKey =
            await window.crypto.subtle.importKey(
                "raw",
                decryptedAESKeyBuffer,
                {
                    name: "AES-GCM"
                },
                false,
                ["decrypt"]
            );


        // --------------------------------------
        // AES decrypt message
        // --------------------------------------

        const decryptedMessageBuffer =
            await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                recoveredAESKey,
                encryptedMessageBuffer
            );


        // --------------------------------------
        // Convert bytes to text
        // --------------------------------------

        const decoder = new TextDecoder();

        const decryptedMessage =
            decoder.decode(decryptedMessageBuffer);


        // --------------------------------------
        // Display results
        // --------------------------------------

        document.getElementById("decryptedAESKey").value =
            arrayBufferToBase64(
                decryptedAESKeyBuffer
            );

        document.getElementById("decryptedMessage").value =
            decryptedMessage;


        alert("Message decrypted successfully!");

    } catch (error) {

        console.error(error);

        alert(
            "Decryption failed. The encrypted data may be invalid."
        );
    }
}


// ==========================================
// BUTTON EVENTS
// ==========================================

document
    .getElementById("generateKeysBtn")
    .addEventListener(
        "click",
        generateRSAKeys
    );


document
    .getElementById("encryptBtn")
    .addEventListener(
        "click",
        encryptMessage
    );


document
    .getElementById("decryptBtn")
    .addEventListener(
        "click",
        decryptMessage
    );