/**
 * CYBERTOOLKIT // Web Crypto API Studio (AES-256-GCM & Hashing)
 * 100% Client-Side Native Web Crypto API
 */

document.addEventListener('DOMContentLoaded', () => {
    initCryptoFormListeners();
});

function initCryptoFormListeners() {
    const encForm = document.getElementById('crypto-encrypt-form');
    const decForm = document.getElementById('crypto-decrypt-form');
    const hashForm = document.getElementById('crypto-hash-form');

    if (encForm) encForm.addEventListener('submit', handleEncryptSubmit);
    if (decForm) decForm.addEventListener('submit', handleDecryptSubmit);
    if (hashForm) hashForm.addEventListener('submit', handleHashSubmit);
}

/**
 * Derives an AES-256 Key from a passphrase and salt using PBKDF2
 */
async function deriveKey(passphrase, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(passphrase),
        'PBKDF2',
        false,
        ['deriveKey']
    );

    return await window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

/**
 * Handles Text Encryption using AES-256-GCM
 */
async function handleEncryptSubmit(e) {
    e.preventDefault();

    const textInput = document.getElementById('enc-plaintext');
    const keyInput = document.getElementById('enc-passphrase');
    const resultBox = document.getElementById('enc-result-output');

    const plaintext = textInput.value;
    const passphrase = keyInput.value;

    if (!plaintext || !passphrase) return;

    try {
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        const key = await deriveKey(passphrase, salt);
        const enc = new TextEncoder();

        const ciphertextBuffer = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            enc.encode(plaintext)
        );

        // Package Salt + IV + Ciphertext into a single array
        const combined = new Uint8Array(salt.length + iv.length + ciphertextBuffer.byteLength);
        combined.set(salt, 0);
        combined.set(iv, salt.length);
        combined.set(new Uint8Array(ciphertextBuffer), salt.length + iv.length);

        // Convert to Base64
        const base64Str = btoa(String.fromCharCode(...combined));

        resultBox.value = base64Str;
        logToTerminal('Texto cifrado exitosamente con AES-256-GCM.', 'success');

    } catch (err) {
        console.error('Encryption error:', err);
        logToTerminal(`Error al cifrar: ${err.message}`, 'error');
        alert('Error en cifrado AES-256: ' + err.message);
    }
}

/**
 * Handles Text Decryption using AES-256-GCM
 */
async function handleDecryptSubmit(e) {
    e.preventDefault();

    const cipherInput = document.getElementById('dec-ciphertext');
    const keyInput = document.getElementById('dec-passphrase');
    const resultBox = document.getElementById('dec-result-output');

    const base64Str = cipherInput.value.trim();
    const passphrase = keyInput.value;

    if (!base64Str || !passphrase) return;

    try {
        const combined = Uint8Array.from(atob(base64Str), c => c.charCodeAt(0));

        if (combined.length < 28) {
            throw new Error('El texto cifrado no tiene la longitud o formato válido.');
        }

        const salt = combined.slice(0, 16);
        const iv = combined.slice(16, 28);
        const ciphertext = combined.slice(28);

        const key = await deriveKey(passphrase, salt);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            ciphertext
        );

        const dec = new TextDecoder();
        const decryptedText = dec.decode(decryptedBuffer);

        resultBox.value = decryptedText;
        logToTerminal('Texto descifrado exitosamente con AES-256-GCM.', 'success');

    } catch (err) {
        console.error('Decryption error:', err);
        logToTerminal('Error al descifrar: Contraseña incorrecta o datos corruptos.', 'error');
        alert('Error al descifrar: Verifica la contraseña clave.');
    }
}

/**
 * Handles SHA-256 / SHA-512 Hashing
 */
async function handleHashSubmit(e) {
    e.preventDefault();

    const textInput = document.getElementById('hash-input-text');
    const algoSelect = document.getElementById('hash-algo');
    const sha256Box = document.getElementById('hash-sha256-val');
    const sha512Box = document.getElementById('hash-sha512-val');

    const text = textInput.value;
    if (!text) return;

    try {
        const enc = new TextEncoder();
        const data = enc.encode(text);

        // SHA-256
        const hash256Buffer = await window.crypto.subtle.digest('SHA-256', data);
        const hash256Hex = Array.from(new Uint8Array(hash256Buffer))
            .map(b => b.toString(16).padStart(2, '0')).join('');

        // SHA-512
        const hash512Buffer = await window.crypto.subtle.digest('SHA-512', data);
        const hash512Hex = Array.from(new Uint8Array(hash512Buffer))
            .map(b => b.toString(16).padStart(2, '0')).join('');

        sha256Box.textContent = hash256Hex;
        sha512Box.textContent = hash512Hex;

        logToTerminal(`Hashes SHA-256 y SHA-512 generados para el texto ingresado (${text.length} caracteres).`, 'success');

    } catch (err) {
        console.error('Hashing error:', err);
        logToTerminal(`Error al calcular hash: ${err.message}`, 'error');
    }
}
