/**
 * CYBERTOOLKIT // Password Entropy & Vault Analyzer Module
 */

document.addEventListener('DOMContentLoaded', () => {
    initPasswordListeners();
});

function initPasswordListeners() {
    const pwdInput = document.getElementById('pwd-test-input');
    const btnGen = document.getElementById('btn-gen-pwd');

    if (pwdInput) {
        pwdInput.addEventListener('input', analyzePasswordEntropy);
    }

    if (btnGen) {
        btnGen.addEventListener('click', generateCyberPassword);
    }
}

/**
 * Calculates entropy in bits and crack time estimation
 */
function analyzePasswordEntropy() {
    const pwdInput = document.getElementById('pwd-test-input');
    const entropyVal = document.getElementById('pwd-entropy-bits');
    const crackTimeVal = document.getElementById('pwd-crack-time');
    const scoreBar = document.getElementById('pwd-score-bar');
    const statusTag = document.getElementById('pwd-status-tag');
    const warningsBox = document.getElementById('pwd-warnings');

    const password = pwdInput.value;
    if (!password) {
        entropyVal.textContent = '0 bits';
        crackTimeVal.textContent = '0 segundos';
        scoreBar.style.width = '0%';
        statusTag.textContent = 'EN ESPERA';
        statusTag.className = 'port-status status-closed';
        warningsBox.innerHTML = '';
        return;
    }

    let charsetSize = 0;
    if (/[a-z]/.test(password)) charsetSize += 26;
    if (/[A-Z]/.test(password)) charsetSize += 26;
    if (/[0-9]/.test(password)) charsetSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 33;

    if (charsetSize === 0) charsetSize = 1;

    // Entropy = length * log2(charsetSize)
    const entropy = Math.round(password.length * Math.log2(charsetSize));

    // Crack time estimation (assuming 10 billion attempts/sec on fast GPU)
    const possibleCombinations = Math.pow(charsetSize, password.length);
    const secondsToCrack = possibleCombinations / (10 * 1000 * 1000 * 1000);

    entropyVal.textContent = `${entropy} bits`;
    crackTimeVal.textContent = formatCrackTime(secondsToCrack);

    // Score classification
    let percent = Math.min(100, Math.round((entropy / 128) * 100));
    scoreBar.style.width = `${percent}%`;

    let warnings = [];
    if (password.length < 10) warnings.push('Demasiado corta (menos de 10 caracteres).');
    if (!/[A-Z]/.test(password)) warnings.push('Falta al menos una mayúscula.');
    if (!/[0-9]/.test(password)) warnings.push('Falta al menos un número.');
    if (!/[^a-zA-Z0-9]/.test(password)) warnings.push('Falta al menos un símbolo especial (!@#$).');
    if (/(123|qwerty|admin|password|abc)/i.test(password)) warnings.push('Contiene patrones comunes o secuenciales.');

    if (entropy < 40) {
        statusTag.textContent = 'DEBIL';
        statusTag.className = 'port-status status-closed';
        scoreBar.style.background = 'var(--neon-red)';
    } else if (entropy < 80) {
        statusTag.textContent = 'MODERADA';
        statusTag.className = 'port-status status-filtered';
        scoreBar.style.background = 'var(--neon-orange)';
    } else {
        statusTag.textContent = 'FUERTE';
        statusTag.className = 'port-status status-open';
        scoreBar.style.background = 'var(--neon-green)';
    }

    if (warnings.length > 0) {
        warningsBox.innerHTML = warnings.map(w => `<div style="font-size:0.75rem; color:var(--neon-orange);"><i class="fa-solid fa-triangle-exclamation"></i> ${w}</div>`).join('');
    } else {
        warningsBox.innerHTML = '<div style="font-size:0.75rem; color:var(--neon-green);"><i class="fa-solid fa-shield-check"></i> Excelente variedad de caracteres y entropía.</div>';
    }
}

/**
 * Formats time duration into human readable string
 */
function formatCrackTime(seconds) {
    if (seconds < 1) return 'Instantáneo (< 1 seg)';
    if (seconds < 60) return `${Math.round(seconds)} segundos`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutos`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} horas`;
    if (seconds < 31536000) return `${Math.round(seconds / 86400)} días`;
    if (seconds < 31536000 * 100) return `${Math.round(seconds / 31536000)} años`;
    if (seconds < 31536000 * 1000000) return `${(seconds / 31536000).toExponential(1)} años`;
    return 'Siglos / Incalculable';
}

/**
 * Generates a strong random password using Web Crypto CSPRNG
 */
function generateCyberPassword() {
    const lengthInput = document.getElementById('pwd-gen-length');
    const length = parseInt(lengthInput ? lengthInput.value : 20, 10) || 20;

    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    const allChars = lower + upper + numbers + symbols;

    const randomValues = new Uint32Array(length);
    window.crypto.getRandomValues(randomValues);

    let password = '';
    // Ensure at least 1 of each category
    password += lower[randomValues[0] % lower.length];
    password += upper[randomValues[1] % upper.length];
    password += numbers[randomValues[2] % numbers.length];
    password += symbols[randomValues[3] % symbols.length];

    for (let i = 4; i < length; i++) {
        password += allChars[randomValues[i] % allChars.length];
    }

    // Shuffle password
    const arr = password.split('');
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    const finalPassword = arr.join('');

    const testInput = document.getElementById('pwd-test-input');
    if (testInput) {
        testInput.value = finalPassword;
        analyzePasswordEntropy();
    }

    logToTerminal(`Nueva contraseña de ${length} caracteres generada con CSPRNG.`, 'success');
}
