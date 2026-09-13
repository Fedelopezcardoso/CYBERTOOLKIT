/**
 * CYBERTOOLKIT // Client-Side Web Port Scanner Module
 * Uses HTTP/HTTPS fetch timing and protocol probe analysis.
 */

document.addEventListener('DOMContentLoaded', () => {
    const scannerForm = document.getElementById('scanner-form');
    if (scannerForm) {
        scannerForm.addEventListener('submit', handleScannerSubmit);
    }
});

// Common Port Definitions & Services
const PORT_SERVICES = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    25: "SMTP (Mail)",
    53: "DNS (Domain Name Service)",
    80: "HTTP (Web Server)",
    110: "POP3 (Mail)",
    135: "RPC (Remote Procedure Call)",
    139: "NetBIOS",
    143: "IMAP (Mail)",
    443: "HTTPS (Secure Web)",
    445: "SMB (File Sharing)",
    1433: "MSSQL (Database)",
    3000: "Dev App Server (Node/React)",
    3306: "MySQL (Database)",
    3389: "RDP (Remote Desktop)",
    5000: "Flask / Dev App Server",
    5432: "PostgreSQL (Database)",
    6379: "Redis (In-Memory DB)",
    8000: "HTTP Dev Server / FastAPI",
    8080: "HTTP Alt Server",
    8443: "HTTPS Alt Server",
    27017: "MongoDB (Database)"
};

const PRESET_COMMON = [80, 443, 8080, 8443, 21, 22, 3000, 5000, 8000];
const PRESET_DATABASES = [3306, 5432, 27017, 6379, 1433, 135, 445];

let isScanning = false;

/**
 * Handles Port Scanner Form Submission
 */
async function handleScannerSubmit(e) {
    e.preventDefault();

    if (isScanning) {
        alert('Ya hay un escaneo en curso. Por favor espera a que finalice.');
        return;
    }

    const targetInput = document.getElementById('scan-target');
    const presetRadio = document.querySelector('input[name="port-preset"]:checked');
    const customPortsInput = document.getElementById('custom-ports');
    const timeoutInput = document.getElementById('scan-timeout');

    const resultsList = document.getElementById('scan-results-list');
    const progressBox = document.getElementById('scan-progress-box');
    const progressBar = document.getElementById('scan-progress-bar');
    const statusText = document.getElementById('scan-status-text');
    const percentageText = document.getElementById('scan-percentage');
    const btnStart = document.getElementById('btn-start-scan');

    let target = targetInput.value.trim();
    if (!target) return;

    // Clean domain or IP
    target = target.replace(/^https?:\/\//i, '').replace(/\/.*$/, '');

    const timeoutMs = parseInt(timeoutInput.value, 10) || 2000;

    // Determine Ports to Scan
    let portsToScan = [];
    if (presetRadio.value === 'common') {
        portsToScan = [...PRESET_COMMON];
    } else if (presetRadio.value === 'databases') {
        portsToScan = [...PRESET_DATABASES];
    } else if (presetRadio.value === 'custom') {
        portsToScan = parseCustomPorts(customPortsInput.value);
        if (portsToScan.length === 0) {
            alert('Por favor ingresa puertos válidos (ej. 80, 443, 8000-8010)');
            return;
        }
    }

    isScanning = true;
    btnStart.disabled = true;
    btnStart.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> ESCANEANDO...';

    progressBox.classList.remove('hidden');
    progressBar.style.width = '0%';
    resultsList.innerHTML = '';

    logToTerminal(`Iniciando escaneo de ${portsToScan.length} puertos en [${target}] (Timeout: ${timeoutMs}ms)...`, 'system');

    let scannedCount = 0;
    const totalPorts = portsToScan.length;

    for (const port of portsToScan) {
        statusText.textContent = `Escaneando puerto ${port}...`;

        const result = await probePortAdvanced(target, port, timeoutMs);
        scannedCount++;

        // Update progress bar
        const percent = Math.round((scannedCount / totalPorts) * 100);
        progressBar.style.width = `${percent}%`;
        percentageText.textContent = `${percent}%`;

        // Render port result
        renderPortResult(resultsList, result);

        logToTerminal(`Puerto ${result.port} (${result.service}): Estado [${result.status.toUpperCase()}] (${result.timeMs}ms - ${result.detail || 'Probe complete'})`, 
            result.status === 'open' ? 'success' : result.status === 'filtered' ? 'warning' : 'info'
        );
    }

    statusText.textContent = 'Escaneo finalizado.';
    isScanning = false;
    btnStart.disabled = false;
    btnStart.innerHTML = '<i class="fa-solid fa-radar"></i> INICIAR ESCANEO DE PUERTOS';

    logToTerminal(`Escaneo de puertos completado en ${target}.`, 'success');
}

/**
 * Parses custom ports string (e.g., "80, 443, 8000-8010")
 */
function parseCustomPorts(inputStr) {
    const ports = new Set();
    if (!inputStr) return [];

    const parts = inputStr.split(',');
    for (let part of parts) {
        part = part.trim();
        if (part.includes('-')) {
            const [start, end] = part.split('-').map(n => parseInt(n.trim(), 10));
            if (!isNaN(start) && !isNaN(end) && start > 0 && end <= 65535 && start <= end) {
                for (let p = start; p <= Math.min(end, start + 100); p++) { // Cap range to 100 ports max
                    ports.add(p);
                }
            }
        } else {
            const p = parseInt(part, 10);
            if (!isNaN(p) && p > 0 && p <= 65535) {
                ports.add(p);
            }
        }
    }
    return Array.from(ports);
}

/**
 * Advanced Multi-Protocol Port Probe
 * Correctly distinguishes Open (Response or CORS error), Closed (Fast TCP RST), and Filtered (Timeout).
 */
async function probePortAdvanced(target, port, timeoutMs) {
    const service = PORT_SERVICES[port] || "Servicio de red";
    const startTime = performance.now();

    // Determine primary protocol (HTTPS for 443/8443, HTTP for others)
    const isSsl = (port === 443 || port === 8443);

    // Try HTTPS first if SSL port, otherwise try HTTP
    let probeResult = await singleProbe(target, port, isSsl ? 'https' : 'http', timeoutMs);

    // If HTTPS probe timed out on port 443/8443, fallback try HTTP probe just in case
    if (probeResult.status === 'filtered' && isSsl) {
        const httpFallback = await singleProbe(target, port, 'http', timeoutMs);
        if (httpFallback.status !== 'filtered') {
            probeResult = httpFallback;
        }
    }

    const elapsed = Math.round(performance.now() - startTime);

    return {
        port,
        service,
        status: probeResult.status,
        timeMs: elapsed,
        detail: probeResult.detail
    };
}

/**
 * Executes a single fetch probe to target:port via HTTP or HTTPS
 */
function singleProbe(target, port, protocol, timeoutMs) {
    return new Promise((resolve) => {
        const startTime = performance.now();
        const controller = new AbortController();
        const timeoutId = setTimeout(() => {
            controller.abort();
        }, timeoutMs);

        const probeUrl = `${protocol}://${target}:${port}/`;

        fetch(probeUrl, {
            method: 'GET',
            mode: 'no-cors',
            cache: 'no-cache',
            signal: controller.signal
        }).then(response => {
            clearTimeout(timeoutId);
            const timeMs = Math.round(performance.now() - startTime);
            resolve({
                status: 'open',
                detail: `HTTP/HTTPS ${response.type} respuesta recibida`
            });
        }).catch(err => {
            clearTimeout(timeoutId);
            const timeMs = Math.round(performance.now() - startTime);

            if (err.name === 'AbortError') {
                // Timeout reached -> Firewall dropped SYN packets (Filtered)
                resolve({
                    status: 'filtered',
                    detail: `Timeout sin respuesta (${timeoutMs}ms)`
                });
            } else {
                // TypeError: Failed to fetch -> In browser JS, a CORS or SSL policy error occurs ONLY AFTER 
                // the TCP socket connection was successfully established!
                // If connection was refused immediately (RST packet), timeMs is very short (< 90ms).
                if (timeMs < 90) {
                    resolve({
                        status: 'closed',
                        detail: 'Conexión rechazada (TCP RST)'
                    });
                } else {
                    // Port is OPEN and listening! (Browser received TCP ACK / HTTP / SSL response, then triggered CORS restriction)
                    resolve({
                        status: 'open',
                        detail: 'Servicio detectado (Respuesta TCP/CORS)'
                    });
                }
            }
        });
    });
}

/**
 * Appends a port result row to the UI list
 */
function renderPortResult(container, result) {
    const item = document.createElement('div');
    item.className = 'port-item';

    let statusClass = 'status-closed';
    let statusLabel = 'CERRADO';

    if (result.status === 'open') {
        statusClass = 'status-open';
        statusLabel = 'ABIERTO';
    } else if (result.status === 'filtered') {
        statusClass = 'status-filtered';
        statusLabel = 'FILTRADO';
    }

    item.innerHTML = `
        <div>
            <span class="port-number">Puerto ${result.port}</span>
            <span class="port-service">(${result.service})</span>
            <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 2px;">${escapeHtml(result.detail || '')}</div>
        </div>
        <div style="display: flex; align-items: center; gap: 0.75rem;">
            <span style="font-size: 0.75rem; color: var(--text-muted);">${result.timeMs} ms</span>
            <span class="port-status ${statusClass}">${statusLabel}</span>
        </div>
    `;

    container.appendChild(item);
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
