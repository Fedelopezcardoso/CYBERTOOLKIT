/**
 * CYBERTOOLKIT // Main Application UI Handler
 */

document.addEventListener('DOMContentLoaded', () => {
    initTabNavigation();
    initTerminalLogger();
    initFormToggles();
});

/**
 * Tab Navigation Switcher
 */
function initTabNavigation() {
    const navButtons = document.querySelectorAll('.cyber-nav .nav-btn');
    const tabPanes = document.querySelectorAll('.cyber-content .tab-pane');

    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');

            // Deactivate all tabs & buttons
            navButtons.forEach(b => b.classList.remove('active'));
            tabPanes.forEach(p => p.classList.remove('active'));

            // Activate target
            btn.classList.add('active');
            const pane = document.getElementById(targetTab);
            if (pane) {
                pane.classList.add('active');
                logToTerminal(`Pestaña activada: ${btn.innerText.trim()}`, 'info');

                // If switching to geoloc tab, trigger Leaflet resize recalculation
                if (targetTab === 'tab-geoloc' && window.cyberMap) {
                    setTimeout(() => {
                        window.cyberMap.invalidateSize();
                    }, 200);
                }
            }
        });
    });
}

/**
 * Terminal Event Logger
 */
function logToTerminal(message, type = 'info') {
    const logsContainer = document.getElementById('terminal-logs');
    if (!logsContainer) return;

    const timeStr = new Date().toLocaleTimeString();
    const logLine = document.createElement('div');
    logLine.className = `log-line ${type}`;

    let prefix = '[INFO]';
    if (type === 'system') prefix = '[SYSTEM]';
    if (type === 'success') prefix = '[SUCCESS]';
    if (type === 'warning') prefix = '[WARN]';
    if (type === 'error') prefix = '[ERROR]';

    logLine.textContent = `[${timeStr}] ${prefix} ${message}`;
    logsContainer.appendChild(logLine);

    // Auto scroll to bottom
    logsContainer.scrollTop = logsContainer.scrollHeight;
}

function initTerminalLogger() {
    const clearBtn = document.getElementById('btn-clear-log');
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            const logsContainer = document.getElementById('terminal-logs');
            if (logsContainer) {
                logsContainer.innerHTML = '';
                logToTerminal('Consola de eventos limpiada.', 'system');
            }
        });
    }
}

/**
 * Interactive Form Toggles
 */
function initFormToggles() {
    // DNS Custom DoH Toggle
    const dnsSelect = document.getElementById('dns-server');
    const customDohGroup = document.getElementById('custom-doh-group');
    if (dnsSelect && customDohGroup) {
        dnsSelect.addEventListener('change', () => {
            if (dnsSelect.value === 'custom') {
                customDohGroup.classList.remove('hidden');
            } else {
                customDohGroup.classList.add('hidden');
            }
        });
    }

    // Scanner Custom Ports Toggle
    const portRadios = document.querySelectorAll('input[name="port-preset"]');
    const customPortsGroup = document.getElementById('custom-ports-group');
    portRadios.forEach(radio => {
        radio.addEventListener('change', () => {
            if (radio.value === 'custom') {
                customPortsGroup.classList.remove('hidden');
            } else {
                customPortsGroup.classList.add('hidden');
            }
        });
    });

    // Scanner Timeout Live Range Display
    const timeoutRange = document.getElementById('scan-timeout');
    const timeoutDisplay = document.getElementById('timeout-display');
    if (timeoutRange && timeoutDisplay) {
        timeoutRange.addEventListener('input', () => {
            timeoutDisplay.textContent = `${timeoutRange.value} ms`;
        });
    }
}
