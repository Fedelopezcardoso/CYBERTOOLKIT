/**
 * CYBERTOOLKIT // DNS & NSLookup Module (DNS-over-HTTPS / DoH)
 * Features record deduplication, GSLB low-TTL detection, multi-provider sweep, and multi-IP collection.
 */

document.addEventListener('DOMContentLoaded', () => {
    const dnsForm = document.getElementById('dns-form');
    if (dnsForm) {
        dnsForm.addEventListener('submit', handleDnsSubmit);
    }
});

// DoH Providers Map
const DOH_PROVIDERS = {
    cloudflare: {
        name: "Cloudflare DNS (1.1.1.1)",
        endpoint: "https://cloudflare-dns.com/dns-query",
        headers: { "Accept": "application/dns-json" }
    },
    google: {
        name: "Google Public DNS (8.8.8.8)",
        endpoint: "https://dns.google/resolve",
        headers: {}
    },
    quad9: {
        name: "Quad9 Secure DNS (9.9.9.9)",
        endpoint: "https://dns.quad9.net:5053/dns-query",
        headers: { "Accept": "application/dns-json" }
    },
    adguard: {
        name: "AdGuard DNS",
        endpoint: "https://dns.adguard-dns.com/resolve",
        headers: {}
    }
};

// DNS Record Type Code Mapping (RFC 1035 / IANA)
const TYPE_NAME_MAP = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    12: 'PTR',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA'
};

/**
 * Handles DNS Lookup Form Submission
 */
async function handleDnsSubmit(e) {
    e.preventDefault();

    const targetInput = document.getElementById('dns-target');
    const serverSelect = document.getElementById('dns-server');
    const customUrlInput = document.getElementById('dns-custom-url');
    const resultsBox = document.getElementById('dns-results');

    let target = targetInput.value.trim();
    if (!target) return;

    // Clean target (remove http:// or https:// if user pasted a URL)
    target = target.replace(/^https?:\/\//i, '').replace(/\/.*$/, '');

    // Get Selected Record Types
    const typeCheckboxes = document.querySelectorAll('input[name="dns-type"]:checked');
    const selectedTypes = Array.from(typeCheckboxes).map(cb => cb.value);

    if (selectedTypes.length === 0) {
        alert('Por favor selecciona al menos un tipo de registro DNS (A, MX, etc.)');
        return;
    }

    // Determine DoH Endpoint
    let providerObj;
    if (serverSelect.value === 'custom') {
        const customUrl = customUrlInput.value.trim();
        if (!customUrl) {
            alert('Por favor ingresa la URL del servidor DoH personalizado.');
            return;
        }
        providerObj = {
            name: "Servidor DoH Personalizado",
            endpoint: customUrl,
            headers: { "Accept": "application/dns-json" }
        };
    } else {
        providerObj = DOH_PROVIDERS[serverSelect.value] || DOH_PROVIDERS.google;
    }

    logToTerminal(`Iniciando NSLookup para [${target}] usando ${providerObj.name}...`, 'system');

    // UI Loading state
    resultsBox.innerHTML = `
        <div class="placeholder-msg">
            <i class="fa-solid fa-circle-notch fa-spin"></i>
            <p>Consultando registros DNS a través de DoH (${providerObj.name})...</p>
        </div>
    `;

    try {
        // Query all selected record types concurrently
        const fetchPromises = selectedTypes.map(rrType => fetchDohRecord(target, rrType, providerObj));
        const results = await Promise.allSettled(fetchPromises);

        const recordSet = new Set();
        const deduplicatedRecords = [];
        const resolvedIpsMap = new Map();
        let isGslbDetected = false;

        results.forEach((res) => {
            if (res.status === 'fulfilled' && res.value && res.value.Answer) {
                res.value.Answer.forEach(record => {
                    const recordTypeName = TYPE_NAME_MAP[record.type] || `TYPE-${record.type}`;
                    const uniqueKey = `${recordTypeName}:${record.name}:${record.data}`;

                    // Deduplicate identical DNS records
                    if (!recordSet.has(uniqueKey)) {
                        recordSet.add(uniqueKey);
                        deduplicatedRecords.push({
                            type: recordTypeName,
                            name: record.name,
                            ttl: record.TTL,
                            data: record.data
                        });
                    }

                    // Check for low TTL (< 15s) indicating GSLB / Dynamic DNS
                    if (record.TTL !== undefined && record.TTL <= 15) {
                        isGslbDetected = true;
                    }

                    // Collect IPv4 and IPv6 addresses for multi-IP summary
                    if (recordTypeName === 'A' || recordTypeName === 'AAAA') {
                        if (record.data && !resolvedIpsMap.has(record.data)) {
                            resolvedIpsMap.set(record.data, {
                                ip: record.data,
                                type: recordTypeName,
                                ttl: record.TTL,
                                provider: providerObj.name
                            });
                        }
                    }
                });
            }
        });

        const resolvedIps = Array.from(resolvedIpsMap.values());

        if (deduplicatedRecords.length > 0) {
            let html = '';

            // Render Multi-IP Summary Box if IPs were resolved
            if (resolvedIps.length > 0) {
                html += renderIpSummaryBox(target, resolvedIps, isGslbDetected);
            }

            // Render Grouped DNS Records (Deduplicated)
            html += renderGroupedRecords(deduplicatedRecords);

            resultsBox.innerHTML = html;

            // Attach event listeners for quick scan buttons & GSLB sweep
            attachDnsActionListeners(target);

            logToTerminal(`NSLookup completado para ${target}. Se encontraron ${deduplicatedRecords.length} registros únicos y ${resolvedIps.length} IP(s).`, 'success');
        } else {
            resultsBox.innerHTML = `
                <div class="placeholder-msg">
                    <i class="fa-solid fa-circle-exclamation"></i>
                    <p>No se encontraron registros para los tipos seleccionados o el dominio no existe.</p>
                </div>
            `;
            logToTerminal(`NSLookup completado para ${target}. Sin resultados devueltos.`, 'warning');
        }

    } catch (err) {
        console.error('DNS Lookup Error:', err);
        resultsBox.innerHTML = `
            <div class="placeholder-msg">
                <i class="fa-solid fa-triangle-exclamation" style="color: var(--neon-red);"></i>
                <p>Error en la consulta DoH: ${err.message}</p>
            </div>
        `;
        logToTerminal(`Error en consulta DNS DoH: ${err.message}`, 'error');
    }
}

/**
 * Fetches a single DNS record type via DoH
 */
async function fetchDohRecord(domain, type, provider) {
    const url = new URL(provider.endpoint);
    url.searchParams.append('name', domain);
    url.searchParams.append('type', type);

    const response = await fetch(url.toString(), {
        method: 'GET',
        headers: provider.headers
    });

    if (!response.ok) {
        throw new Error(`HTTP Error ${response.status} del proveedor DoH`);
    }

    return await response.json();
}

/**
 * Renders Multi-IP Resolution Summary Box with GSLB Notice
 */
function renderIpSummaryBox(domain, resolvedIps, isGslb) {
    let ipsHtml = resolvedIps.map(item => `
        <div style="display: flex; justify-content: space-between; align-items: center; background: rgba(0,0,0,0.4); padding: 0.45rem 0.8rem; border-radius: 4px; border: 1px solid rgba(0,243,255,0.15);">
            <div>
                <span style="color: var(--neon-cyan); font-weight: bold; font-size: 0.85rem;">[${item.type}]</span>
                <span style="color: var(--text-bright); font-size: 0.9rem; font-family: var(--font-mono); margin-left: 0.5rem;">${escapeHtml(item.ip)}</span>
                ${item.ttl !== undefined ? `<span style="font-size: 0.7rem; color: var(--text-muted); margin-left: 0.5rem;">(TTL: ${item.ttl}s)</span>` : ''}
            </div>
            <div style="display: flex; gap: 0.4rem;">
                <button class="cyber-btn secondary btn-quick-scan" data-ip="${escapeHtml(item.ip)}" style="padding: 0.25rem 0.6rem; font-size: 0.72rem;" title="Escanear esta IP en el Port Scanner">
                    <i class="fa-solid fa-radar"></i> Escanear
                </button>
                <button class="cyber-btn secondary btn-quick-geo" data-ip="${escapeHtml(item.ip)}" style="padding: 0.25rem 0.6rem; font-size: 0.72rem;" title="Geolocalizar esta IP">
                    <i class="fa-solid fa-earth-americas"></i> Geolocalizar
                </button>
            </div>
        </div>
    `).join('');

    let gslbBadge = isGslb ? `
        <div style="background: rgba(255, 158, 0, 0.15); border: 1px solid var(--neon-orange); border-radius: 4px; padding: 0.4rem 0.6rem; margin-bottom: 0.6rem; font-size: 0.75rem; color: var(--neon-orange); display: flex; align-items: center; justify-content: space-between;">
            <span><i class="fa-solid fa-bolt"></i> <strong>GSLB / Balanceo Dinámico Detectado:</strong> TTL ultracorto (<=15s). La IP cambia según la carga/WAF.</span>
            <button class="cyber-btn secondary" id="btn-gslb-sweep" style="padding: 0.2rem 0.5rem; font-size: 0.7rem; background: rgba(255,158,0,0.2); border-color: var(--neon-orange); color: var(--neon-orange);" title="Consultar múltiples DNS para descubrir el pool completo de IPs WAF">
                <i class="fa-solid fa-network-wired"></i> Barrido Multi-DNS
            </button>
        </div>
    ` : '';

    return `
        <div style="background: linear-gradient(135deg, rgba(0, 243, 255, 0.1), rgba(0, 168, 255, 0.05)); border: 1px solid var(--neon-cyan); border-radius: 8px; padding: 1rem; margin-bottom: 1rem;">
            ${gslbBadge}
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.6rem;">
                <span style="color: var(--neon-cyan); font-weight: bold; font-family: var(--font-mono); font-size: 0.9rem;">
                    <i class="fa-solid fa-network-wired"></i> DIRECCIONES IP RESUELTAS (${resolvedIps.length})
                </span>
                <span style="font-size: 0.75rem; color: var(--text-muted);">Dominio: ${escapeHtml(domain)}</span>
            </div>
            <div style="display: flex; flex-direction: column; gap: 0.4rem;" id="ip-summary-list">
                ${ipsHtml}
            </div>
        </div>
    `;
}

/**
 * Renders all DNS records grouped by type (Deduplicated)
 */
function renderGroupedRecords(records) {
    return records.map(record => {
        const isLowTtl = record.ttl !== undefined && record.ttl <= 15;
        return `
            <div class="dns-record-badge">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span class="dns-type-tag"><i class="fa-solid fa-tag"></i> REGISTRO ${record.type}</span>
                    <span style="font-size: 0.75rem; color: ${isLowTtl ? 'var(--neon-orange)' : 'var(--text-muted)'};">
                        ${isLowTtl ? '<i class="fa-solid fa-bolt"></i> ' : ''}TTL: ${record.ttl !== undefined ? record.ttl + 's' : 'N/A'}
                    </span>
                </div>
                <div class="dns-value">${escapeHtml(record.data)}</div>
            </div>
        `;
    }).join('');
}

/**
 * Multi-DNS Sweep for GSLB Pool Discovery
 * Queries Google, Cloudflare, Quad9, and AdGuard simultaneously to harvest all active WAF/GSLB IPs.
 */
async function runGslbMultiDnsSweep(domain) {
    logToTerminal(`Iniciando Barrido Multi-DNS para [${domain}] a través de Cloudflare, Google, Quad9 y AdGuard...`, 'system');

    const sweepProviders = [DOH_PROVIDERS.google, DOH_PROVIDERS.cloudflare, DOH_PROVIDERS.quad9, DOH_PROVIDERS.adguard];
    const discoveredIpsMap = new Map();

    const sweepPromises = sweepProviders.map(provider => fetchDohRecord(domain, 'A', provider).catch(() => null));
    const results = await Promise.all(sweepPromises);

    results.forEach((res, idx) => {
        const provName = sweepProviders[idx].name;
        if (res && res.Answer) {
            res.Answer.forEach(rec => {
                if (rec.type === 1 || rec.type === 28) {
                    if (rec.data && !discoveredIpsMap.has(rec.data)) {
                        discoveredIpsMap.set(rec.data, {
                            ip: rec.data,
                            type: rec.type === 1 ? 'A' : 'AAAA',
                            ttl: rec.TTL,
                            provider: provName
                        });
                    }
                }
            });
        }
    });

    const allDiscovered = Array.from(discoveredIpsMap.values());
    logToTerminal(`Barrido Multi-DNS completado. Se descubrieron ${allDiscovered.length} IP(s) únicas en el pool GSLB.`, 'success');

    // Update IP summary UI list with discovered IPs
    const summaryList = document.getElementById('ip-summary-list');
    if (summaryList && allDiscovered.length > 0) {
        summaryList.innerHTML = allDiscovered.map(item => `
            <div style="display: flex; justify-content: space-between; align-items: center; background: rgba(0,0,0,0.4); padding: 0.45rem 0.8rem; border-radius: 4px; border: 1px solid rgba(0,243,255,0.15);">
                <div>
                    <span style="color: var(--neon-cyan); font-weight: bold; font-size: 0.85rem;">[${item.type}]</span>
                    <span style="color: var(--text-bright); font-size: 0.9rem; font-family: var(--font-mono); margin-left: 0.5rem;">${escapeHtml(item.ip)}</span>
                    <span style="font-size: 0.7rem; color: var(--text-muted); margin-left: 0.5rem;">(${item.provider})</span>
                </div>
                <div style="display: flex; gap: 0.4rem;">
                    <button class="cyber-btn secondary btn-quick-scan" data-ip="${escapeHtml(item.ip)}" style="padding: 0.25rem 0.6rem; font-size: 0.72rem;" title="Escanear esta IP en el Port Scanner">
                        <i class="fa-solid fa-radar"></i> Escanear
                    </button>
                    <button class="cyber-btn secondary btn-quick-geo" data-ip="${escapeHtml(item.ip)}" style="padding: 0.25rem 0.6rem; font-size: 0.72rem;" title="Geolocalizar esta IP">
                        <i class="fa-solid fa-earth-americas"></i> Geolocalizar
                    </button>
                </div>
            </div>
        `).join('');

        attachDnsActionListeners(domain);
    }
}

/**
 * Attach quick scan, quick geo, and GSLB sweep button listeners
 */
function attachDnsActionListeners(domain) {
    document.querySelectorAll('.btn-quick-scan').forEach(btn => {
        btn.addEventListener('click', () => {
            const ip = btn.getAttribute('data-ip');
            if (ip) {
                const scannerNavBtn = document.querySelector('.nav-btn[data-tab="tab-scanner"]');
                if (scannerNavBtn) scannerNavBtn.click();

                const scanTarget = document.getElementById('scan-target');
                if (scanTarget) scanTarget.value = ip;

                logToTerminal(`IP ${ip} copiada al Port Scanner. Listo para iniciar escaneo.`, 'info');
            }
        });
    });

    document.querySelectorAll('.btn-quick-geo').forEach(btn => {
        btn.addEventListener('click', () => {
            const ip = btn.getAttribute('data-ip');
            if (ip) {
                const geoNavBtn = document.querySelector('.nav-btn[data-tab="tab-geoloc"]');
                if (geoNavBtn) geoNavBtn.click();

                const geoTarget = document.getElementById('geo-target');
                if (geoTarget) {
                    geoTarget.value = ip;
                    fetchIpGeolocation(ip);
                }
            }
        });
    });

    const sweepBtn = document.getElementById('btn-gslb-sweep');
    if (sweepBtn) {
        sweepBtn.addEventListener('click', () => {
            runGslbMultiDnsSweep(domain);
        });
    }
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
