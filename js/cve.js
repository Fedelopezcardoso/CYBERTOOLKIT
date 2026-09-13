/**
 * CYBERTOOLKIT // CVE & Threat Vulnerability Finder Module
 * Uses Official NVD NIST API v2.0 (CORS Enabled) with CIRCL fallback
 */

document.addEventListener('DOMContentLoaded', () => {
    const cveForm = document.getElementById('cve-form');
    if (cveForm) {
        cveForm.addEventListener('submit', handleCveSubmit);
    }
});

/**
 * Handles CVE Search Form Submission
 */
async function handleCveSubmit(e) {
    e.preventDefault();

    const targetInput = document.getElementById('cve-query');
    const resultsBox = document.getElementById('cve-results');

    let query = targetInput.value.trim();
    if (!query) return;

    logToTerminal(`Buscando vulnerabilidades CVE para [${query}] en la base oficial NIST NVD...`, 'system');

    resultsBox.innerHTML = `
        <div class="placeholder-msg">
            <i class="fa-solid fa-circle-notch fa-spin"></i>
            <p>Consultando base de datos oficial NIST NVD (National Vulnerability Database)...</p>
        </div>
    `;

    try {
        // Try Official NIST NVD API 2.0 (Native CORS support)
        const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=12`;
        let response = await fetch(nvdUrl).catch(() => null);

        let cveItems = [];

        if (response && response.ok) {
            const data = await response.json();
            if (data && data.vulnerabilities && data.vulnerabilities.length > 0) {
                cveItems = parseNvdData(data.vulnerabilities);
            }
        }

        // If NVD returned no results or was rate limited, try CIRCL API via CORS proxy fallback
        if (cveItems.length === 0) {
            logToTerminal(`Intentando proveedor alternativo de vulnerabilidades (CIRCL)...`, 'warning');
            const fallbackUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(`https://cve.circl.lu/api/search/${query}`)}`;
            const fallbackRes = await fetch(fallbackUrl).catch(() => null);

            if (fallbackRes && fallbackRes.ok) {
                const circlData = await fallbackRes.json();
                const rawList = Array.isArray(circlData) ? circlData : (circlData.results || []);
                if (rawList.length > 0) {
                    cveItems = parseCirclData(rawList.slice(0, 12));
                }
            }
        }

        if (cveItems.length > 0) {
            renderCveCards(resultsBox, cveItems);
            logToTerminal(`Búsqueda CVE completada para ${query}. Se encontraron ${cveItems.length} registros.`, 'success');
        } else {
            resultsBox.innerHTML = `
                <div class="placeholder-msg">
                    <i class="fa-solid fa-shield-check" style="color: var(--neon-green);"></i>
                    <p>No se encontraron vulnerabilidades registradas para "${query}".</p>
                </div>
            `;
            logToTerminal(`Sin registros de vulnerabilidades para ${query}.`, 'info');
        }

    } catch (err) {
        console.error('CVE Lookup Error:', err);
        resultsBox.innerHTML = `
            <div class="placeholder-msg">
                <i class="fa-solid fa-triangle-exclamation" style="color: var(--neon-red);"></i>
                <p>Error en la búsqueda de vulnerabilidades: ${err.message}</p>
            </div>
        `;
        logToTerminal(`Error al buscar CVE: ${err.message}`, 'error');
    }
}

/**
 * Parses NVD NIST 2.0 API response array
 */
function parseNvdData(vulnArray) {
    return vulnArray.map(item => {
        const cveObj = item.cve || {};
        const cveId = cveObj.id || 'CVE-UNKNOWN';

        // Get English description
        const descObj = (cveObj.descriptions || []).find(d => d.lang === 'en') || cveObj.descriptions?.[0];
        const summary = descObj ? descObj.value : 'Sin descripción disponible.';

        // Metrics CVSS v3.1 / v3.0 / v2.0
        const metrics = cveObj.metrics || {};
        const cvssV31 = metrics.cvssMetricV31?.[0]?.cvssData || metrics.cvssMetricV30?.[0]?.cvssData || metrics.cvssMetricV2?.[0]?.cvssData || {};

        const score = cvssV31.baseScore !== undefined ? parseFloat(cvssV31.baseScore) : 0;
        const severity = cvssV31.baseSeverity || (score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : score > 0 ? 'LOW' : 'N/A');
        const published = cveObj.published ? new Date(cveObj.published).toLocaleDateString() : 'N/A';

        return {
            id: cveId,
            summary: summary,
            score: score,
            severity: severity,
            published: published,
            source: 'NIST NVD'
        };
    });
}

/**
 * Parses CIRCL API response array
 */
function parseCirclData(circlArray) {
    return circlArray.map(item => {
        const cveId = item.id || item.CVE || 'CVE-UNKNOWN';
        const summary = item.summary || item.Description || 'Sin descripción.';
        const score = parseFloat(item.cvss || 0);
        const published = item.Published ? new Date(item.Published).toLocaleDateString() : 'N/A';

        let severity = 'N/A';
        if (score >= 9.0) severity = 'CRITICAL';
        else if (score >= 7.0) severity = 'HIGH';
        else if (score >= 4.0) severity = 'MEDIUM';
        else if (score > 0) severity = 'LOW';

        return {
            id: cveId,
            summary: summary,
            score: score,
            severity: severity,
            published: published,
            source: 'CIRCL'
        };
    });
}

/**
 * Renders parsed CVE items into UI cards
 */
function renderCveCards(container, cveItems) {
    container.innerHTML = cveItems.map(item => {
        let cvssClass = 'status-open';
        let cvssLabel = `${item.severity} (${item.score.toFixed(1)})`;

        if (item.score >= 9.0 || item.severity === 'CRITICAL') {
            cvssClass = 'status-closed';
            cvssLabel = `CRÍTICO (${item.score > 0 ? item.score.toFixed(1) : '9.0+'})`;
        } else if (item.score >= 7.0 || item.severity === 'HIGH') {
            cvssClass = 'status-filtered';
            cvssLabel = `ALTO (${item.score.toFixed(1)})`;
        } else if (item.score >= 4.0 || item.severity === 'MEDIUM') {
            cvssClass = 'status-filtered';
            cvssLabel = `MEDIO (${item.score.toFixed(1)})`;
        } else if (item.score > 0) {
            cvssClass = 'status-open';
            cvssLabel = `BAJO (${item.score.toFixed(1)})`;
        } else {
            cvssLabel = 'INFORMACIÓN';
        }

        return `
            <div class="dns-record-badge" style="gap: 0.5rem; background: rgba(5, 10, 20, 0.8);">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span class="dns-type-tag" style="color: var(--neon-cyan); font-size: 0.95rem;">
                        <i class="fa-solid fa-bug"></i> ${escapeHtml(item.id)}
                    </span>
                    <span class="port-status ${cvssClass}">${cvssLabel}</span>
                </div>
                <div style="font-size: 0.82rem; color: var(--text-bright); line-height: 1.4;">
                    ${escapeHtml(item.summary)}
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 0.3rem; font-size: 0.72rem; color: var(--text-muted);">
                    <span><i class="fa-regular fa-calendar"></i> Publicado: ${item.published} (${item.source})</span>
                    <a href="https://nvd.nist.gov/vuln/detail/${item.id}" target="_blank" rel="noopener" style="color: var(--neon-cyan); text-decoration: none;">
                        Ver en NIST NVD <i class="fa-solid fa-up-right-from-square"></i>
                    </a>
                </div>
            </div>
        `;
    }).join('');
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
