/**
 * CYBERTOOLKIT // CVE & Threat Vulnerability Finder Module (v2.3 Reverse-Index Update)
 * Features:
 * 1. Reverse-Index Fetching: Always fetches the newest 2026/2025 CVEs from the end of NVD's index.
 * 2. Intelligent Dual Search: Direct CVE ID Lookup vs Keyword Search.
 * 3. Exact Sorting: Sorts by CVE Year & ID descending (newest to oldest).
 * 4. Progressive Pagination: "Cargar 30 vulnerabilidades anteriores" button.
 */

document.addEventListener('DOMContentLoaded', () => {
    const cveForm = document.getElementById('cve-form');
    if (cveForm) {
        cveForm.addEventListener('submit', handleCveSubmit);
    }
});

let cveState = {
    query: '',
    totalResults: 0,
    currentLowestStartIndex: 0,
    itemsMap: new Map(),
    isCveIdPattern: false
};

/**
 * Handles CVE Search Form Submission
 */
async function handleCveSubmit(e) {
    if (e && e.preventDefault) e.preventDefault();

    const targetInput = document.getElementById('cve-query');
    const resultsBox = document.getElementById('cve-results');

    let query = targetInput.value.trim();
    if (!query) return;

    // Detect if input is an exact CVE ID pattern (e.g., CVE-2026-73570 or 2026-73570)
    const isCveIdPattern = /^(CVE-)?\d{4}-\d+$/i.test(query);
    let normalizedCveId = query.toUpperCase();
    if (isCveIdPattern && !normalizedCveId.startsWith('CVE-')) {
        normalizedCveId = `CVE-${normalizedCveId}`;
    }

    // Reset state for new search
    cveState = {
        query: isCveIdPattern ? normalizedCveId : query,
        totalResults: 0,
        currentLowestStartIndex: 0,
        itemsMap: new Map(),
        isCveIdPattern: isCveIdPattern
    };

    logToTerminal(`Buscando las vulnerabilidades MÁS RECIENTES para [${cveState.query}] en NIST NVD...`, 'system');

    resultsBox.innerHTML = `
        <div class="placeholder-msg">
            <i class="fa-solid fa-circle-notch fa-spin"></i>
            <p>Consultando base de datos NIST NVD (Obteniendo vulnerabilidades más recientes primero)...</p>
        </div>
    `;

    if (cveState.isCveIdPattern) {
        // Direct CVE ID lookup
        await fetchDirectCveId(normalizedCveId);
    } else {
        // Keyword search with reverse index logic to get newest CVEs first
        await fetchRecentKeywordCves(false);
    }
}

/**
 * Direct CVE ID Fetch
 */
async function fetchDirectCveId(cveId) {
    const resultsBox = document.getElementById('cve-results');
    try {
        const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
        const response = await fetch(nvdUrl).catch(() => null);

        if (response && response.ok) {
            const data = await response.json();
            if (data && data.vulnerabilities && data.vulnerabilities.length > 0) {
                const parsed = parseNvdData(data.vulnerabilities);
                cveState.totalResults = 1;
                parsed.forEach(item => cveState.itemsMap.set(item.id, item));
                renderCveStateUI(resultsBox);
                logToTerminal(`CVE exacto encontrado: ${cveId}`, 'success');
                return;
            }
        }

        resultsBox.innerHTML = `
            <div class="placeholder-msg">
                <i class="fa-solid fa-triangle-exclamation" style="color: var(--neon-orange);"></i>
                <p>No se encontró información registrada para el ID "${escapeHtml(cveId)}".</p>
            </div>
        `;
        logToTerminal(`CVE ID ${cveId} no encontrado en NVD.`, 'warning');

    } catch (err) {
        console.error('Direct CVE Error:', err);
        resultsBox.innerHTML = `<div class="placeholder-msg"><p>Error: ${err.message}</p></div>`;
    }
}

/**
 * Fetches recent keyword CVEs starting from the END of NVD's index
 */
async function fetchRecentKeywordCves(isLoadMore = false) {
    const resultsBox = document.getElementById('cve-results');

    try {
        if (!isLoadMore) {
            // First step: Probe to get totalResults count
            const probeUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(cveState.query)}&resultsPerPage=1`;
            const probeRes = await fetch(probeUrl).catch(() => null);

            if (probeRes && probeRes.ok) {
                const probeData = await probeRes.json();
                cveState.totalResults = probeData.totalResults || 0;
            }

            if (cveState.totalResults === 0) {
                // Fallback to CIRCL
                await fetchCirclFallback();
                return;
            }

            // Calculate start index to fetch the LAST page (the newest CVEs in NVD)
            cveState.currentLowestStartIndex = Math.max(0, cveState.totalResults - 30);
        } else {
            // Step backwards for loading older items
            cveState.currentLowestStartIndex = Math.max(0, cveState.currentLowestStartIndex - 30);
        }

        // Fetch 30 items from the calculated index
        const pageUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(cveState.query)}&resultsPerPage=30&startIndex=${cveState.currentLowestStartIndex}`;
        const response = await fetch(pageUrl).catch(() => null);

        if (response && response.ok) {
            const data = await response.json();
            if (data && data.vulnerabilities && data.vulnerabilities.length > 0) {
                const parsed = parseNvdData(data.vulnerabilities);
                parsed.forEach(item => cveState.itemsMap.set(item.id, item));
            }
        }

        renderCveStateUI(resultsBox);
        logToTerminal(`Se cargaron vulnerabilidades para ${cveState.query} (En pantalla: ${cveState.itemsMap.size}/${cveState.totalResults}).`, 'success');

    } catch (err) {
        console.error('Keyword CVE Error:', err);
        resultsBox.innerHTML = `<div class="placeholder-msg"><p>Error al buscar vulnerabilidades: ${err.message}</p></div>`;
    }
}

/**
 * Fallback to CIRCL API via CORS proxy if NVD returns 0 results
 */
async function fetchCirclFallback() {
    const resultsBox = document.getElementById('cve-results');
    logToTerminal(`Intentando proveedor secundario (CIRCL)...`, 'warning');

    const fallbackUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(`https://cve.circl.lu/api/search/${cveState.query}`)}`;
    const response = await fetch(fallbackUrl).catch(() => null);

    if (response && response.ok) {
        const circlData = await response.json();
        const rawList = Array.isArray(circlData) ? circlData : (circlData.results || []);
        if (rawList.length > 0) {
            const parsed = parseCirclData(rawList);
            cveState.totalResults = parsed.length;
            parsed.forEach(item => cveState.itemsMap.set(item.id, item));
            renderCveStateUI(resultsBox);
            logToTerminal(`CIRCL respondió con ${parsed.length} vulnerabilidades.`, 'success');
            return;
        }
    }

    resultsBox.innerHTML = `
        <div class="placeholder-msg">
            <i class="fa-solid fa-shield-check" style="color: var(--neon-green);"></i>
            <p>No se encontraron registros de CVE para "${escapeHtml(cveState.query)}".</p>
        </div>
    `;
}

/**
 * Parses NVD NIST 2.0 API response array
 */
function parseNvdData(vulnArray) {
    return vulnArray.map(item => {
        const cveObj = item.cve || {};
        const cveId = cveObj.id || 'CVE-UNKNOWN';

        const descObj = (cveObj.descriptions || []).find(d => d.lang === 'en') || cveObj.descriptions?.[0];
        const summary = descObj ? descObj.value : 'Sin descripción disponible.';

        const metrics = cveObj.metrics || {};
        const cvssV31 = metrics.cvssMetricV31?.[0]?.cvssData || metrics.cvssMetricV30?.[0]?.cvssData || metrics.cvssMetricV2?.[0]?.cvssData || {};

        const score = cvssV31.baseScore !== undefined ? parseFloat(cvssV31.baseScore) : 0;
        const severity = cvssV31.baseSeverity || (score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : score > 0 ? 'LOW' : 'N/A');
        const publishedDate = cveObj.published ? new Date(cveObj.published) : null;
        const publishedStr = publishedDate ? publishedDate.toLocaleDateString() : 'N/A';

        return {
            id: cveId,
            summary: summary,
            score: score,
            severity: severity,
            published: publishedStr,
            rawDate: cveObj.published || '',
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
        const publishedDate = item.Published ? new Date(item.Published) : null;
        const publishedStr = publishedDate ? publishedDate.toLocaleDateString() : 'N/A';

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
            published: publishedStr,
            rawDate: item.Published || '',
            source: 'CIRCL'
        };
    });
}

/**
 * Renders parsed CVE items and Load More Button
 */
function renderCveStateUI(container) {
    const itemsArray = Array.from(cveState.itemsMap.values());

    // Sort items by CVE ID Year & Number descending (e.g. CVE-2026-9588 > CVE-2026-89638 > CVE-2024-xxx)
    itemsArray.sort((a, b) => {
        const parseId = (idStr) => {
            const parts = idStr.split('-');
            if (parts.length >= 3) {
                return { year: parseInt(parts[1], 10) || 0, num: parseInt(parts[2], 10) || 0 };
            }
            return { year: 0, num: 0 };
        };

        const idA = parseId(a.id);
        const idB = parseId(b.id);

        if (idA.year !== idB.year) {
            return idB.year - idA.year; // Higher year first
        }
        if (idA.num !== idB.num) {
            return idB.num - idA.num; // Higher ID number first
        }

        const timeA = a.rawDate ? new Date(a.rawDate).getTime() : 0;
        const timeB = b.rawDate ? new Date(b.rawDate).getTime() : 0;
        return timeB - timeA;
    });

    const summaryBanner = `
        <div style="background: rgba(0, 243, 255, 0.08); border: 1px solid rgba(0, 243, 255, 0.25); border-radius: 6px; padding: 0.6rem 0.8rem; margin-bottom: 0.75rem; font-size: 0.8rem; color: var(--text-muted); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem;">
            <span><i class="fa-solid fa-clock-rotate-left" style="color: var(--neon-cyan);"></i> Orden: <strong>NUEVOS PRIMERO (2026/2025...)</strong></span>
            <span style="color: var(--neon-cyan); font-weight: bold;">[${itemsArray.length} de ${cveState.totalResults} mostradas para "${escapeHtml(cveState.query)}"]</span>
        </div>
    `;

    const cardsHtml = itemsArray.map(item => {
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
                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 0.3rem; font-size: 0.72rem; color: var(--text-muted); flex-wrap: wrap; gap: 0.4rem;">
                    <span><i class="fa-regular fa-calendar"></i> Publicado: ${item.published} (${item.source})</span>
                    <a href="https://nvd.nist.gov/vuln/detail/${item.id}" target="_blank" rel="noopener" style="color: var(--neon-cyan); text-decoration: none;">
                        Ver en NIST NVD <i class="fa-solid fa-up-right-from-square"></i>
                    </a>
                </div>
            </div>
        `;
    }).join('');

    // Load More Button if older results remain
    let loadMoreBtn = '';
    if (!cveState.isCveIdPattern && cveState.currentLowestStartIndex > 0) {
        loadMoreBtn = `
            <div style="text-align: center; margin-top: 1rem;">
                <button type="button" class="cyber-btn secondary" id="btn-load-more-cve" style="width: 100%;">
                    <i class="fa-solid fa-download"></i> CARGAR 30 VULNERABILIDADES ANTERIORES... (${itemsArray.length} / ${cveState.totalResults})
                </button>
            </div>
        `;
    }

    container.innerHTML = summaryBanner + cardsHtml + loadMoreBtn;

    // Attach listener to Load More button
    const btnMore = document.getElementById('btn-load-more-cve');
    if (btnMore) {
        btnMore.addEventListener('click', async () => {
            btnMore.disabled = true;
            btnMore.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Cargando vulnerabilidades anteriores...';
            await fetchRecentKeywordCves(true);
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
