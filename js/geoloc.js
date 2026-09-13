/**
 * CYBERTOOLKIT // IP Geolocation & Leaflet.js Interactive Map Module
 */

document.addEventListener('DOMContentLoaded', () => {
    initLeafletMap();

    const geolocForm = document.getElementById('geoloc-form');
    const myIpBtn = document.getElementById('btn-my-ip');

    if (geolocForm) {
        geolocForm.addEventListener('submit', handleGeolocSubmit);
    }

    if (myIpBtn) {
        myIpBtn.addEventListener('click', () => {
            document.getElementById('geo-target').value = '';
            handleGeolocSubmit(new Event('submit'));
        });
    }

    // Auto-fetch client IP info on startup
    fetchIpGeolocation('');
});

let cyberMap = null;
let cyberMarker = null;

/**
 * Initializes Leaflet Map with Dark Theme Tiles
 */
function initLeafletMap() {
    const mapElement = document.getElementById('leaflet-map');
    if (!mapElement || cyberMap) return;

    // Default center (0, 0)
    cyberMap = L.map('leaflet-map').setView([20, 0], 2);
    window.cyberMap = cyberMap;

    // Dark Mode Tiles (CartoDB Dark Matter)
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(cyberMap);
}

/**
 * Handles Form Submit for IP Geolocation
 */
function handleGeolocSubmit(e) {
    if (e && e.preventDefault) e.preventDefault();

    const targetInput = document.getElementById('geo-target');
    const ip = targetInput.value.trim();

    fetchIpGeolocation(ip);
}

/**
 * Fetches Geolocation Data for a given IP or Client IP
 */
async function fetchIpGeolocation(ipTarget) {
    logToTerminal(`Solicitando geolocalización para IP ${ipTarget || '[MI IP ACUTAL]'}...`, 'system');

    const detailsContainer = document.getElementById('geo-details-container');
    const endpoint = ipTarget ? `https://ipwho.is/${ipTarget}` : `https://ipwho.is/`;

    try {
        const response = await fetch(endpoint);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status} al consultar geolocalización`);
        }

        const data = await response.json();

        if (!data.success) {
            throw new Error(data.message || 'IP no encontrada o inválida');
        }

        renderGeoDetails(data);
        updateMapLocation(data.latitude, data.longitude, data.ip, data.city, data.country);

        detailsContainer.classList.remove('hidden');
        logToTerminal(`Geolocalización exitosa para IP ${data.ip}: ${data.city}, ${data.country} (${data.connection?.isp || data.isp})`, 'success');

    } catch (err) {
        console.error('Geolocation Error:', err);
        logToTerminal(`Error en geolocalización: ${err.message}`, 'error');
        alert(`Error al obtener geolocalización: ${err.message}`);
    }
}

/**
 * Updates UI Details Cards
 */
function renderGeoDetails(data) {
    const flagStr = data.flag?.emoji ? `${data.flag.emoji} ` : '';
    
    document.getElementById('geo-country').textContent = `${flagStr}${data.country || 'Desconocido'} (${data.country_code || 'N/A'})`;
    document.getElementById('geo-city').textContent = `${data.city || 'N/A'}, ${data.region || 'N/A'}`;
    document.getElementById('geo-isp').textContent = data.connection?.isp || data.isp || 'N/A';
    document.getElementById('geo-asn').textContent = data.connection?.asn ? `AS${data.connection.asn} (${data.connection.org || ''})` : 'N/A';
    document.getElementById('geo-coords').textContent = `${data.latitude?.toFixed(4)}, ${data.longitude?.toFixed(4)}`;
    document.getElementById('geo-timezone').textContent = data.timezone?.id ? `${data.timezone.id} (UTC ${data.timezone.utc || ''})` : 'N/A';
}

/**
 * Updates Leaflet Map Center & Marker
 */
function updateMapLocation(lat, lng, ip, city, country) {
    if (!cyberMap || lat === undefined || lng === undefined) return;

    const coords = [lat, lng];

    cyberMap.setView(coords, 10, { animate: true });

    if (cyberMarker) {
        cyberMarker.setLatLng(coords);
    } else {
        // Custom Neon Cyan Icon
        const cyanIcon = L.divIcon({
            className: 'custom-map-marker',
            html: `<div style="
                width: 16px;
                height: 16px;
                background-color: #00f3ff;
                border: 2px solid #ffffff;
                border-radius: 50%;
                box-shadow: 0 0 15px #00f3ff, 0 0 30px #00a8ff;
            "></div>`,
            iconSize: [16, 16],
            iconAnchor: [8, 8]
        });

        cyberMarker = L.marker(coords, { icon: cyanIcon }).addTo(cyberMap);
    }

    cyberMarker.bindPopup(`
        <div style="font-family: monospace; font-size: 12px; color: #0d1117;">
            <strong>IP: ${ip}</strong><br>
            Ubicación: ${city}, ${country}<br>
            Coords: ${lat.toFixed(4)}, ${lng.toFixed(4)}
        </div>
    `).openPopup();
}
