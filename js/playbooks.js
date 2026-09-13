/**
 * CYBERTOOLKIT // Incident Response Playbooks Module
 */

document.addEventListener('DOMContentLoaded', () => {
    initPlaybookListeners();
});

function initPlaybookListeners() {
    const checkboxes = document.querySelectorAll('.playbook-checkbox');
    checkboxes.forEach(cb => {
        cb.addEventListener('change', updatePlaybookProgress);
    });
}

function updatePlaybookProgress() {
    const total = document.querySelectorAll('.playbook-checkbox').length;
    const checked = document.querySelectorAll('.playbook-checkbox:checked').length;
    const percent = Math.round((checked / total) * 100);

    const progressBar = document.getElementById('playbook-progress-bar');
    const percentText = document.getElementById('playbook-percent-text');

    if (progressBar) progressBar.style.width = `${percent}%`;
    if (percentText) percentText.textContent = `${percent}% Completo`;

    logToTerminal(`Progreso de Playbook de Respuesta a Incidentes: ${checked}/${total} pasos completados (${percent}%).`, 'info');
}
