// Threat Intelligence Dashboard JavaScript

let threatsData = [];
let allThreats = [];
let lastUpdated = null;

document.addEventListener('DOMContentLoaded', function() {
    console.log('Threat Intelligence Dashboard initialized');
    loadThreats();
    setInterval(loadThreats, 300000); // Refresh every 5 minutes
});

async function loadThreats() {
    showLoading();
    hideError();

    try {
        console.log('Fetching threat intelligence data...');
        const response = await fetch('/api/threats');  // ✅ fixed endpoint
        const data = await response.json();

        if (data.success) {
            threatsData = data.data;
            allThreats = data.data;
            lastUpdated = new Date();
            updateUI();
            console.log(`Successfully loaded ${threatsData.length} threats`);
        } else {
            throw new Error(data.error || 'Failed to load threat data');
        }
    } catch (error) {
        console.error('Error loading threats:', error);
        showError(error.message);
    } finally {
        hideLoading();
    }
}

function updateUI() {
    updateCounters();
    renderThreats();
}

function updateCounters() {
    const threatCount = document.getElementById('threatCount');
    const lastUpdatedElement = document.getElementById('lastUpdated');
    if (threatCount) threatCount.textContent = `${threatsData.length} Threats`;
    if (lastUpdatedElement && lastUpdated) lastUpdatedElement.textContent = `Updated: ${lastUpdated.toLocaleTimeString()}`;
}

function renderThreats() {
    const container = document.getElementById('threatContainer');
    const emptyState = document.getElementById('emptyState');
    if (!container) return;

    if (threatsData.length === 0) {
        container.innerHTML = '';
        if (emptyState) emptyState.style.display = 'block';
        return;
    }

    if (emptyState) emptyState.style.display = 'none';
    container.innerHTML = threatsData.map(threat => createThreatCard(threat)).join('');
}

function createThreatCard(threat) {
    const riskLevel = calculateRiskLevel(threat.iocs);
    const riskClass = getRiskClass(riskLevel);
    return `
        <div class="col-md-6 col-lg-4 mb-4">
            <div class="card threat-card ${riskClass} fade-in">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h6 class="card-title mb-0">${escapeHtml(threat.title)}</h6>
                    <span class="badge ${getRiskBadgeClass(riskLevel)}">${riskLevel}</span>
                </div>
                <div class="card-body">
                    <p class="card-text">${escapeHtml(threat.summary)}</p>
                    <small class="text-muted">
                        <i class="fas fa-calendar me-1"></i>${threat.published || 'Unknown Date'}
                        ${threat.source ? `<br><i class="fas fa-source me-1"></i>${escapeHtml(threat.source)}` : ''}
                    </small>
                    <div class="ioc-list mt-2">${renderIOCs(threat.iocs)}</div>
                </div>
                <div class="card-footer d-flex justify-content-between align-items-center">
                    <small class="text-muted">IOCs: ${getTotalIOCCount(threat.iocs)}</small>
                    ${threat.link && threat.link !== '#' ? `
                        <a href="${escapeHtml(threat.link)}" target="_blank" class="btn btn-sm btn-outline-primary">
                            <i class="fas fa-external-link-alt me-1"></i> View Source
                        </a>` : ''}
                </div>
            </div>
        </div>
    `;
}

function renderIOCs(iocs) {
    if (!iocs) return '<span class="text-muted">No IOCs detected</span>';
    let html = '';
    if (iocs.urls?.length) html += `<strong>URLs:</strong><br>${iocs.urls.map(u => `<span class="badge badge-url">${escapeHtml(u)}</span>`).join('')}<br>`;
    if (iocs.ips?.length) html += `<strong>IPs:</strong><br>${iocs.ips.map(ip => `<span class="badge badge-ip">${escapeHtml(ip)}</span>`).join('')}<br>`;
    if (iocs.domains?.length) html += `<strong>Domains:</strong><br>${iocs.domains.map(d => `<span class="badge badge-domain">${escapeHtml(d)}</span>`).join('')}<br>`;
    if (iocs.hashes?.length) html += `<strong>Hashes:</strong><br>${iocs.hashes.map(h => `<span class="badge badge-hash">${escapeHtml(h.slice(0, 16))}...</span>`).join('')}<br>`;
    return html || '<span class="text-muted">No IOCs detected</span>';
}

function calculateRiskLevel(iocs) {
    if (!iocs) return 'LOW';
    let score = (iocs.urls?.length || 0) * 2 +
                (iocs.ips?.length || 0) * 3 +
                (iocs.domains?.length || 0) * 2 +
                (iocs.hashes?.length || 0) * 4;
    return score >= 10 ? 'HIGH' : score >= 5 ? 'MEDIUM' : 'LOW';
}

function getRiskClass(level) {
    return { HIGH: 'high-risk', MEDIUM: 'medium-risk', LOW: 'low-risk' }[level] || 'low-risk';
}

function getRiskBadgeClass(level) {
    return { HIGH: 'bg-danger', MEDIUM: 'bg-warning', LOW: 'bg-success' }[level] || 'bg-secondary';
}

function getTotalIOCCount(iocs) {
    if (!iocs) return 0;
    return (iocs.urls?.length || 0) + (iocs.ips?.length || 0) + (iocs.domains?.length || 0) + (iocs.hashes?.length || 0);
}

function showLoading() {
    const el = document.getElementById('loadingIndicator');
    if (el) el.style.display = 'block';
}

function hideLoading() {
    const el = document.getElementById('loadingIndicator');
    if (el) el.style.display = 'none';
}

function showError(msg) {
    const alert = document.getElementById('errorAlert');
    const message = document.getElementById('errorMessage');
    if (alert && message) {
        message.textContent = msg;
        alert.style.display = 'block';
    }
}

function hideError() {
    const alert = document.getElementById('errorAlert');
    if (alert) alert.style.display = 'none';
}

function refreshThreats() {
    console.log('Manual refresh triggered');
    loadThreats();
}

function escapeHtml(text) {
    if (!text) return '';
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return text.replace(/[&<>"']/g, m => map[m]);
}

// 🔍 Filter logic
function filterThreats() {
    const searchTerm = document.getElementById('searchInput')?.value.toLowerCase() || '';
    const sourceFilter = document.getElementById('sourceFilter')?.value || '';
    const riskFilter = document.getElementById('riskFilter')?.value || '';

    const filtered = allThreats.filter(threat => {
        const text = `${threat.title} ${threat.summary} ${JSON.stringify(threat.iocs)}`.toLowerCase();
        const matchesSearch = searchTerm === '' || text.includes(searchTerm);
        const matchesSource = sourceFilter === '' || (threat.source && threat.source.includes(sourceFilter));
        const risk = calculateRiskLevel(threat.iocs);
        const matchesRisk = riskFilter === '' || risk === riskFilter;
        return matchesSearch && matchesSource && matchesRisk;
    });

    renderFilteredThreats(filtered);
}

function renderFilteredThreats(threats) {
    const container = document.getElementById('threatContainer');
    if (!container) return;
    container.innerHTML = threats.length
        ? threats.map(createThreatCard).join('')
        : '<div class="col-12 text-center py-5"><p class="text-muted">No threats match your search criteria.</p></div>';
}

// 📤 Export
function exportIOCs(format) {
    const rows = [];
    allThreats.forEach(t => {
        const src = t.source || 'Unknown';
        const pub = t.published || 'Unknown';
        const type = t.threat_type || 'Unknown';
        (t.iocs.urls || []).forEach(v => rows.push({ type: 'URL', value: v, source: src, threat_type: type, published: pub }));
        (t.iocs.ips || []).forEach(v => rows.push({ type: 'IP', value: v, source: src, threat_type: type, published: pub }));
        (t.iocs.domains || []).forEach(v => rows.push({ type: 'Domain', value: v, source: src, threat_type: type, published: pub }));
        (t.iocs.hashes || []).forEach(v => rows.push({ type: 'Hash', value: v, source: src, threat_type: type, published: pub }));
    });

    if (format === 'csv') exportAsCSV(rows);
    else if (format === 'json') exportAsJSON(rows);
}

function exportAsCSV(rows) {
    const csv = [
        ['Type', 'Value', 'Source', 'Threat Type', 'Published'],
        ...rows.map(r => [r.type, `"${r.value}"`, `"${r.source}"`, `"${r.threat_type}"`, `"${r.published}"`])
    ].map(row => row.join(',')).join('\n');
    downloadFile(csv, 'threat_iocs.csv', 'text/csv');
}

function exportAsJSON(rows) {
    const json = JSON.stringify(rows, null, 2);
    downloadFile(json, 'threat_iocs.json', 'application/json');
}

function exportSummary() {
    const summary = {
        generated_at: new Date().toISOString(),
        total_threats: allThreats.length,
        threat_sources: [...new Set(allThreats.map(t => t.source).filter(Boolean))],
        total_iocs: {
            urls: allThreats.reduce((s, t) => s + (t.iocs.urls?.length || 0), 0),
            ips: allThreats.reduce((s, t) => s + (t.iocs.ips?.length || 0), 0),
            domains: allThreats.reduce((s, t) => s + (t.iocs.domains?.length || 0), 0),
            hashes: allThreats.reduce((s, t) => s + (t.iocs.hashes?.length || 0), 0)
        },
        threats: allThreats
    };
    downloadFile(JSON.stringify(summary, null, 2), 'threat_summary.json', 'application/json');
}

function downloadFile(content, filename, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
