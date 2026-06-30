const indicator = document.getElementById("api-status-indicator");

export function updateApiStatus(isConnected) {
    if (!indicator) return;
    
    // Clean rebuild: Clear everything and reconstruct cleanly
    indicator.innerHTML = "";
    
    // Create the status dot element
    const dot = document.createElement("span");
    dot.className = isConnected 
        ? "status-badge__dot status-badge__dot--connected" 
        : "status-badge__dot";
    
    // Determine the status text
    const statusText = isConnected ? " API: Connected" : " API: Offline";
    
    // Append dot and text node cleanly
    indicator.appendChild(dot);
    indicator.appendChild(document.createTextNode(statusText));
}

export function renderAuditResults(auditData) {
    const resultsSection = document.getElementById("results-section");
    const listContainer = document.getElementById("vulnerabilities-output-list");
    
    document.getElementById("res-target-device").textContent = auditData.device || auditData.device_name;
    document.getElementById("res-target-ip").textContent = auditData.ip_address || auditData.device_ip;
    document.getElementById("res-total-violations").textContent = auditData.total_vulnerabilities;

    listContainer.innerHTML = "";
    
    // Support either nested or raw array layouts
    const findingsArray = auditData.findings || auditData.data?.findings || [];
    
    findingsArray.forEach(finding => {
        const severityClass = (finding.severity || "medium").toLowerCase();
        const card = document.createElement("div");
        card.className = `finding-card finding-card--${severityClass}`;
        card.innerHTML = `
            <div class="finding-card__header">
                <span class="finding-card__id">${finding.id}</span>
                <span class="finding-card__severity finding-card__severity--${severityClass}">${finding.severity}</span>
            </div>
            <div class="finding-card__body">
                <strong>${finding.issue}</strong>
                <p style="margin: 0.5rem 0; font-size: 0.9rem; color: #475569;">${finding.details}</p>
                <code># Remediation Fix:\n${finding.fix}</code>
            </div>
        `;
        listContainer.appendChild(card);
    });
    resultsSection.classList.remove("hidden");
}

export function renderHistoryTable(historyArray) {
    const tbody = document.getElementById("history-table-body");
    if (!tbody) return;
    if (!historyArray || historyArray.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="table-placeholder">No historical records found in database.</td></tr>`;
        return;
    }
    tbody.innerHTML = historyArray.map(row => `
        <tr>
            <td><strong>#${row.id}</strong></td>
            <td>${row.execution_date || "N/A"}</td>
            <td>${row.device_name}</td>
            <td><code>${row.device_ip}</code></td>
            <td><span class="status-badge" style="border-color: var(--color-danger); color: var(--color-danger); font-size: 0.8rem; padding: 0.2rem 0.6rem;">${row.total_vulnerabilities} Risks</span></td>
            <td style="text-align: center;">
                <button type="button" class="btn btn--secondary view-details-btn" data-id="${row.id}" style="padding: 0.4rem 0.8rem; font-size: 0.85rem;">
                     View Report
                </button>
            </td>
        </tr>
    `).join("");
}