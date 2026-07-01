import { checkBackendHealth, postAuditConfiguration, fetchAuditHistoryLogs, fetchAuditDetailsById } from "./api.js";
import { updateApiStatus, renderAuditResults, renderHistoryTable } from "./ui.js";

const auditForm        = document.getElementById("audit-submission-form");
const runAuditBtn       = document.getElementById("run-audit-btn");
const refreshHistoryBtn = document.getElementById("refresh-history-btn");
const historyTableBody  = document.getElementById("history-table-body");

async function bootstrap() {
    const isAlive = await checkBackendHealth();
    updateApiStatus(isAlive);
    if (isAlive) {
        await reloadHistoryLogData();
    }
}

async function reloadHistoryLogData() {
    try {
        const response = await fetchAuditHistoryLogs();
        const historyData = response.success ? response.data : response;
        renderHistoryTable(historyData);
    } catch (err) {
        console.error("History log reload routine encountered error:", err);
    }
}

auditForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const nameInput   = document.getElementById("device-name-input").value.trim();
    const ipInput     = document.getElementById("device-ip-input").value.trim();
    const configInput = document.getElementById("router-config-textarea").value.trim();

    // Field validation with clean English feedback
    if (!nameInput || !ipInput || !configInput) {
        alert("Please fill in all required fields: Device Name, IP Address, and Configuration.");
        return;
    }

    try {
        runAuditBtn.disabled = true;
        runAuditBtn.innerHTML = "⏳ Analyzing Configuration...";

        const response = await postAuditConfiguration(nameInput, ipInput, configInput);
        const resultPayload = response.success ? response.data : response;

        renderAuditResults(resultPayload);
        await reloadHistoryLogData();

    } catch (error) {
        alert(`Audit Execution Failed: ${error.message}`);
    } finally {
        runAuditBtn.disabled = false;
        runAuditBtn.innerHTML = "<span>⚡</span> Run Automated Audit";
    }
});

refreshHistoryBtn.addEventListener("click", reloadHistoryLogData);

historyTableBody.addEventListener("click", async (e) => {
    if (e.target.classList.contains("view-details-btn")) {
        const auditId = e.target.getAttribute("data-id");
        try {
            const response = await fetchAuditDetailsById(auditId);
            const resultPayload = response.success ? response.data : response;
            renderAuditResults(resultPayload);
        } catch (err) {
            alert(`Could not fetch details for audit entry #${auditId}`);
        }
    }
});

// Register console testing hook cleanly for development troubleshooting
window.apiDebug = { checkHealth: checkBackendHealth, runAudit: postAuditConfiguration, getHistory: fetchAuditHistoryLogs };

document.addEventListener("DOMContentLoaded", bootstrap);