
const ENDPOINTS = {
    checkHealth: "/api/status",  
    runAudit: "/api/audit",
    fetchHistory: "/api/audits"
};
/**
 * Pings the root health check route to confirm backend availability.
 * @returns {Promise<boolean>} True if server answers successfully, false otherwise.
 */
export async function checkBackendHealth() {
    try {
        const response = await fetch(ENDPOINTS.checkHealth);
        if (!response.ok) return false;
        const data = await response.json();
        return data.status === "ok";
    } catch (error) {
        console.error("[API REPO] Health check pipeline failed:", error);
        return false;
    }
}

/**
 * Sends raw Cisco configuration telemetry data to the automated analyzer engine.
 * @param {string} deviceName - Hostname identification.
 * @param {string} deviceIp - Targeted node IPv4 address string.
 * @param {string} routerConfig - Raw Cisco IOS configuration dump string.
 * @returns {Promise<Object>} Formatted API payload resolution.
 */
export async function postAuditConfiguration(deviceName, deviceIp, routerConfig) {
    const payload = {
        device_name: deviceName,
        device_ip: deviceIp,
        router_config: routerConfig
    };

    const response = await fetch(ENDPOINTS.runAudit, {
        method: "POST",
        headers: {
            "Accept": "application/json",
            "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
    });

    if (!response.ok) {
        const errorDetails = await response.json().catch(() => ({ detail: "Unknown server error" }));
        throw new Error(errorDetails.detail || `HTTP Error ${response.status}`);
    }

    return await response.json();
}

/**
 * Queries the persistent SQLite instance to fetch complete historical audit summary runs.
 * @returns {Promise<Object>} System metrics logging matrix collection list.
 */
export async function fetchAuditHistoryLogs() {
    const response = await fetch(ENDPOINTS.fetchHistory);
    
    if (!response.ok) {
        throw new Error(`Failed to extract audit histories. Status code: ${response.status}`);
    }
    
    return await response.json();
}

/**
 * Queries detailed structural vulnerability findings for a specific audit ID block.
 * @param {number|string} auditId - The unique integer identifier of the target historical record.
 * @returns {Promise<Object>} Full detailed report payload containing compliance array entries.
 */
export async function fetchAuditDetailsById(auditId) {
    const response = await fetch(`${ENDPOINTS.fetchHistory}/${auditId}`);
    
    if (!response.ok) {
        if (response.status === 404) {
            throw new Error(`Audit record entry with ID [${auditId}] was not located inside SQLite.`);
        }
        throw new Error(`Server returned status handling error code: ${response.status}`);
    }
    
    return await response.json();
}