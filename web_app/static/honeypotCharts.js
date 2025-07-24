document.addEventListener("DOMContentLoaded", async () => {
    const selectedHoneypot = localStorage.getItem("selectedHoneypot");
    if (!selectedHoneypot) return;

    // Page Title
    document.getElementById("honeypot-title").textContent = selectedHoneypot;

    // Get ports for this honeypot and display in html
    const ports = getPortsByType(null, selectedHoneypot);
    const portsElement = document.getElementById("honeypot-ports");
    portsElement.textContent = ports.length > 0
        ? `Ports: ${ports.join(", ")}`
        : "No ports found for this honeypot.";

    // Retrieve data from csvs and get selected honeypot tables only
    const data = await loadData();
    if (!data) {
        return;
    }
    const honeypotSummary = data.honeypot_summaries[`${selectedHoneypot}_summary`];
    if (honeypotSummary) {
        renderHoneypotCharts(honeypotSummary, selectedHoneypot);
    }
});

async function renderHoneypotCharts(honeypotData, honeypotName) {

    // Honeypot Chart 1: Top x Source IPs
    const chart1Limit = 3;
    topxSourceIPs = createCountDictionary(honeypotData, "ip", chart1Limit);
    createBarChart("HoneypotChart1", topxSourceIPs, "Source IP Address", "Count", `Top ${chart1Limit} Source IPs for ${honeypotName}`);

    // Honeypot Chart 2: Top x Organizations
    const chart2Limit = 3;
    topxOrgs = createCountDictionary(honeypotData, "org", chart2Limit);
    createBarChart("HoneypotChart2", topxOrgs, "Organization", "Count", `Top ${chart2Limit} Organizations for ${honeypotName}`);


    // Honeypot Chart 4: Activity over Time
    const timeIncrementSize = 100; // in seconds.
    numRowsPerIncrement = countRowsPerTimeIncrement(honeypotData, '@timestamp', timeIncrementSize);
    createLineChart("HoneypotChart4", numRowsPerIncrement, `${honeypotName} Activity Over Time`, "Time", "Number of Entries", "time", "linear");
}
