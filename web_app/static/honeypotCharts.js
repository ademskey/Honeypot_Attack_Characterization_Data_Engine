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
    createTextforHTMLID(`Top ${chart1Limit} Source IPs for ${honeypotName}`, "honeypot-chart1-title")
    topxSourceIPs = createCountDictionary(honeypotData, "ip", chart1Limit);
    createBarChart("honeypot-chart1", topxSourceIPs, "Source IP Address", "Count", "");

    // Honeypot Chart 2: Activity over Time
    createTextforHTMLID(`${honeypotName} Activity Over Time`, "honeypot-chart2-title")
    const timeIncrementSize = 100; // in seconds.
    numRowsPerIncrement = countRowsPerTimeIncrement(honeypotData, '@timestamp', timeIncrementSize);
    createLineChart("honeypot-chart2", numRowsPerIncrement, "", "Time", `Number of Hits from ${honeypotName}`, "time", "linear");

    // Honeypot Chart 3: Top x Organizations
    const chart3Limit = 3;
    createTextforHTMLID(`Top ${chart3Limit} Organizations for ${honeypotName}`, "honeypot-chart3-title")
    topxOrgs = createCountDictionary(honeypotData, "org", chart3Limit);
    createBarChart("honeypot-chart3", topxOrgs, "Organization", "Count", "");




    createLineChart()
}
