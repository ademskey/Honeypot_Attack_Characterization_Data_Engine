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

    // Honeypot Chart 1: Activity over Time
    const timeIncrementSize = 5; // in seconds.
    numRowsPerIncrement = rowCountsByTypeAndTime(honeypotData, 'port', '@timestamp', timeIncrementSize);
    createMultiLineChart("HoneypotChart1", numRowsPerIncrement, `${honeypotName} Activity Over Time`, "Time", "Number of Entries");
}
