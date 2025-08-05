function toggleDropdown() {
    document.getElementById("honeypotDropdown").classList.toggle("show");
}

function selectHoneypot(name) {
    localStorage.setItem("selectedHoneypot", name);
}

document.addEventListener("DOMContentLoaded", async () => {

    window.addEventListener("click", (e) => {
        if (!e.target.matches(".dropbtn")) {
            const dropdowns = document.getElementsByClassName("dropdown-content");
            for (let i = 0; i < dropdowns.length; i++) {
                dropdowns[i].classList.remove("show");
            }
        }
    });

    const selectedHoneypot = localStorage.getItem("selectedHoneypot");
    if (!selectedHoneypot) return;

    // Page Title and one sentence summary.
    document.getElementById("honeypot-title").textContent = selectedHoneypot;
    document.getElementById("honeypot-summary").textContent = getHoneypotSentenceSummary(String(selectedHoneypot));


    // Get ports for this honeypot and display in html
    const ports = getPortsByType(null, selectedHoneypot);
    const portsElement = document.getElementById("honeypot-ports");
    portsElement.textContent = ports.length > 0
        ? `Port(s): ${ports.join(", ")}`
        : "No ports found for this honeypot.";

    // Retrieve data from csvs and get selected honeypot tables only
    const data = await loadData();
    if (!data) {
        return;
    }
    const honeypotSummary = data.honeypot_summaries[`${selectedHoneypot}_summary`];
    const timeVsHoneypotHits = data.historical_data['time_vs_honeypot_hits'];

    const timeVsSelectedHoneypotHits = timeVsHoneypotHits.map(entry => ({
        '@timestamp': entry["@timestamp"],
        hits: entry[selectedHoneypot] || 0
    }));

    if (honeypotSummary) {
        renderHoneypotCharts(honeypotSummary, timeVsSelectedHoneypotHits, selectedHoneypot);
    }
});

async function renderHoneypotCharts(honeypotData, timeVsSelectedHoneypotHits, honeypotName) {

    console.log("time vs selected Honeypot hits:");
    console.log(timeVsSelectedHoneypotHits);
    // Honeypot Chart 1: Top x Source IPs
    const chart1Limit = 3;
    createTextforHTMLID(`Top ${chart1Limit} Source IPs for ${honeypotName}`, "honeypot-chart1-title")
    topxSourceIPs = createCountDictionary(honeypotData, "ip", chart1Limit);
    createBarChart("honeypot-chart1", topxSourceIPs, "Source IP Address", "Count", "");

    // Honeypot Chart 2: Top x Organizations
    const chart2Limit = 3;
    createTextforHTMLID(`Top ${chart2Limit} Organizations for ${honeypotName}`, "honeypot-chart2-title")
    topxOrgs = createCountDictionary(honeypotData, "org", chart2Limit);
    createBarChart("honeypot-chart2", topxOrgs, "Organization", "Count", "");

    // Honeypot Chart 3: Activity over Time
    createTextforHTMLID(`${honeypotName} Activity Over Time`, "honeypot-chart3-title")
    console.log("Sample input data:", timeVsSelectedHoneypotHits.slice(0, 5));
    selectedHoneypotActivityOverTime = createXYPoints(timeVsSelectedHoneypotHits, "@timestamp", "hits", "line", "time");
    console.log("create xy points for chart 3");
    console.log(selectedHoneypotActivityOverTime);
    createLineChart("honeypot-chart3", selectedHoneypotActivityOverTime, "", "Time", "Hits", "time", "linear");
}
