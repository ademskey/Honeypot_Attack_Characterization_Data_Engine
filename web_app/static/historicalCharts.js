window.addEventListener("DOMContentLoaded", async () => {
    const data = await loadData();
    if (!data) return;

    const historical = data.historical_data;

    renderHistoricalCharts(historical);
});

async function renderHistoricalCharts(historicalData) {

    // One JS dictionary for each CSV:
    const fullHourlyData = historicalData["full_hourly_data"];
    const companyHits = historicalData["company_hits"];
    const destportHits = historicalData["destport_hits"];
    const honeypotHits = historicalData["honeypot_hits"];
    const ipHits = historicalData["ip_hits"];
    const timeandPort = historicalData["time_vs_port"];

    // Historical Chart 1: Number of Hits per Honeypot -- Bar Chart
    const chart1Limit = 10;
    const hitsPerType = createXYPoints(honeypotHits, "honeypot", "hits", "bar");
    createBarChart("HistChart1", hitsPerType, "Honeypot", "Attack Count", `Top ${chart1Limit} Honeypots`);

    // Historical Chart 2: Top x Organizations by total number of hits-- Bar Chart 
    const chart4Limit = 5;
    const topXOrganizations = createXYPoints(companyHits, "Org", "hits", "bar", chart4Limit);
    createBarChart("HistChart2", topXOrganizations, "Organization (geoip.as_org)", "Count", `Top ${chart4Limit} Organizations`);

    // Historical Chart 3: Top x Source IP Hits -- Bar Chart
    const chart3Limit = 10;
    const topXSrcIPs = createXYPoints(ipHits, "ip", "hits", "bar", chart3Limit);
    createBarChart("HistChart3", topXSrcIPs, "Source IP", "Number of Hits", `Top ${chart3Limit} Source IPs`);

    // Hourly Chart 4: type vs Dest Port
    createScatterPlot("HistChart4", getPortsByType("scatter"), "Honeypot", "Destination Port", "Honeypot vs Destination Port", "category", "linear");

}