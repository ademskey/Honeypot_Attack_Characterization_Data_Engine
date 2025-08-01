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
    createTextforHTMLID(`Top ${chart1Limit} Honeypots`, "historical-chart1-title");
    //const hitsPerType = createXYPoints(honeypotHits, "honeypot", "hits", "bar");
    const hitsPerType = createXYPoints(honeypotHits, "honeypot", "hits", "bar", "", chart1Limit);
    createBarChart("historical-chart1", hitsPerType, "Honeypot", "Attack Count", "");

    // Historical Chart 2: Top x Organizations by total number of hits-- Bar Chart 
    const chart2Limit = 5;
    createTextforHTMLID(`Top ${chart2Limit} Organizations`, "historical-chart2-title")
    //const topXOrganizations = createXYPoints(companyHits, "Org", "hits", "bar", chart2Limit);
    const topXOrganizations = createXYPoints(companyHits, "Org", "hits", "bar", "", chart2Limit);
    createBarChart("historical-chart2", topXOrganizations, "Organization (geoip.as_org)", "Count", "");

    // Historical Chart 3: Top x Source IP Hits -- Bar Chart
    const chart3Limit = 10;
    createTextforHTMLID(`Top ${chart3Limit} Source IPs`, "historical-chart3-title")
    const topXSrcIPs = createXYPoints(ipHits, "ip", "hits", "bar", "", chart3Limit);
    createBarChart("historical-chart3", topXSrcIPs, "Source IP", "Number of Hits", "");

    // Hourly Chart 4: type vs Dest Port
    createTextforHTMLID("Honeypot vs Destination Port", "historical-chart4-title")
    createScatterPlot("historical-chart4", getPortsByType("scatter"), "Honeypot", "Destination Port", "", "category", "linear");

}