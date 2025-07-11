window.addEventListener("DOMContentLoaded", async () => {
    const data = await loadData();
    if (!data) return;

    const hourly = data.historical_data;

    renderHourlyCharts(hourly);
});

async function renderHourlyCharts(historicalData) {

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
    const chart2Limit = 5;
    const topXOrganizations = createXYPoints(companyHits, "Org", "Hits", "bar", chart2Limit);
    createBarChart("HistChart2", topXOrganizations, "Organization (geoip.as_org)", "Count", `Top ${chart2Limit} Organizations`);

    // Historical Chart 3: Top x Source IP Hits -- Bar Chart
    const chart3Limit = 10;
    const srcIPsByPort = createXYPoints(ipHits, "ip", "hits", "bar", chart3Limit);
    createBarChart("HistChart3", srcIPsByPort, "Source IP", "Number of Hits", `Top ${chart3Limit} Source IPs`)



    // Historical Chart 8 (Big Box): Time vs Dest Port -- Scatter Plot
    console.log(timeandPort);
    //flattenedTimeandPort = flattenTable(timeandPort, "@timestamp");
    //console.log(flattenedTimeandPort);
}