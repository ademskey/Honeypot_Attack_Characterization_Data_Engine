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
    const timeAndPort = historicalData["time_vs_port"];

    // Historical Chart 1: Time vs Dest Port -- Scatter Plot
    // Ask Caitlyn if it's easy to flatten the timestamp vs port table instead of list of ports

    // Historical Chart 2: Number of Hits per Honeypot -- Bar Chart
    const hitsPerType = createXYPoints(honeypotHits, "honeypot", "hits", "bar");
    createBarChart("HistChart2", hitsPerType, "Honeypot", "Attack Count", "Number of Attacks Per Honeypot");

    // Historical Chart 3: Top x Organizations -- Bar Chart
    const chart5Limit = 5;
    const topXOrganizations = createXYPoints(companyHits, "Org", "Hits", "bar", chart5Limit);
    createBarChart("HistChart3", topXOrganizations, "Organization (geoip.as_org)", "Count", `Top ${chart5Limit} Organizations`);
}