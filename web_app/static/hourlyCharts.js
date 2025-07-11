window.addEventListener("DOMContentLoaded", async () => {
    const data = await loadData();
    if (!data) return;

    const hourly = data.hourly_data;

    renderHourlyCharts(hourly);
});

async function renderHourlyCharts(hourlyData) {
    const fullHourlyData = hourlyData["full_hourly_data"];
    const companyHits = hourlyData["company_hits"];

    // Hourly Chart 1: Top x Destination Ports -- Bar Chart
    const chart1Limit = 5
    const topxDestPorts = createCountDictionary(fullHourlyData, 'dest_port', chart1Limit);
    createBarChart("HourlyChart1", topxDestPorts, "Destination Port", "Count", `Top ${chart1Limit} Destination Ports`);

    // Chart 5: Top x Organizations -- Bar Chart
    const chart5Limit = 5;
    const topXOrganizations = createCountDictionary(data_table, 'geoip.as_org', chart5Limit);
    const chart5 = createBarChart("Chart5", topXOrganizations, "Organization (geoip.as_org)", "Count", `Top ${chart5Limit} Organizations`);
}