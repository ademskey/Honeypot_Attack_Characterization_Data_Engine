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

    // Hourly Chart 2: Top x Organizations -- Bar Chart
    const chart2Limit = 5;
    const topXOrganizations = createXYPoints(companyHits, "Org", "Hits", "bar", chart2Limit);
    createBarChart("HourlyChart2", topXOrganizations, "Organization (geoip.as_org)", "Count", `Top ${chart2Limit} Organizations`);



    // Hourly Chart 7: Activity Over Time -- line graph
    //const chart6LinestoShow = 5;s
    const timeIncrementSize = 5; // in seconds.
    numRowsPerIncrement = rowCountsByTypeAndTime(fullHourlyData, 'type', '@timestamp', timeIncrementSize);
    createMultiLineChart("HourlyChart7", numRowsPerIncrement, "Activity Over Time", "Time", "Number of Entries");
}