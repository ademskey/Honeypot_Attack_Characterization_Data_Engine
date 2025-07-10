

window.addEventListener("DOMContentLoaded", async () => {
    const data = await loadData();
    if (!data) return;

    const hourly = data.hourly_data["full_hourly_data"];

    renderHourlyCharts(hourly);
});

async function renderHourlyCharts(hourlyData) {

    console.log(hourlyData);

    console.log(Object.keys(hourlyData));  // See what keys are available

    // Hourly Chart 1: Top x Destination Ports -- Bar Chart
    const chart1Limit = 3
    const top10DestPorts = createCountDictionary(hourlyData, 'dest_port', chart1Limit);
    createBarChart("Chart1", top10DestPorts, "Destination Port", "Count", `Top ${chart1Limit} Destination Ports`);

    // Hourly Chart 2: Top x Source Ports -- Bar Chart
    const chart2Limit = 3;
    const top10SrcPorts = createCountDictionary(hourlyData, 'src_port', chart2Limit);
    createBarChart("Chart2", top10SrcPorts, "Source Port", "Count", `Top ${chart2Limit} Source Ports`);
}