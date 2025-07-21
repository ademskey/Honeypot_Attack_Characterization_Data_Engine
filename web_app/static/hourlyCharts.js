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
    const chart1Limit = 5;
    const topxDestPorts = createCountDictionary(fullHourlyData, 'dest_port', chart1Limit);
    createBarChart("HourlyChart1", topxDestPorts, "Destination Port", "Count", `Top ${chart1Limit} Destination Ports`);

    // Hourly Chart 2: Top x Cities
    // Small preprocessing -- want to create a subtable with country and city together for better x-axis.
    let geoTable = fullHourlyData
        .filter(row =>
            row["geoip.country_name"] &&
            row["geoip.country_name"].trim() !== "" &&
            row["geoip.city_name"] &&
            row["geoip.city_name"].trim() !== ""
        )
        .map(row => {
            const country = row["geoip.country_name"] === "United States" ? "US" : row["geoip.country_name"];
            const city = row["geoip.city_name"];
            return {
                country_city: `${country}, ${city}`
            };
        });


    //console.log(geoTable);
    const chart2Limit = 5;
    const topXCities = createCountDictionary(geoTable, "country_city", chart2Limit);
    createBarChart("HourlyChart2", topXCities, "Source Country, City", "Num Hits", "Number of Hits from Source City");

    // Hourly Chart 3: Top x Organizations by total number of hits-- Bar Chart 
    const chart3Limit = 10;
    const topXOrganizations = createXYPoints(companyHits, "Org", "Hits", "bar", chart3Limit)
    createBarChart("HourlyChart3", topXOrganizations, "Organization (geoip.as_org)", "Count", `Top ${chart3Limit} Organizations`);


    // Hourly Chart 4: Activity Over Time -- line graph
    const timeIncrementSize = 5; // in seconds.
    const chart4Limit = 5;
    numRowsPerIncrement = rowCountsByTypeAndTime(fullHourlyData, 'type', '@timestamp', timeIncrementSize, chart4Limit);
    createMultiLineChart("HourlyChart4", numRowsPerIncrement, `Top ${chart4Limit} Honeypots Activity Over Time`, "Time", "Number of Entries");
}
