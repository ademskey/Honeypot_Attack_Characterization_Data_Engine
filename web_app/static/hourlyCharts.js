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
    createTextforHTMLID(`Top ${chart1Limit} Destination Ports`, "hourly-chart1-title");
    const topxDestPorts = createCountDictionary(fullHourlyData, 'dest_port', chart1Limit);
    createBarChart("hourly-chart1", topxDestPorts, "Destination Port", "Count", "");

    // Hourly Chart 2: Top x Cities
    // Preprocessing -- want to create a subtable with country and city together for better x-axis.
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
    const chart2Limit = 5;
    createTextforHTMLID("Number of Hits from Source City", "hourly-chart2-title");
    const topXCities = createCountDictionary(geoTable, "country_city", chart2Limit);
    createBarChart("hourly-chart2", topXCities, "Source Country, City", "Num Hits", "");

    // Hourly Chart 3: Top x Organizations by total number of hits-- Bar Chart 
    const chart3Limit = 10;
    createTextforHTMLID(`Top ${chart3Limit} Organizations`, "hourly-chart3-title");
    const topXOrganizations = createXYPoints(companyHits, "Org", "Hits", "bar", chart3Limit);
    createBarChart("hourly-chart3", topXOrganizations, "Organization (geoip.as_org)", "Count", "");

    // Hourly Chart 4: Activity Over Time -- line graph
    const timeIncrementSize = 5; // in seconds.
    const chart4Limit = 5;
    createTextforHTMLID(`Top ${chart4Limit} Honeypots Activity Over Time`, "hourly-chart4-title")
    numRowsPerIncrement = rowCountsByTypeAndTime(fullHourlyData, "type", "@timestamp", timeIncrementSize, chart4Limit);
    createMultiLineChart("hourly-chart4", numRowsPerIncrement, "", "Time", "Number of Hits", "time", timeIncrementSize);
}
