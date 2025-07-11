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

    // Hourly Chart 3: City Name and Source IPs -- Scatter Plot
    const { mapping: cityIndexMap, labels: cityLabels } = categoriestoIndex(fullHourlyData, "geoip.city_name");
    const { mapping: ipIndexMap, labels: ipLabels } = categoriestoIndex(fullHourlyData, "src_ip");

    const points = fullHourlyData.map(row => {
        const city = row["geoip.city_name"] || "Unknown";
        const ip = row["src_ip"];
        return {
            x: cityIndexMap[city],
            y: ipIndexMap[ip]
        };
    });

    const ctx = document.getElementById("HourlyChart3").getContext("2d");
    new Chart(ctx, {
        type: 'scatter',
        data: {
            datasets: [{
                data: points,
                backgroundColor: 'steelblue',
                pointRadius: 4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Source IPs by City'
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const city = cityLabels[context.raw.x];
                            const ip = ipLabels[context.raw.y];
                            return `City: ${city}, IP: ${ip}`;
                        }
                    }
                },
                legend: { display: false }
            },
            scales: {
                x: {
                    type: 'linear',
                    ticks: {
                        callback: function (value) {
                            return cityLabels[value] || '';
                        },
                        stepSize: 1
                    },
                    title: {
                        display: true,
                        text: 'City'
                    }
                },
                y: {
                    type: 'linear',
                    ticks: {
                        callback: function (value) {
                            return ipLabels[value] || '';
                        },
                        stepSize: 1
                    },
                    title: {
                        display: true,
                        text: 'Source IP'
                    }
                }
            }
        }
    });

    // Hourly Chart 4: Organization and Source IPs -- Scatter Plot


    // Hourly Chart 7: Activity Over Time -- line graph
    //const chart6LinestoShow = 5;s
    const timeIncrementSize = 5; // in seconds.
    numRowsPerIncrement = rowCountsByTypeAndTime(fullHourlyData, 'type', '@timestamp', timeIncrementSize);
    createMultiLineChart("HourlyChart7", numRowsPerIncrement, "Activity Over Time", "Time", "Number of Entries");
}