async function renderCharts() {
    try {
        const response = await fetch('/data');
        const data = await response.json();  // Only call .json() once

        const historical_data = data.historical_data;
        const hour_data = data.hourly_data;

        // Proceed to render your charts using historical_data and hour_data
        // e.g. createLineChart(historical_data["some_table"]);
    } catch (error) {
        console.error("Failed to load chart data:", error);
    }

    // Bar graphs have associated variables called "chartxLimit". This is the top x number of bars to show.
    // Scatter Plots: Must make sure type is correct according to what your x axis is. Use "linear" for continuous
    // stuff like time and "category" for discrete values,  like IP

    // Need to create a formatted timestamp column using Date(). 
    data_table.forEach(row => {
        const original = row['@timestamp'];
        const dateObj = new Date(original);
        row.utc_string = dateObj.toISOString();  // e.g., '2025-07-01T20:33:54.000Z'
    });
    // Now the @timestamp column is of type Date.


    // // Chart 1: Top x Destination Ports -- Bar Chart
    // const chart1Limit = 3
    // const top10DestPorts = createCountDictionary(data_table, 'dest_port', chart1Limit);
    // const chart1 = createBarChart("Chart1", top10DestPorts, "Destination Port", "Count", `Top ${chart1Limit} Destination Ports`);

    // // Chart 2: Top x Source Ports -- Bar Chart
    // const chart2Limit = 3;
    // const top10SrcPorts = createCountDictionary(data_table, 'src_port', chart2Limit);
    // const chart2 = createBarChart("Chart2", top10SrcPorts, "Source Port", "Count", `Top ${chart2Limit} Source Ports`);

    // // Chart 3: Destination Ports Over Time -- Scatter Plot
    // const portsOverTime = makeXYPoints(data_table, '@timestamp', 'dest_port');
    // const chart3 = createScatterPlotTime("Chart3", portsOverTime, "Time", "Destination Port", "Destination Ports over Time", "time");

    // // Chart 4: Number of Attacks Per Honeypot (number of rows for each type.) -- Bar Chart
    // const chart4Limit = null;
    // const attacksPerType = createCountDictionary(data_table, 'type', chart4Limit);
    // const chart4 = createBarChart("Chart4", attacksPerType, "Honeypot", "Attack Count", "Number of Attacks Per Honeypot");

    // // Chart 5: Top x Organizations -- Bar Chart
    // const chart5Limit = 5;
    // const topXOrganizations = createCountDictionary(data_table, 'geoip.as_org', chart5Limit);
    // const chart5 = createBarChart("Chart5", topXOrganizations, "Organization (geoip.as_org)", "Count", `Top ${chart5Limit} Organizations`);

    // // Chart 6: Source IP vs Destinatation Port -- Scatter Plot
    // const IPsByPort = makeXYPoints(data_table, "src_ip", "dest_port");
    // const chart7 = createScatterPlot("Chart6", IPsByPort, "Source IP", "Destination Port", "Source IP vs Destination Port", "category");

    // // Chart 7: Activity Over Time -- line graph
    // //const chart6LinestoShow = 5;
    // const timeIncrementSize = 5; // in seconds.
    // numRowsPerIncrement = rowCountsByTypeAndTime(data_table, 'type', '@timestamp', timeIncrementSize);
    // const chart6 = createMultiLineChart("Chart7", numRowsPerIncrement, "Activity Over Time", "Time", "Number of Entries");



    function createMultiLineChart(canvasID, dataByType, title, xtitle, ytitle) {
        const allBuckets = new Set();

        // Collect all unique bucket keys (numeric) across all types
        Object.values(dataByType).forEach(bucketCounts => {
            Object.keys(bucketCounts).forEach(bucket => allBuckets.add(Number(bucket)));
        });

        const sortedBuckets = Array.from(allBuckets).sort((a, b) => a - b);

        // Convert numeric buckets to formatted UTC time strings
        const labels = sortedBuckets.map(bucket => {
            const date = new Date(bucket * 1000 * 5);  // 5 = timeIncrementSize
            const MM = String(date.getUTCMonth() + 1).padStart(2, '0');
            const DD = String(date.getUTCDate()).padStart(2, '0');
            const YYYY = date.getUTCFullYear();
            const HH = String(date.getUTCHours()).padStart(2, '0');
            const mm = String(date.getUTCMinutes()).padStart(2, '0');
            const SS = String(date.getUTCSeconds()).padStart(2, '0');
            return `${MM}/${DD}/${YYYY} ${HH}:${mm}:${SS}`;
        });

        const datasets = Object.entries(dataByType).map(([type, counts], idx) => {
            return {
                label: type,
                data: sortedBuckets.map(bucket => counts[bucket] || 0),
                borderColor: `hsl(${idx * 60}, 70%, 50%)`,
                fill: false
            };
        });

        const ctx = document.getElementById(canvasID).getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: datasets
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: title
                    }
                },
                scales: {
                    x: {
                        title: {
                            display: true,
                            text: xtitle
                        },
                        ticks: {
                            maxRotation: 60,
                            minRotation: 45,
                            autoSkip: true,
                            maxTicksLimit: 20
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: ytitle
                        },
                        beginAtZero: true
                    }
                }
            }
        });
    }


    function createScatterPlot(canvasID, data, xtitle, ytitle, title, type) {
        const ctx4 = document.getElementById(canvasID).getContext('2d');
        new Chart(ctx4, {
            type: 'scatter',
            data: {
                datasets: [{
                    // label: ytitle,
                    data: data,
                    backgroundColor: 'steelblue'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: title
                    },
                    legend: {
                        display: false,
                    }
                },
                scales: {
                    x: {
                        type: type,
                        title: {
                            display: true,
                            text: xtitle
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: ytitle
                        },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    function createScatterPlotTime(canvasID, data, xtitle, ytitle, title, type) {
        const ctx4 = document.getElementById(canvasID).getContext('2d');
        new Chart(ctx4, {
            type: 'scatter',
            data: {
                datasets: [{
                    // label: ytitle,
                    data: data,
                    backgroundColor: 'steelblue'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: title
                    },
                    legend: {
                        display: false,
                    }
                },
                scales: {
                    x: {
                        type: type,
                        title: {
                            display: true,
                            text: xtitle
                        },
                        ticks: {
                            callback: function (value) {
                                const date = new Date(value);
                                const MM = String(date.getUTCMonth() + 1).padStart(2, '0'); // Months are 0-indexed
                                const DD = String(date.getUTCDate()).padStart(2, '0');
                                const YYYY = date.getUTCFullYear();
                                const HH = String(date.getUTCHours()).padStart(2, '0');
                                const mm = String(date.getUTCMinutes()).padStart(2, '0');
                                const SS = String(date.getUTCSeconds()).padStart(2, '0');
                                return `${MM}/${DD}/${YYYY} ${HH}:${mm}:${SS}`;
                            }
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: ytitle
                        },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    function createBarChart(canvasID, data, xtitle, ytitle, title) {
        const labels1 = Object.keys(data);
        const values1 = Object.values(data);

        const ctx1 = document.getElementById(canvasID).getContext('2d');
        new Chart(ctx1, {
            type: 'bar',
            data: {
                labels: labels1,
                datasets: [{
                    label: title,
                    data: values1,
                    backgroundColor: labels1.map((_, i) => `hsl(${i * 60}, 70%, 50%)`)
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: title
                    },
                    legend: {
                        display: false,
                    }
                },

                scales: {
                    x: {
                        title: {
                            display: true,
                            text: xtitle
                        },
                        beginAtZero: true
                    },
                    y: {
                        title: {
                            display: true,
                            text: ytitle
                        },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    // For Scatter Plot
    function makeXYPoints(data, xKey, yKey) {
        return data
            .filter(row => row[xKey] !== undefined && row[yKey] !== undefined)
            .map(row => ({
                x: row[xKey],
                y: row[yKey]
            }));
    }

    function ipToInt(ip) {
        return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0);
    }


    // returns the number of each value in a column. Returns top x entries.
    function createCountDictionary(data, column, topN = null) {
        const dict = {};

        data.forEach(row => {
            const key = row[column];
            if (key === undefined) {
                console.warn('Skipping row due to undefined key:', row);
                return;
            }
            if (!dict[key]) dict[key] = 0;
            dict[key] += 1;
        });

        // Convert to entries, sort by count descending
        const sortedEntries = Object.entries(dict)
            .sort((a, b) => b[1] - a[1]);

        // Limit to top N if specified
        const limitedEntries = topN ? sortedEntries.slice(0, topN) : sortedEntries;

        // Rebuild object
        const result = {};
        limitedEntries.forEach(([key, count]) => {
            result[key] = count;
        });

        return result;
    }

    // Counts of the number of each [valueToCount] in each time increment.
    function rowCountsByTypeAndTime(data_table, typeKey, timestampKey, incrementSeconds) {
        const counts = {};

        data_table.forEach(row => {
            const type = row[typeKey];
            const time = new Date(row[timestampKey]).getTime(); // milliseconds since epoch UTC
            const bucket = Math.floor(time / (incrementSeconds * 1000)); // integer bucket

            if (!counts[type]) counts[type] = {};
            if (!counts[type][bucket]) counts[type][bucket] = 0;
            counts[type][bucket]++;
        });

        return counts;
    }


}

renderCharts();