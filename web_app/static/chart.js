async function renderCharts() {
    const response = await fetch('/data'); // in app.py
    const data_table = await response.json(); // the js uses the table-like json format.

    // Bar graphs have associated variables called "chartxLimit". This is the top x number of bars to show.
    // Scatter Plots: Must make sure type is correct according to what your x axis is. Use "linear" for continuous
    // stuff like time and "category" for discrete values,  like IP

    // Chart 1: Top x Destination Ports -- Bar Chart
    const chart1Limit = 3
    const top10DestPorts = createCountDictionary(data_table, 'dest_port', chart1Limit);
    const chart1 = createBarChart("Chart1", top10DestPorts, "Destination Port", "Count", `Top ${chart1Limit} Destination Ports`);

    // Chart 2: Top x Source Ports -- Bar Chart
    const chart2Limit = 3;
    const top10SrcPorts = createCountDictionary(data_table, 'src_port', chart2Limit);
    const chart2 = createBarChart("Chart2", top10SrcPorts, "Source Port", "Count", `Top ${chart2Limit} Source Ports`);

    // Chart 3: Destination Ports Over Time -- Scatter Plot
    const portsOverTime = makeXYPoints(data_table, '@timestamp', 'dest_port');
    const chart3 = createScatterPlot("Chart3", portsOverTime, "Time", "Destination Port", "Destination Ports over Time", "linear");
    // Chart 4: Number of Attacks Per Honeypot (number of rows for each type.) -- Bar Chart
    chart4Limit = null;
    const attacksPerType = createCountDictionary(data_table, 'type', chart4Limit);
    const chart4 = createBarChart("Chart4", attacksPerType, "Honeypot", "Attack Count", "Number of Attacks Per Honeypot");

    // Chart 5: Top x Organizations -- Bar Chart
    const chart5Limit = 5;
    const topXOrganizations = createCountDictionary(data_table, 'geoip.as_org', chart5Limit);
    const chart5 = createBarChart("Chart5", topXOrganizations, "Organization (geoip.as_org)", "Count", `Top ${chart5Limit} Organizations`);

    // Chart 6: Activity Over Time -- line graph
    const chart6LinestoShow = 5;
    const timeIncrementSize = 5; // in seconds.
    numRowsPerIncrement = rowCountsByTypeAndTime(data_table, 'type', '@timestamp', timeIncrementSize);
    const chart6 = createMultiLineChart("Chart6", numRowsPerIncrement, "Activity Over Time", "Time", "Number of Entries");

    // Chart 7: Source IP vs Destinatation Port -- Scatter Plot
    const IPsByPort = makeXYPoints(data_table, "src_ip", "dest_port");
    const chart7 = createScatterPlot("Chart7", IPsByPort, "Source IP", "Destination Port", "Source IP vs Destination Port", "category");


    function createMultiLineChart(canvasID, dataByType, title, xtitle, ytitle) {
        const allBuckets = new Set();

        // Collect all unique bucket keys across all types
        Object.values(dataByType).forEach(bucketCounts => {
            Object.keys(bucketCounts).forEach(bucket => allBuckets.add(Number(bucket)));
        });

        const sortedBuckets = Array.from(allBuckets).sort((a, b) => a - b);

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
                labels: sortedBuckets,
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

    // // For creating simple charts where x and y values are straight values from the cleaned data.
    // // if needing aggregated values or values not in the table then do this manually.
    // function createColumnDictionary(data, keyColumn, valueColumn) {
    //     const dict = {};
    //     data.forEach(row => {
    //         const key = row[keyColumn];
    //         const value = row[valueColumn];
    //         if (key === undefined || value === undefined) {
    //             console.warn('Skipping row due to undefined key/value:', row);
    //             return;
    //         }
    //         if (!dict[key]) dict[key] = 0;
    //         dict[key] += value;
    //     });

    //     return dict;
    // }


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
    function rowCountsByTypeAndTime(data, valueToCount, timeColumn, incrementSize) {
        const grouped = {};

        data.forEach(row => {
            const type = row[valueToCount];
            const time = row[timeColumn];

            if (type === undefined || time === undefined || isNaN(time)) return;

            const bucket = Math.floor(time / incrementSize) * incrementSize;

            if (!grouped[type]) grouped[type] = {};
            if (!grouped[type][bucket]) grouped[type][bucket] = 0;

            grouped[type][bucket] += 1;
        });

        return grouped;
    }

}

renderCharts();