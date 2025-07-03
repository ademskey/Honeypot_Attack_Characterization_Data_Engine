async function renderCharts() {
    const response = await fetch('/data'); // in app.py
    const data_table = await response.json(); // the js uses the table-like json format.

    // Chart 1: Total Time per Honeypot -- Bar Chart
    const timeByType = createColumnDictionary(data_table, 'type', 'time');
    const chart1 = createBarChart("Chart1", timeByType, 'Total Time per Honeypot Type');

    // Chart 2: Top x Destination Ports -- Bar Chart
    const chart2Limit = 3;
    const top10DestPorts = createCountDictionary(data_table, 'dest_port', chart2Limit);
    const chart2 = createBarChart("Chart2", top10DestPorts, `Top ${chart2Limit} Destination Ports`);

    // Chart 3: Top x Source Ports -- Bar Chart
    const chart3Limit = 3;
    const top10SrcPorts = createCountDictionary(data_table, 'src_port', chart3Limit);
    const chart3 = createBarChart("Chart3", top10SrcPorts, `Top ${chart3Limit} Source Ports`);

    // Chart 4: Destination Ports Over Time -- Scatter Plot
    const portsOverTime = createColumnDictionary(data_table, 'time', 'dest_port');
    const chart4 = createScatterPlot("Chart4", portsOverTime, "Time", "Destination Port", "Destination Ports over Time")

    // Chart 5: Number of Attacks Per Honeypot (number of rows for each type.) -- Bar Chart
    const attacksPerType = createCountDictionary(data_table, 'type', null)
    const chart5 = createBarChart("Chart5", attacksPerType, "Number of Attacks Per Honeypot")


    function createScatterPlot(canvasID, data, xtitle, ytitle, title) {
        const ctx4 = document.getElementById(canvasID).getContext('2d');
        new Chart(ctx4, {
            type: 'scatter',
            data: {
                datasets: [{
                    label: ytitle,
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

    function createBarChart(canvasID, data, title) {
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
                    }
                }
            }
        });
    }

    // For creating simple charts where x and y values are straight values from the cleaned data.
    // if needing aggregated values or values not in the table then do this manually.
    function createColumnDictionary(data, keyColumn, valueColumn) {
        const dict = {};
        data.forEach(row => {
            const key = row[keyColumn];
            const value = row[valueColumn];
            if (key === undefined || value === undefined) {
                console.warn('Skipping row due to undefined key/value:', row);
                return;
            }
            if (!dict[key]) dict[key] = 0;
            dict[key] += value;
        });

        return dict;
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



    // // For each chart, create a new dictionary where x - axis is the key, and value to plot is the value.
    // const timeByType = {};
    // data_table.forEach(row => {
    //     const key = row.type;
    //     if (!timeByType[key]) timeByType[key] = 0;
    //     timeByType[key] += row.time;
    // });

    // const labels1 = Object.keys(timeByType);
    // const values1 = Object.values(timeByType);

    // const ctx1 = document.getElementById('Chart1').getContext('2d');
    // new Chart(ctx1, {
    //     type: 'bar',
    //     data: {
    //         labels: labels1,
    //         datasets: [{
    //             label: 'Total Time per Honeypot Type',
    //             data: values1,
    //             backgroundColor: labels1.map((_, i) => `hsl(${i * 60}, 70%, 50%)`)
    //         }]
    //     },
    //     options: {
    //         responsive: true,
    //         plugins: {
    //             title: {
    //                 display: true,
    //                 text: 'Total Time per Honeypot Type'
    //             }
    //         }
    //     }
    // });


    // const countByPort = {};
    // data_table.forEach(row => {
    //     const port = row.dest_port;
    //     if (!countByPort[port]) countByPort[port] = 0;
    //     countByPort[port] += 1;
    // });

    // const labels2 = Object.keys(countByPort);
    // const values2 = Object.values(countByPort);

    // const ctx2 = document.getElementById('Chart2').getContext('2d');
    // new Chart(ctx2, {
    //     type: 'pie',
    //     data: {
    //         labels: labels2,
    //         datasets: [{
    //             label: 'Connection Count by Port',
    //             data: values2,
    //             backgroundColor: labels2.map((_, i) => `hsl(${i * 60}, 70%, 50%)`)
    //         }]
    //     },
    //     options: {
    //         responsive: true,
    //         plugins: {
    //             title: {
    //                 display: true,
    //                 text: 'Connection Count by Destination Port'
    //             }
    //         }
    //     }
    // });

    // // ============================
    // // 📊 Chart 3: Optional – Time per type per port (multi-line)
    // // ============================
    // const nested = {};  // type -> port -> time
    // data_table.forEach(row => {
    //     if (!nested[row.type]) nested[row.type] = {};
    //     if (!nested[row.type][row.dest_port]) nested[row.type][row.dest_port] = 0;
    //     nested[row.type][row.dest_port] += row.time;
    // });

    // const allTypes = Object.keys(nested);
    // const allPorts = [...new Set(data_table.map(r => r.dest_port))];

    // const datasets3 = allPorts.map((port, i) => ({
    //     label: `Port ${port}`,
    //     data: allTypes.map(type => nested[type]?.[port] || 0),
    //     borderColor: `hsl(${i * 60}, 70%, 50%)`,
    //     fill: false,
    //     borderWidth: 2
    // }));

    // const ctx3 = document.getElementById('Chart3').getContext('2d');
    // new Chart(ctx3, {
    //     type: 'line',
    //     data: {
    //         labels: allTypes,
    //         datasets: datasets3
    //     },
    //     options: {
    //         responsive: true,
    //         plugins: {
    //             title: {
    //                 display: true,
    //                 text: 'Time per Honeypot Type by Port'
    //             }
    //         },
    //         scales: {
    //             y: { beginAtZero: true }
    //         }
    //     }
    // });

    // // Plotting ports over time
    // portsByTime = {};

    // portsByTime = data_table.map(row => ({
    //     x: row.time,
    //     y: parseInt(row.dest_port)
    // }));

    // const ctx4 = document.getElementById('Chart4').getContext('2d');
    // new Chart(ctx4, {
    //     type: 'scatter',
    //     data: {
    //         datasets: [{
    //             label: 'Ports over Time',
    //             data: portsByTime,
    //             backgroundColor: 'steelblue'
    //         }]
    //     },
    //     options: {
    //         responsive: true,
    //         plugins: {
    //             title: {
    //                 display: true,
    //                 text: 'Ports over Time'
    //             }
    //         },
    //         scales: {
    //             x: {
    //                 title: {
    //                     display: true,
    //                     text: 'Time'
    //                 },
    //                 beginAtZero: true
    //             },
    //             y: {
    //                 title: {
    //                     display: true,
    //                     text: 'Destination Port'
    //                 },
    //                 beginAtZero: true
    //             }
    //         }
    //     }
    // });
}


renderCharts();