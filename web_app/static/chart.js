/* Helper functions to a couple different types of charts for reusability*/

/* Bar graphs have associated variables called "chartxLimit". This is the top x number of bars to show.
// Scatter Plots: Must make sure type is correct according to what your x axis is. Use "linear" for continuous
// stuff like time and "category" for discrete values,  like IP */

function getPortsByType(mode = null, selectHoneypot = null) {
    // Raw honeypot -> ports mapping
    const rawData = [
        ["Ciscoasa", [5000, 8443]],
        ["Dicompot", [11112]],
        ["Honeyaml", [8080]],
        ["Medpot", [2575]],
        ["SentryPeer", [5060]],
        ["Abdhoney", [5555]],
        ["Conpot", [161, 2404, 10001, 623, 1025, 50100]],
        ["Cowrie", [22, 23]],
        ["Dionaea", [20, 21, 42, 69, 81, 135, 445, 1433, 1723, 1883, 3306, 27017]],
        ["Elasticpot", [9200]],
        ["H0neytr4p", [443]],
        ["Heralding", [110, 143, 465, 993, 995, 1080, 5432, 5900]],
        ["Ipphoney", [631]],
        ["Mailoney", [25, 587]],
        ["Miniprint", [9100]],
        ["Redishoneypot", [6379]],
        ["Wordpot", [80]]
    ];

    let filteredData = rawData;
    if (selectHoneypot !== null) {
        const found = rawData.find(([name]) => name === selectHoneypot);
        return found ? found[1] : [];  // just return [22, 23] etc.
    }

    if (mode === "scatter") {
        // Scatter format: [{ x: honeypot, y: port }]
        return rawData.flatMap(([honeypot, ports]) =>
            ports.map(port => ({
                x: honeypot,
                y: port
            }))
        );
    }
    else if (mode === "bar") {
        // Bar format: { honeypotName: numPorts }
        const barData = {};
        rawData.forEach(([honeypot, ports]) => {
            barData[honeypot] = ports.length; // number of ports per honeypot
        });
        return barData;
    }
    else {
        console.error("Invalid mode for getPortsByType:", mode);
        return mode === "bar" ? {} : [];
    }
}


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


function createScatterPlot(
    canvasID,
    data,
    xtitle = "[missing]",
    ytitle = "[missing]",
    title = "[missing]",
    xtype = "category",  // default x-axis type
    ytype = "linear"     // default y-axis type
) {
    const ctx4 = document.getElementById(canvasID).getContext('2d');

    new Chart(ctx4, {
        type: 'scatter',
        data: {
            datasets: [{
                label: ytitle,
                data: data, // expects [{x:..., y:...}, ...]
                backgroundColor: 'steelblue',
                pointRadius: 4,
                pointHoverRadius: 6
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
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: context => { return `${xtitle}: ${context.raw.x}, ${ytitle}: ${context.raw.y}`; }
                    }
                }
            },
            scales: {
                x: {
                    type: xtype,
                    title: {
                        display: true,
                        text: xtitle
                    },
                    ticks: {
                        autoSkip: true,
                        maxRotation: 90,
                        minRotation: 45
                    }
                },
                y: {
                    type: ytype,
                    title: {
                        display: true,
                        text: ytitle
                    },
                    beginAtZero: false,
                    ticks: {
                        autoSkip: true
                    }
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
                    type: type,
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
                tooltip: {
                    // callbacks: {
                    //     label: context => { return `${xtitle}: ${context.raw.x}, ${ytitle}: ${context.raw.y}`; }
                    // }
                },
                legend: {
                    display: false,
                }
            },

            scales: {
                x: {
                    ticks: {
                        autoskip: false,
                        minRotation: 45,
                        maxRotation: 45,
                        font: {
                            size: 14
                        },
                    },
                    title: {
                        display: true,
                        text: xtitle
                    },
                    //beginAtZero: true
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

// For Scatter Plot and Bar chart -- data must be an array.
function createXYPoints(data, xKey, yKey, chartType, limit = null) {
    //Ensure data is an array
    if (!Array.isArray(data)) {
        if (typeof data === 'object' && data !== null) {
            data = Object.values(data);
        } else {
            console.error("createXYPoints: data is not an array or object:", data);
            return chartType === 'bar' ? {} : [];
        }
    }

    let output;

    // Filter valid rows
    const filtered = data.filter(row => row[xKey] !== undefined && row[yKey] !== undefined);

    if (chartType === 'scatter') {
        output = filtered.map(row => ({
            x: row[xKey],
            y: row[yKey]
        }));

        if (limit !== null) {
            output = output
                .sort((a, b) => b.y - a.y)
                .slice(0, limit);
        }
    }

    else if (chartType === 'bar') {
        output = {};

        const sorted = filtered
            .sort((a, b) => b[yKey] - a[yKey])
            .slice(0, limit !== null ? limit : filtered.length);

        sorted.forEach(row => {
            output[row[xKey]] = row[yKey];
        });
    }

    return output;
}


// returns the number of each value in a column in a table. Returns top x entries.
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
function rowCountsByTypeAndTime(data_table, typeKey, timestampKey, incrementSeconds, limit) {
    const counts = {};
    const totalCountsByType = {};

    // Step 1: Count per type and time bucket
    data_table.forEach(row => {
        const type = row[typeKey];
        const time = new Date(row[timestampKey]).getTime(); // milliseconds since epoch UTC
        const bucket = Math.floor(time / (incrementSeconds * 1000)); // integer bucket

        if (!counts[type]) counts[type] = {};
        if (!counts[type][bucket]) counts[type][bucket] = 0;
        counts[type][bucket]++;

        // Track total occurrences of each type
        totalCountsByType[type] = (totalCountsByType[type] || 0) + 1;
    });

    // Step 2: Sort types by their total count (descending)
    const topTypes = Object.entries(totalCountsByType)
        .sort((a, b) => b[1] - a[1]) // sort by total counts descending
        .slice(0, limit)             // take only top <limit>
        .map(entry => entry[0]);     // get just the type names

    // Step 3: Filter counts to only include top types
    const filteredCounts = {};
    topTypes.forEach(type => {
        filteredCounts[type] = counts[type];
    });

    return filteredCounts;
}


// function flattenTable(data_table, key) {
//     console.log("key used for flattening: ", key);
//     console.log(data_table[key]);
//     const flattened = [];

//     data_table.forEach(row => {
//         const timestamp = row.timestamp;
//         let portList;
//         try {
//             portList = JSON.parse(row[key]);
//         } catch (e) {
//             console.error("Error parsing port list:", row[key]);
//             return;
//         }

//         if (Array.isArray(portList)) {
//             portList.forEach(port => {
//                 if (!isNaN(port)) {
//                     flattened.push({
//                         timestamp: timestamp,
//                         port: port
//                     });
//                 }
//             });
//         }
//     });

//     return flattened;
// }

// function categoriestoIndex(data, key) {
//     const unique = [...new Set(data.map(row => row[key] || "Unknown"))];
//     const mapping = {};
//     unique.forEach((val, idx) => mapping[val] = idx);
//     return { mapping, labels: unique };
// }