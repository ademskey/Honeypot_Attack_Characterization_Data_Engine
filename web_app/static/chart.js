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

function createMultiLineChart(canvasID, dataByType, title, xtitle, ytitle, xtype, timeIncrementSize = 10) {
    const allBuckets = new Set();

    // Collect all unique bucket keys (numeric)
    Object.values(dataByType).forEach(bucketCounts => {
        Object.keys(bucketCounts).forEach(bucket => allBuckets.add(Number(bucket)));
    });

    // Sort bucket timestamps ascending
    const sortedBuckets = Array.from(allBuckets).sort((a, b) => a - b);

    let labels;

    if (xtype === "time") {
        // Convert epoch ms → UTC formatted string
        labels = sortedBuckets.map(ms => {
            const date = new Date(ms);
            const MM = String(date.getUTCMonth() + 1).padStart(2, '0');
            const DD = String(date.getUTCDate()).padStart(2, '0');
            const YYYY = date.getUTCFullYear();
            const HH = String(date.getUTCHours()).padStart(2, '0');
            const mm = String(date.getUTCMinutes()).padStart(2, '0');
            const SS = String(date.getUTCSeconds()).padStart(2, '0');
            return `${MM}/${DD}/${YYYY} ${HH}:${mm}:${SS}`;
        });
    } else {
        // Use raw bucket values directly (categorical or numeric)
        labels = sortedBuckets;
    }

    // Build datasets for each type
    const datasets = Object.entries(dataByType).map(([type, counts], idx) => ({
        label: type,
        data: sortedBuckets.map(bucket => counts[bucket] || 0),
        borderColor: `hsl(${idx * 60}, 70%, 50%)`,
        fill: false
    }));

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


function createLineChart(canvasID, numRowsPerIncrement, title, xtitle, ytitle, xtype = "time", ytype = "linear") {
    const allBuckets = Object.keys(numRowsPerIncrement).map(Number).sort((a, b) => a - b);

    let labels;

    if (xtype === "time") {
        // Convert epoch ms → UTC formatted string
        labels = allBuckets.map(ms => {
            const date = new Date(ms);
            const MM = String(date.getUTCMonth() + 1).padStart(2, '0');
            const DD = String(date.getUTCDate()).padStart(2, '0');
            const YYYY = date.getUTCFullYear();
            const HH = String(date.getUTCHours()).padStart(2, '0');
            const mm = String(date.getUTCMinutes()).padStart(2, '0');
            const SS = String(date.getUTCSeconds()).padStart(2, '0');
            return `${MM}/${DD}/${YYYY} ${HH}:${mm}:${SS}`;
        });
    } else {
        // Use raw bucket values directly
        labels = allBuckets;
    }

    // Extract values in order of sortedBuckets
    const values = allBuckets.map(bucket => numRowsPerIncrement[bucket] || 0);

    const ctx = document.getElementById(canvasID).getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: ytitle,
                data: values,
                borderColor: 'steelblue',
                backgroundColor: 'rgba(70, 130, 180, 0.3)',
                fill: false,
                tension: 0.1
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
                }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: xtitle
                    },
                    ticks: {
                        autoSkip: true,
                        maxRotation: 60,
                        minRotation: 45
                    }
                },
                y: {
                    type: ytype, // ensures a numeric axis
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1,            // force increments of 1
                        callback: function (value) {
                            if (Number.isInteger(value)) {
                                return value;       // show only integers
                            }
                        }
                    }
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
// Used in multi-line graph for activity over time.
function rowCountsByTypeAndTime(data_table, typeKey, timestampKey, incrementSeconds, limit) {
    const counts = {};
    const totalCountsByType = {};
    const bucketTimes = new Set(); // track all unique bucket times

    data_table.forEach(row => {
        const type = row[typeKey];
        const time = new Date(row[timestampKey]).getTime(); // ms since epoch
        const bucketStartMs = Math.floor(time / (incrementSeconds * 1000)) * incrementSeconds * 1000;

        if (!counts[type]) counts[type] = {};
        if (!counts[type][bucketStartMs]) counts[type][bucketStartMs] = 0;
        counts[type][bucketStartMs]++;

        totalCountsByType[type] = (totalCountsByType[type] || 0) + 1;
        bucketTimes.add(bucketStartMs);
    });

    // Find top <limit> honeypot types
    const topTypes = Object.entries(totalCountsByType)
        .sort((a, b) => b[1] - a[1])
        .slice(0, limit)
        .map(entry => entry[0]);

    // Filter only top types
    const filteredCounts = {};
    topTypes.forEach(type => {
        filteredCounts[type] = counts[type];
    });

    return filteredCounts; // numeric epoch ms as keys
}

// Counts the number of rows every <incrementSize> seconds.
// Input: JS table
// The timeStampColumn should be in Date() format.
function countRowsPerTimeIncrement(data, timestampKey, incrementSize) {
    const bucketCounts = {};

    data.forEach(row => {
        const ts = new Date(row[timestampKey]).getTime(); // ms epoch
        if (isNaN(ts)) return;

        const bucketStartMs = Math.floor(ts / (incrementSize * 1000)) * incrementSize * 1000;
        bucketCounts[bucketStartMs] = (bucketCounts[bucketStartMs] || 0) + 1;
    });

    return bucketCounts; // { epoch_ms_bucket: count }
}
