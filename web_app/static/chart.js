/* Helper functions to a couple different types of charts for reusability*/

/* Bar graphs have associated variables called "chartxLimit". This is the top x number of bars to show.
// Scatter Plots: Must make sure type is correct according to what your x axis is. Use "linear" for continuous
// stuff like time and "category" for discrete values,  like IP */

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
                data: data,
                backgroundColor: 'steelblue',
                pointRadius: 4
            }]
        },
        options: {
            indexAxis: 'x',
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
                        label: function (context) {
                            return `City: ${context.raw.x}, IP: ${context.raw.y}`;
                        }
                    }
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
                        autoSkip: true,
                        maxRotation: 90,
                        minRotation: 45
                    }
                },
                y: {
                    type: type,
                    title: {
                        display: true,
                        text: ytitle
                    },
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

// For Scatter Plot and Bar chart
function createXYPoints(data, xKey, yKey, chartType, limit = null) {
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

function flattenTable(data_table, key) {
    console.log("key used for flattening: ", key);
    console.log(data_table[key]);
    const flattened = [];

    data_table.forEach(row => {
        const timestamp = row.timestamp;
        let portList;
        try {
            portList = JSON.parse(row[key]);
        } catch (e) {
            console.error("Error parsing port list:", row[key]);
            return;
        }

        if (Array.isArray(portList)) {
            portList.forEach(port => {
                if (!isNaN(port)) {
                    flattened.push({
                        timestamp: timestamp,
                        port: port
                    });
                }
            });
        }
    });

    return flattened;
}

function categoriestoIndex(data, key) {
    const unique = [...new Set(data.map(row => row[key] || "Unknown"))];
    const mapping = {};
    unique.forEach((val, idx) => mapping[val] = idx);
    return { mapping, labels: unique };
}