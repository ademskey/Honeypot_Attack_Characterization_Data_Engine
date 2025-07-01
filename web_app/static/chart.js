async function renderCharts() {
    const response = await fetch('/data'); // in app.py
    const data_table = await response.json(); // the js uses the table-like json format.


    // // For each chart, create a new dictionary where x-axis is the key, and value to plot is the value.
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

    // Plotting ports over time
    portsByTime = {};

    portsByTime = data_table.map(row => ({
        x: row.time,
        y: parseInt(row.dest_port)
    }));

    const ctx4 = document.getElementById('Chart4').getContext('2d');
    new Chart(ctx4, {
        type: 'scatter',
        data: {
            datasets: [{
                label: 'Ports over Time',
                data: portsByTime,
                backgroundColor: 'steelblue'
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Ports over Time'
                }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Time'
                    },
                    beginAtZero: true
                },
                y: {
                    title: {
                        display: true,
                        text: 'Destination Port'
                    },
                    beginAtZero: true
                }
            }
        }
    });
}


renderCharts();