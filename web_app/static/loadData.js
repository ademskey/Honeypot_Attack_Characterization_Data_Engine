/*Loads data and replaces the timestamp column into a JS friendly format*/
async function loadData() {
    let historical_data = {};
    let hourly_data = {};
    let honeypot_summaries = {}

    try {
        const response = await fetch('/data', {
            headers: {
                'X-Requested-By': 'frontend' // request comes from valid frontend.
            }
        });

        console.log("waiting for data from app.py .....");

        const data = await response.json();

        historical_data = data.historical_data;
        hourly_data = data.hourly_data;
        honeypot_summaries = data.honeypot_summaries

        console.log("got data from app.py");
        console.log(hourly_data);

    } catch (error) {
        console.error("Failed to load chart data:", error);
        return null;
    }

    // For tables with a timestamp column, convert @timestamp to a JS-friendly Date() format.
    for (const table of Object.values(historical_data)) {
        table.forEach(row => {
            if ('@timestamp' in row && row['@timestamp']) {
                const dateObj = new Date(row['@timestamp']);
                row.utc_string = dateObj.toISOString();
            }
        });
    }

    for (const table of Object.values(hourly_data)) {
        table.forEach(row => {
            if ('@timestamp' in row && row['@timestamp']) {
                const dateObj = new Date(row['@timestamp']);
                row.utc_string = dateObj.toISOString();
            }
        });
    }

    for (const table of Object.values(honeypot_summaries)) {
        table.forEach(row => {
            if ('@timestamp' in row && row['@timestamp']) {
                const dateObj = new Date(row['@timestamp']);
                row.utc_string = dateObj.toISOString();
            }
        });
    }

    return { historical_data, hourly_data, honeypot_summaries };
}

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