/*Loads data and replaces the timestamp column into a JS friendly format*/
async function loadData() {
    let historical_data = {};
    let hourly_data = {};

    try {
        const response = await fetch('/data');
        const data = await response.json();

        historical_data = data.historical_data;
        hourly_data = data.hourly_data;
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

    return { historical_data, hourly_data };
}
