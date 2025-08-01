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

    return { historical_data, hourly_data, honeypot_summaries };
}