async function renderChart() {
    const response = await fetch('/data');
    const chartData = await response.json();

    const ctx = document.getElementById('salesChart').getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: chartData.labels,
            datasets: chartData.datasets.map((dataset, index) => ({
                label: dataset.label,
                data: dataset.data,
                borderWidth: 2,
                fill: false,
                borderColor: `hsl(${index * 60}, 70%, 50%)`
            }))
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

renderChart();
