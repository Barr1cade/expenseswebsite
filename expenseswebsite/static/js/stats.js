const renderChart = (data, labels) =>{
var ctx = document.getElementById('myChart').getContext('2d');
var myChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
        labels: labels,
        datasets: [{
            label: 'Last 6 months expenses.',
            data: data,
            backgroundColor: [
                'rgba(255, 99, 132, 0.2)',
                'rgba(54, 162, 235, 0.2)',
                'rgba(255, 206, 86, 0.2)',
                'rgba(75, 192, 192, 0.2)',
                'rgba(153, 102, 255, 0.2)',
                'rgba(255, 159, 64, 0.2)',
                'rgba(30, 8, 140, 0.2)',
                'rgba(232, 228, 16, 0.2);',
                'rgba(232, 121, 16, 0.2);',
                'rgba(16, 139, 232, 0.2);'
            ],
            borderColor: [
                'rgba(255, 99, 132, 1)',
                'rgba(54, 162, 235, 1)',
                'rgba(255, 206, 86, 1)',
                'rgba(75, 192, 192, 1)',
                'rgba(153, 102, 255, 1)',
                'rgba(255, 159, 64, 1)',
                'rgba(30, 8, 140, 1)',
                'rgba(232, 228, 16, 1);',
                'rgba(232, 121, 16, 1);',
                'rgba(16, 139, 232, 1);'

            ],
            borderWidth: 1
        }]
    },
    options: {
        title:{
            display:true,
            text: 'Расходы по категориям.'
        }
    }
});
};

const getChartData = () => {
    fetch ("/expense_category_summary")
        .then((res) => res.json())
        .then((results) =>{
            const category_data = results.expense_category_data;
            const [labels, data] = [
                Object.keys(category_data),
                Object.values(category_data),
            ];
            renderChart(data, labels)
        })
}

document.onload = getChartData();