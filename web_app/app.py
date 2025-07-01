from packages import *

app = Flask(__name__)

# Sample DataFrame
data = {
    'month': ['Jan', 'Feb', 'Mar', 'Apr', 'May'] * 5,
    'type': ['A'] * 5 + ['B'] * 5 + ['C'] * 5 + ['D'] * 5 + ['E'] * 5,
    'sales': [120, 130, 125, 140, 150,
              80, 95, 100, 110, 120,
              200, 210, 190, 220, 230,
              50, 55, 53, 60, 65,
              160, 170, 165, 180, 190]
}
df = pd.DataFrame(data)
# df = get_data()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/data')
def chart_data():
    pivot = df.pivot(index='month', columns='type', values='sales').fillna(0)
    labels = pivot.index.tolist()
    datasets = [
        {'label': col, 'data': pivot[col].tolist()}
        for col in pivot.columns
    ]
    return jsonify({'labels': labels, 'datasets': datasets})

if __name__ == '__main__':
    app.run(debug=True)
