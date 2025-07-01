from packages import *
from data import *

app = Flask(__name__)

df = get_df()
update_time = 5 # in seconds

def update_data_loop():
    global df
    while True:
        try:
            df = get_df()
            print("DataFrame updated")
        except Exception as e:
            print(f"Error updating DataFrame: {e}")
        time.sleep(update_time)  # 5 minutes
        

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
    # Start background data update thread
    threading.Thread(target=update_data_loop, daemon=True).start()
    app.run(debug=True)