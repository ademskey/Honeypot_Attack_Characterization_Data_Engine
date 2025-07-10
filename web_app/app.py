from packages import *
from data import *

app = Flask(__name__)

#df = get_df()
UPDATE_TIME = 3600 # in seconds

# Runs a background thread to run Adam + Caitlyn's pipeline every [update_time] seconds.
# to provide continuously updated data.
def update_data_loop():
    global df
    while True:
        try:
           # df = get_and_clean_data()
            print("update data loop")
        except Exception as e:
            print(f"Error updating DataFrame: {e}")
        time.sleep(UPDATE_TIME)
        
# Browser Page appearance
@app.route('/')
def index():
    return render_template('hourly.html')

@app.route('/hourly.html')
def hourly_page():
    return render_template('hourly.html')

@app.route('/historical.html')
def historical_page():
    return render_template('historical.html')


# Returns dictionary of flat json files so that JS can use it, keeping table structure of the pandas df.
@app.route('/data')
def chart_data():
    try:
        historical_dfs = {
            name: df.fillna("").to_dict(orient='records')
            for name, df in get_tables_in_folder('historical_data_totals').items()
        }

        hour_dfs = {
            name: df.fillna("").to_dict(orient='records')
            for name, df in get_tables_in_folder('hourly_data').items()
        }

        return jsonify({
            "historical_data": historical_dfs,
            "hourly_data": hour_dfs
        })
    except Exception as e:
        print(f"Error preparing chart data: {e}")
        return jsonify({"error": "Failed to load chart data"}), 500





# helper function for chart_data that returns dictionary of datasets in specified folder.
def get_tables_in_folder(folder):
    folder_path = os.path.join('data', folder)
    if not os.path.isdir(folder_path):
        return {}

    tables = {}
    for file in os.listdir(folder_path):
        if file.endswith('.csv'):
            path = os.path.join(folder_path, file)
            key = os.path.splitext(file)[0]
            try:
                tables[key] = pd.read_csv(path)
                print("getting data csv file success")
            except Exception as e:
                print(f"Failed to load {file}: {e}")
    return tables


if __name__ == '__main__':
    threading.Thread(target=update_data_loop, daemon=True).start()
    app.run(debug=True)