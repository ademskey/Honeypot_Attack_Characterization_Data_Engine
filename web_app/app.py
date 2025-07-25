from packages import *
import query_and_process

app = Flask(__name__)

UPDATE_TIME = 3600 # in seconds

# Runs a background thread to run Adam + Caitlyn's pipeline every [update_time] seconds.
# to provide continuously updated data.
running_lock = threading.Lock()
def update_data_loop():
    while True:
        if running_lock.acquire(blocking=False):
            try:
                print("Starting a new data update cycle...", flush=True)
                query_and_process.main()
                print("Data update cycle completed.", flush=True)
            except Exception as e:
                print(f"Data update failed: {e}", flush=True)
            finally:
                running_lock.release()
        else:
            print("[WARN] Previous data update still running. Skipping this cycle.", flush=True)

        time.sleep(UPDATE_TIME)
        
# Browser Page appearance
@app.route('/')
def index():
    return render_template('home.html')

@app.route('/home.html')
def home():
    return render_template('home.html')

@app.route('/hourly.html')
def hourly_page():
    return render_template('hourly.html')

@app.route('/historical.html')
def historical_page():
    return render_template('historical.html')

@app.route('/honeypot.html')
def honeypot_page():
    return render_template('honeypot.html')

@app.route('/data', methods=['POST', 'PUT', 'PATCH', 'DELETE', 'CONNECT'])
def data_path():
    return "UNAUTHORIZED HTTP ACCESS TO HONEYPOT DATA DETECTED"


# Returns dictionary of flat json files so that JS can use it, keeping table structure of the pandas df.
@app.route('/data')
def chart_data():
    try:
        historical_dfs = {
            name: df.fillna("").to_dict(orient='records')
            for name, df in get_tables_in_folder('historical_data').items()
        }

        hour_dfs = {
            name: df.fillna("").to_dict(orient='records')
            for name, df in get_tables_in_folder('hourly_data').items()
        }

        summary_dfs = {
            name: df.fillna("").to_dict(orient='records')
            for name, df in get_tables_in_folder('historical_data/honeypot_summaries').items()
        }

        return jsonify({
            "historical_data": historical_dfs,
            "hourly_data": hour_dfs,
            "honeypot_summaries": summary_dfs
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

# Only start update loop if not in the reloader subprocess (running for first time)
    # Don't want to interrrupt background thread that updates the dataset.
if __name__ == '__main__':
    # Run the background update thread ONLY in the final reloader process
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        print("Background update thread started")
        threading.Thread(target=update_data_loop, daemon=True).start()

    app.run(debug=True)
