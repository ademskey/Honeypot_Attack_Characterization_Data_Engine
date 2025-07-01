from packages import *
from data import *

app = Flask(__name__)

df = get_df()
UPDATE_TIME = 5 # in seconds

# Runs a background thread to run Adam + Caitlyn's pipeline every [update_time] seconds.
# to provide continuously updated data.
def update_data_loop():
    global df
    while True:
        try:
            df = get_df()
            print("DataFrame updated")
        except Exception as e:
            print(f"Error updating DataFrame: {e}")
        time.sleep(UPDATE_TIME)
        
# Browser Page appearance
@app.route('/')
def index():
    return render_template('index.html')

# Returns a flat json file so that JS can use it, keeping table structure of the pandas df.
@app.route('/data')
def chart_data():
    return jsonify(df.to_dict(orient='records')) # df is coming from update_data_loop(). 

if __name__ == '__main__':
    threading.Thread(target=update_data_loop, daemon=True).start()
    app.run(debug=True)