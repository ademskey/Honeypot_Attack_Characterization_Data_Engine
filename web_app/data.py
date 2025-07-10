from packages import *
from query_script import collect_honeypot_data


# Insert data pipeline logic here. Performs pull of raw data + data cleaning. Return cleaned pandas dataframe.
# used in update_data_loop() in app.py for continuous refresh.
def get_and_clean_data():
    return True

    # collect_honeypot_data() eventually.

    # fake DataFrame. replace with caitlyn's pipeline that uses honeypot_data.jsonl
    # outputs collection of csv's into /data/historical_data and /data/hours_data
