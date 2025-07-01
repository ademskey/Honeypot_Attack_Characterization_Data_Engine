from packages import *
from query_script import collect_honeypot_data


# Insert data pipeline logic here. Performs pull of raw data + data cleaning. Return cleaned pandas dataframe.
# used in update_data_loop() in app.py for continuous refresh.
def get_df():

    # collect_honeypot_data() eventually.

    # Sample DataFrame. replace with caitlyn's pipeline that uses honeypot_data.jsonl
    data = {
        'dest_port': ['80', '43', '70', '22', '65'] * 5,
        'type': ['Cowrie'] * 5 + ['Honeypot'] * 5 + ['EndlessSSH'] * 5 + ['Ciscoasa'] * 5 + ['Medpot'] * 5,
        'time': [1, 2, 3, 4, 5,
                6, 6, 7, 8, 9,
                10, 11, 12, 13,
                14, 15, 16, 17, 18,
                19, 20, 21, 22, 23, 24]
    }
    df = pd.DataFrame(data)
    return df