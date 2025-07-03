from packages import *
from query_script import collect_honeypot_data


# Insert data pipeline logic here. Performs pull of raw data + data cleaning. Return cleaned pandas dataframe.
# used in update_data_loop() in app.py for continuous refresh.
def get_df():

    # collect_honeypot_data() eventually.

    # fake DataFrame. replace with caitlyn's pipeline that uses honeypot_data.jsonl
    data = {
        'dest_port': [1, 2, 3, 4, 5,
                6, 7, 8, 9, 10,
                11, 12, 13, 14,
                15, 16, 17, 18, 19,
                20, 21, 22, 23, 24, 25],
        'src_port': ['12', '12', '1', '2', '2'] * 5,
        'type': ['Cowrie'] * 5 + ['Honeypot'] * 5 + ['EndlessSSH'] * 5 + ['Ciscoasa'] * 5 + ['Medpot'] * 5,
        'time': [1, 2, 3, 4, 5,
                6, 7, 8, 9, 10,
                11, 12, 13, 14,
                15, 16, 17, 18, 19,
                20, 21, 22, 23, 24, 25],
        'geoip.as_org': ['Org1'] * 5 + ['Org2'] * 5 + ['Org3'] * 5 + ['Org4'] * 5 + ['Org5'] * 5
    }
    df = pd.DataFrame(data)
    # may need to add a formatted timestamp column
    return df