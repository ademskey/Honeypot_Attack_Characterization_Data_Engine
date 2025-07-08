from packages import *
from query_script import collect_honeypot_data


# Insert data pipeline logic here. Performs pull of raw data + data cleaning. Return cleaned pandas dataframe.
# used in update_data_loop() in app.py for continuous refresh.
def get_df():

    # collect_honeypot_data() eventually.

    # fake DataFrame. replace with caitlyn's pipeline that uses honeypot_data.jsonl
    # return collection of csv's that are in either
    data = {
        'dest_port': [1, 2, 3, 4, 5,
                6, 7, 8, 9, 10,
                11, 12, 13, 14,
                15, 16, 17, 18, 19,
                20, 21, 22, 23, 24, 25],
        'src_port': ['12', '12', '1', '2', '2'] * 5,
        'src_ip': ['1.355.224.22', '153.462.34443', '234.5223.423', '131.34.31.2', '2.243.12.3'] * 5,
        'type': ['Cowrie'] * 5 + ['Honeypot'] * 5 + ['EndlessSSH'] * 5 + ['Ciscoasa'] * 5 + ['Medpot'] * 5,
        '@timestamp':
   [ "2025-07-01T20:33:58.327Z",
    "2025-07-01T20:33:57.000Z",
    "2025-07-01T20:33:56.339Z",
    "2025-07-01T20:33:55.411Z",
    "2025-07-01T20:33:55.402Z",
    "2025-07-01T20:33:55.322Z",
    "2025-07-01T20:33:55.113Z",
    "2025-07-01T20:33:55.113Z",
    "2025-07-01T20:33:55.095Z",
    "2025-07-01T20:33:55.000Z",
    "2025-07-01T20:33:55.000Z",
    "2025-07-01T20:33:55.000Z",
    "2025-07-01T20:33:55.000Z",
    "2025-07-01T20:33:55.000Z",
    "2025-07-01T20:33:55.000Z",
    "2025-07-01T20:33:55.000Z",
    "2025-07-01T20:33:55.000Z",
    "2025-07-01T20:33:54.613Z",
    "2025-07-01T20:33:54.000Z",
    "2025-07-01T20:33:54.000Z",
    "2025-07-01T20:33:54.000Z",
    "2025-07-01T20:33:54.000Z",
    "2025-07-01T20:33:54.000Z",
    "2025-07-01T20:33:54.000Z",
    "2025-07-01T20:33:54.001Z"]
,
        'geoip.as_org': ['Org1'] * 5 + ['Org2'] * 5 + ['Org3'] * 5 + ['Org4'] * 5 + ['Org5'] * 5
    }
    df = pd.DataFrame(data)
    print(df)
    # may need to add a formatted timestamp column
    return df