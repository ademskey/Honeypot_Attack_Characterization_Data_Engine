from packages import *
from query_script import collect_honeypot_data


# Insert data pipeline logic here
def get_df():
        # Sample DataFrame. replace with caitlyn's pipeline that uses honeypot_data.jsonl
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
    return df
