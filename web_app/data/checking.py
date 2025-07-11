# Emily's sanity checking for makign JS charts

import os
import pandas as pd

def load_csvs_into_dataframes():
    base_dir = os.path.dirname(__file__)  # directory of checking.py
    dataframes = {}

    for subfolder in ['historical_data', 'hourly_data']:
        folder_path = os.path.join(base_dir, subfolder)
        for filename in os.listdir(folder_path):
            if filename.endswith('.csv'):
                filepath = os.path.join(folder_path, filename)
                df_key = f"{subfolder}_{filename.replace('.csv', '')}"
                dataframes[df_key] = pd.read_csv(filepath)

    return dataframes

# Example usage
dfs = load_csvs_into_dataframes()

df = dfs['hourly_data_company_hits']

# Ensure columns are correctly named (e.g., 'Org' and 'Hits')
top_5_companies = df.sort_values(by='Hits', ascending=False).head(5)

df = dfs['historical_data_ip_hits']
print(df.sort_values(by='hits', ascending=False).head(5))


df = dfs['hourly_data_full_hourly_data']
print(df.sort_values(by='hits', ascending=False).head(5))