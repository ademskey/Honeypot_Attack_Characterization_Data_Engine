# -*- coding: utf-8 -*-
'''
Honeypot_data_cleaning.ipynb
## **Honeypot Data Cleaning Pipeline**
    *Programmer: Caitlyn Boyd*

    *Last Modified: 07/14/2025*
        - CB 07/11/2025: bug fixes, added logs and timing, converted to a class.
        - CB 07/14/2025: bug fixes, optimization, drop unnecessary columns before
            json serialization.
    
    Modified by Emily on 07/14, changed csv paths to add data folder for hourly and historical data subfolders

    **Description:** This program is intended to clean 24 hours of data from T-pot
    that is pulled from elastic pot and converted into a .csv file. Future
    modifications will allow for batch processing of jsonl data taken from the same
    location.
'''

import pandas as pd
import ipaddress
import numpy as np
import warnings
from pandas.errors import PerformanceWarning
import time

'''
    Function: timeit
    Description: wrapper that times each process for efficiency.
    To time a function just add @timeit above the function header.
    
    Last Modified:
        - CB 07/10/2025: changed print format
'''
def timeit(func):
    def wrapper(*args, **kwargs):
        print()
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        print(f"✅ {func.__name__} finished in {elapsed:.2f} seconds")
        return result
    return wrapper

'''
    Class: DataJanitor
    Description: The data cleaning process for the T-pot data.
    
    Programmer: Caitlyn Boyd
    Last Modified: 07/11/2025
        - CB 07/11/2025: added logs
        - CB 07/14/2025: added necessary_before_serial to drop more columns and speed up serialization.
'''
class DataJanitor:
    # all file paths
    def __init__(self):
        warnings.simplefilter("ignore", PerformanceWarning)
        warnings.simplefilter(action='ignore', category=FutureWarning)
        
        self.honeypot_json = "honeypot_data.jsonl"
        
        self.total_company_hits_csv = "data/historical_data/company_hits.csv"
        self.destport_hits_csv = "data/historical_data/destport_hits.csv"
        self.honeypot_hits_csv = "data/historical_data/honeypot_hits.csv"
        self.ip_hits_csv = "data/historical_data/ip_hits.csv"
        self.time_vs_port_csv = "data/historical_data/time_vs_port.csv"
        self.hourly_company_hits_csv = "data/hourly_data/company_hits.csv"
        self.full_hourly_data_csv = "data/hourly_data/full_hourly_data.csv"
        
        self.logs = []
        self.honeypot_info = {"Ciscoasa" : [5000, 8443],
                         "Dicompot" : [11112],
                         "Honeyaml" : [8080],
                         "Medpot" : [2575],
                         "SentryPeer" : [5060],
                         "Abdhoney" : [5555],
                         "Conpot" : [161, 2404, 10001, 623, 1025, 50100],
                         "Cowrie" : [22, 23],
                         "Dionaea" : [20, 21, 42, 69, 81, 135, 445, 1433, 1723, 1883, 3306, 27017],
                         "Elasticpot" : [9200],
                         "H0neytr4p" : [443],
                         "Heralding" : [110, 143, 465, 993, 995, 1080, 5432, 5900],
                         "Ipphoney" : [631],
                         "Mailoney" : [25, 587],
                         "Miniprint" : [9100],
                         "Redishoneypot" : [6379],
                         "Wordpot" : [80]}
        
        self.necessary_before_serial = ['@timestamp', 'dest_ip', 'dest_port', 'src_ip',
                                  'src_port', 'type', 'geoip', 'anomaly', 'flow_id', "eventid","session",
                                  "message", "ip_rep","params", "raw_sig", "os", "link", "tags"]
        
        self.necessary_columns = ['@timestamp', 'dest_ip', 'dest_port', 'src_ip',
                                  'src_port', 'type', 'geoip.country_name',
                                  'geoip.city_name', 'geoip.as_org', 'tags', "flow_id", "anomaly.type",
                                  "anomaly.event", "anomaly.layer", "eventid","session",
                                  "message", "ip_rep","params", "raw_sig", "os", "link"]

    '''
        Function: drop_constant_columns
        Description: drops all columns that contain only one unique value

        Input:
            - df: pandas dataframe
        Output:
            - pandas dataframe with all constant columns dropped
        
        Last Modified: 07/11/2025
            - CB 07/11/2025: added logging

    '''
    def drop_constant_columns(self, df):
        non_list_columns = df.columns[~df.applymap(type).eq(list).any()]
        nunique = df[non_list_columns].nunique(dropna=False)
        constant_columns = [col for col in nunique.index if nunique[col] <= 1 and col != '@timestamp']
        self.logs.append("Constant columns dropped.")
        df.drop(columns=constant_columns, inplace=True)
        return df

    '''
        Function: print_progress

        Description: Prints the size of the original and cleaned dataframes

        Input:
            - last_l: size of original dataframe
            - last_w: width of original dataframe
            - cur_l: size of cleaned dataframe
            - cur_w: width of cleaned dataframe
        Output:
            - Prints the size of the original and cleaned dataframes
        
        Last Modified: 07/11/2025
            - CB 07/11/2025: adds to logs instead of prints


    '''
    def print_progress(self, last_l, last_w, cur_l, cur_w):
        self.logs.append("Original Dataframe size: " + str(last_l) + " rows and " + str(last_w) + " columns.")
        self.logs.append("Final Dataframe size: " + str(cur_l) + " rows and " + str(cur_w) + " columns.")

    '''
        Function: drop_local_traffic
        Description: drops all local traffic from the data collected from T-pot using
        Elastic. Drops all entries with the destination 64297 (internal communication
        port), geoip location in Poulsbo (the site of the honeypots), and all error
        alerts from Suricata found through the "tags" column.

        Input:
            - df: pandas dataframe
        Output:
            - df: Pandas dataframe with all local traffic dropped.
        
        Last Modified: 07/11/2025
            - CB 07/11/2025: Now drops 172.200.200.5 source ip that represents
                honeypot responses to attackers. Also dropped 172.18.254.0 since
                it is the IP of the VPN used to access the data. Also added logging.

    '''
    def drop_local_traffic(self, df):
        conditions = pd.Series(True, index=df.index)
        if "dest_port" in df.columns:
            conditions &= df["dest_port"] != 64297
        if "src_ip" in df.columns:
            conditions &= df["src_ip"] != '172.19.254.0'
            conditions &= df["src_ip"] != '172.200.200.5'
        if "geoip.city_name" in df.columns:
            conditions &= df["geoip.city_name"] != "Poulsbo"
        if "tags" in df.columns:
            conditions &= df["tags"].isnull()
        
        self.logs.append("Local traffic dropped")
        return df[conditions]

    '''
        Function: remove_suricata_duplicates
        Description: fnds and removes all suricata alerts and appends them to the
        original alert row by "flow_id". Assumes that the data does not cross the 4am
        mark --- which is when suricata resets its flow_ids.

        Input:
            - df: pandas dataframe
        Output:
            - pandas dataframe with all suricata alerts appended to the original alert
              row.
        
        Last Modified: 07/11/2025
            - CB 07/11/2025: added logging

    '''
    def remove_suricata_duplicates(self, df):
        filter_col = 'anomaly.event'

        # If the column doesn't exist, return the DataFrame as-is
        if not {'anomaly.event', 'flow_id', 'anomaly.type', 'anomaly.layer', '@timestamp'}.issubset(df.columns):
            df.columns.append("Error in remove_suricata_duplicates: missing a column, suricata duplicates could not be aggregated")
            return df

        # Split into duplicates and clean rows
        duplicates = df[df[filter_col].notnull()]
        clean_df = df[df[filter_col].isnull()]

        # Select only useful columns
        duplicates = duplicates[[
            "flow_id",
            "anomaly.type",
            "anomaly.event",
            "anomaly.layer",
            "@timestamp"
            ]]


        # Aggregate by flow_id, combining unique values
        aggregated = duplicates.groupby(['flow_id', '@timestamp']).agg({
            "anomaly.type": lambda x: ', '.join(pd.unique(x.dropna().astype(str))),
            "anomaly.event": lambda x: ', '.join(pd.unique(x.dropna().astype(str))),
            "anomaly.layer": lambda x: ', '.join(pd.unique(x.dropna().astype(str))),
            }).reset_index()

        # Join the aggregated anomalies back to the clean data
        self.logs.append("Suricata duplicates aggregated")
        return clean_df.merge(aggregated, on=['flow_id','@timestamp'], how="left")

    '''
    Function: remove_cowrie_duplicates
    Description: finds and removes all cowrie events and appends them to the
    original alert row by matching the session code. This limits cowrie entries
    to one alert per session. Events are identified in the "eventid" column with
    values of 'connect', 'end', etc. Session IDs are found int he "session" column.

    Appends "message" and "ip_rep" columns to the original alert row.

    Input:
        - df: Pandas dataframe
    Output:
        - Pandas dataframe with all Cowrie sessions appended to the original alert
          row.
    
    Last Modified: 07/11/2025
        - CB 07/11/2025: added logging
    '''
    def remove_cowrie_duplicates(self, df):
        # Step 1: Filter Cowrie duplicates
        if 'type' not in df.columns:
            self.logs.append("Error in remove_cowrie_duplicates: Missing type column, Cowrie duplicates could not be aggregated")
            return df
        
        duplicates = df[df["type"] == "Cowrie"]
        clean_df = df[df["type"] != "Cowrie"]

        # Step 2: Keep only useful columns
        if 'eventid' not in df.columns:
            self.logs.append("Error in remove_cowrie_duplicates: Missing eventid column, Cowrie duplicates could not be aggregated")
            return df
        if 'session' not in df.columns:
            self.logs.append("Error in remove_cowrie_duplicates: Missing session column, Cowrie duplicates could not be aggregated")
            return df
        if 'message' not in df.columns:
            self.logs.append("Error in remove_cowrie_duplicates: Missing message column, Cowrie duplicates could not be aggregated")
            return df
        if 'ip_rep' not in df.columns:
            self.logs.append("Error in remove_cowrie_duplicates: Missing ip_rep column, Cowrie duplicates could not be aggregated")
            return df
        
        duplicates = duplicates[[
            "eventid",
            "session",
            "message",
            "ip_rep",
        ]]

        # Step 3: Aggregate entries by session
        aggregated = (
            duplicates
            .groupby("session")
            .agg({
                "eventid": lambda x: ' , '.join(pd.unique(x.dropna().astype(str))),
                "message": lambda x: ' , '.join(pd.unique(x.dropna().astype(str))),
                "ip_rep": lambda x: ' , '.join(pd.unique(x.dropna().astype(str))),
            })
            .reset_index()
        )

        # Step 4: Join the aggregated info back into the cleaned DataFrame
        cleaned_df = clean_df.merge(aggregated, on="session", how="left")
        self.logs.append("Cowrie duplicates aggregated")
        return cleaned_df

    '''
        Function: remove_P0f_duplicates
        Description: identifies all P0f entries by the "type" column and combines them
        to corresponding entries by "src_ip", "@timestamp", "dest_port", "src_port".
        Appends "params", "raw_sig", "os", and "link" columns to the original alert row.

        Input:
            - df: Pandas dataframe
        Output:
            - Pandas dataframe with all P0f entries combined to corresponding entries.
        
        Last Modified: 07/11/2025
            - CB 07/11/2025: added logging

    '''
    def remove_P0f_duplicates(self, df):
        required_cols = ["type", "src_ip", "dest_ip", "@timestamp", "dest_port", "src_port",
                         "params", "raw_sig", "os", "link"]
        
        missing = [col for col in required_cols if col not in df.columns]
        if missing:
            self.logs.append("Error in remove_P0f_duplicates: Missing columns for P0f aggregation")
            return df

        is_p0f = df["type"] == "P0f"
        p0f_df = df[is_p0f]
        other_df = df[~is_p0f]

        if p0f_df.empty:
            self.logs.append("Error in remove_P0f_duplicates: There are no P0f entries")
            return df

        key_cols = ["src_ip", "dest_ip", "@timestamp", "dest_port", "src_port"]
        agg_cols = ["params", "raw_sig", "os", "link"]

        aggregated = (
            p0f_df
            .groupby(key_cols, dropna=False)
            .agg({col: lambda x: ' | '.join(pd.unique(x.dropna().astype(str))) for col in agg_cols})
            .reset_index()
        )

        # Merge matches
        merged = other_df.merge(aggregated, on=key_cols, how="left")

        # Identify and keep unmatched aggregated rows
        matched_keys = other_df[key_cols].drop_duplicates()
        unmatched = pd.merge(aggregated, matched_keys, on=key_cols, how='left', indicator=True)
        unmatched = unmatched[unmatched['_merge'] == 'left_only'].drop(columns='_merge')

        # Ensure unmatched rows have all columns in merged
        for col in merged.columns:
            if col not in unmatched.columns:
                unmatched[col] = np.nan
        unmatched = unmatched[merged.columns]  # align columns

        # Combine matched + unmatched
        merged = pd.concat([merged, unmatched], ignore_index=True)
        self.logs.append("P0f duplicates removed")
        return merged
    '''
        Function: drop_sparse_columns
        Description: drops all columns with less than min_coverage (decimal) entries.

        Input:
            - df: Pandas dataframe
            - min_coverage: decimal value between 0 and 1 representing the minimum
          percentage of data coverage.
        Output:
            - Pandas dataframe with all columns with less than min_coverage entries
              dropped.
        
        Last Modified: 07/11/2025
            - CB 07/11/2025: added logging
    '''
    def drop_sparse_columns(self, df, min_coverage):
        always_keep = ['geoip.as_org', '@timestamp']
        
        row_count = len(df)
        
        # Determine which columns meet the coverage threshold
        columns_to_keep = [
            col for col in df.columns
            if df[col].notnull().sum() >= row_count * min_coverage or col in always_keep
        ]
        
        
        self.logs.append("Sparse columns dropped")
        return df[columns_to_keep]
    
    '''
        Method: drop_unused_columns
        Description: keeps only the columns necessary for operations.
        
        Input:
            - df: pandas dataframe containining T-pot data.
            - flag: boolean representing whether or not serialization has been done.
        Output:
            - filtered pandas dataframe with only necessary columns.
        
        Last Modified: 07/14/2025
            - CB 07/14/2025: added error handling, added flag to drop columns pre-serialization
    '''
    def drop_unused_columns(self, df, flag):
        if flag:
            for col in self.necessary_before_serial:
                if col not in df.columns:
                    self.logs.append(f"Error: drop_unused_columns w/flag, missing {col}, unused columns could not be dropped")
                    return df
            return df[self.necessary_before_serial]
        else:
            for col in self.necessary_columns:
                if col not in df.columns:
                    self.logs.append(f"Error: drop_unused_columns missing {col}, unused columns could not be dropped")
                    return df
            return df[self.necessary_columns]

    '''
        Function: is_private_ip
        Description: decides and returns if an ip address is private.

        Input:
            - ip_str: string representing an ip address
        Output:
            - boolean representing if the ip address is private.

        Last Modified: 07/11/2025
    '''
    def is_private_ip(self, ip_str):
        try:
            return ipaddress.ip_address(ip_str).is_private
        except ValueError:
            return False
    
    '''
        Method: id_honeypot
        Description: Identifies and labels honeypots by dest_port numbers.
        
        Input:
            - df: pandas dataframe of T-pot data.
            - honeypot_name: string name of the honeypot
            - port_list: list of ports associated with that honeypot.
        Output: NONE
        
        Last Modified: 07/11/2025
            - CB 07/10/2025: converted to a class method.
    '''
    def id_honeypot(self, df, honeypot_name, port_list):
        target_ports = port_list

        # Identify the rows to modify
        mask = ((df["dest_port"].isin(target_ports)))

        mask2 =  ((df["src_port"].isin(target_ports)) &
            ((df["src_ip"] == "172.200.200.5") | (df["src_ip"] == "127.0.0.1")) &
            ~((self.is_private_ip(df["dest_port"]))))
        # Modify the "type" where the mask is True
        df.loc[mask, "type"] = honeypot_name
        df.loc[mask2, "type"] = honeypot_name
        
        return df

    '''
        Function: label_hidden_honeypots
        Description: Finds all unlabeled honeypots by port number and labels them
        through the 'type' column.

        Input:
            - df: Pandas dataframe
        Output:
            - Pandas dataframe with all unlabeled honeypots labeled.
        
        Last Modified: 07/11/2025
            - CB 07/11/2025: added logging
    '''
    def label_hidden_honeypots(self, df):
        
        if 'type' not in df.columns:
            self.logs.append("Error in label_hidden_honeypots: Missing type column, hidden honeypots could not be identified")
            return df

        for honeypot in self.honeypot_info.keys():
            df = self.id_honeypot(df, honeypot, self.honeypot_info[honeypot])

        # assigns all others to honeytrap since it tracks all other ports
        df.loc[~df['type'].isin(self.honeypot_info.keys()), 'type'] = 'Honeytrap'

        return df


    '''
        Function: run_everything
        Description: this function functions as the driver for the program. It calls
        all other functions.
        
        Input: NONE
        Output:
            - df: pandas dataframe with clean data.
        
        Last Modified: 07/11/2025
            - CB 07/11/2025: added logging
            - CB 07/14/2025: passed df as an input and removed read to json file.
    '''
    def run_everything(self, df):

        # Load and normalize JSON data
        if df.empty:
            self.logs.append("Error in run_everything: Input data is empty.")
            return df
        
        df = pd.json_normalize(df.to_dict(orient="records"))

        original_shape = df.shape
        
        df = self.drop_unused_columns(df, False)
        
        
        # Sequential cleaning pipeline
        df = self.drop_local_traffic(df)
        df = self.remove_suricata_duplicates(df)
        df = self.remove_cowrie_duplicates(df)
        df = self.remove_P0f_duplicates(df)
        df = self.label_hidden_honeypots(df)
        df = self.drop_sparse_columns(df, 0.5)
        self.print_progress(original_shape[0], original_shape[1], df.shape[0], df.shape[1])

        return df

    """**Data Compilation**
    Description: This section compiles and savs only absolutely necessary data for overall analysis and visualization.
    """

    '''
        Function: compile_hourly_data
        Description: compiles all the necessary data for the hourly visualizations and
        saves them into .csv files.

        Input:
            - df: Pandas dataframe
        Output:
          - full_hourly_data.csv
          - company_hits.csv
        
        Last Modified: 07/11/2025
            - CB 07/11/2025: added logging, hid data paths as data members of the class.

    '''
    def compile_hourly_data(self, df):
        columns_to_keep = ['@timestamp', 'dest_ip', 'dest_port', 'src_ip', 'src_port', 'type', 'geoip.country_name', 'geoip.city_name']
        if not all(col in df.columns for col in columns_to_keep):
            return

        df[columns_to_keep].to_csv('data/hourly_data/full_hourly_data.csv', index=False)

        if 'geoip.as_org' in df.columns:
            hits_df = df.groupby('geoip.as_org').agg(
                Hits=('geoip.as_org', 'count'),
                Total_ips=('src_ip', 'nunique')
            ).reset_index().rename(columns={'geoip.as_org': 'Org'})
            hits_df.to_csv(self.hourly_company_hits_csv, index=False)

    '''
        Function: compile_hits_data
        Description: compiles all the necessary data for the hits visualizations and
        saves them into .csv files.

        Input:
            - df: Pandas dataframe
        Output:
            - destport_hits.csv
            - honeypot_hits.csv
            - ip_hits.csv
            - company_hits.csv
        
        Last Modified: 07/11/2025
            - CB 07/11/2025: added logging, hid data paths as class data members.
    '''
    def compile_hits_data(self, df):
        # Helper function to merge existing and new hits
        def merge_and_save(existing_path, groupby_col, label_col, df, out_col='hits'):
            if groupby_col not in df.columns:
                self.logs.append(f"Missing {groupby_col} column, skipping {label_col} hits.")
                return

            # Load existing data
            try:
                existing_df = pd.read_csv(existing_path)
            except (FileNotFoundError, pd.errors.EmptyDataError):
                existing_df = pd.DataFrame(columns=[label_col, out_col])

            existing_df.set_index(label_col, inplace=True)
            existing_df[out_col] = existing_df[out_col].astype(float)

            # Compute new hits
            new_hits = df.groupby(groupby_col).size().rename(out_col).to_frame()
            new_hits.index.name = label_col

            # Combine new + existing
            combined = new_hits.add(existing_df, fill_value=0).reset_index()

            # Save to CSV
            combined.to_csv(existing_path, index=False)

        # Port hits
        merge_and_save(self.destport_hits_csv, 'dest_port', 'port', df)

        # Honeypot hits
        merge_and_save(self.honeypot_hits_csv, 'type', 'honeypot', df)

        # IP hits
        merge_and_save(self.ip_hits_csv, 'src_ip', 'ip', df)

        # Company hits
        merge_and_save(self.total_company_hits_csv, 'geoip.as_org', 'Org', df)

    '''
        Function: save_time_vs_port_data
        Description: compiles all the necessary data for the time vs port visualizations and
        saves them into .csv files.

        Input:
            - df: Pandas dataframe
        Output:
            - time_vs_port.csv
        
        Last Modified: 07/11/2025
            - CB 07/11/2025: added logging, hid file paths as class data members,
                changed column timestamp to @timestamp for consistency.
    '''
    def save_time_vs_port_data(self, df):
        time_vs_port_df = pd.read_csv(self.time_vs_port_csv)
        
        if time_vs_port_df.empty:
            time_vs_port_df = pd.DataFrame(columns=['@timestamp', 'ports', 'ips'])
        if "@timestamp" not in df.columns:
            self.logs.append("Error in save_time_vs_port_data: Missing @timestamp column, time vs port data could not be compiled")
            return
        if "dest_port" not in df.columns:
            self.logs.append("Error in save_time_vs_port_data: Missing dest_port column, time vs port data could not be compiled")
            return
        if "src_ip" not in df.columns:
            self.logs.append("Error in save_time_vs_port_data: Missing src_ip column, time vs port data could not be compiled")
            return
        
        earliest = df["@timestamp"].min()
        port_list = df['dest_port'].unique().tolist()
        ip_list = df['src_ip'].unique().tolist()
        entry = {"@timestamp": earliest, "ports": port_list, "ips": ip_list}

        # ✅ Wrap entry in a list to create one-row DataFrame
        time_vs_port_df = pd.concat([time_vs_port_df, pd.DataFrame([entry])], ignore_index=True)
        time_vs_port_df.to_csv(self.time_vs_port_csv, index=False)

    '''
        Function: reset_csvs
        Description: empties all the .csv files but preserves the columns.

        Input: NONE
        Output: NONE
        
        Last Modfied: 07/11/2025
            - CB 07/11/2025: hid file paths as data members, added ips to time_vs_port
    '''
    def reset_csvs(self):
        pd.DataFrame(columns=['port', 'hits']).to_csv(self.destport_hits_csv, index=False)
        pd.DataFrame(columns=['honeypot', 'hits']).to_csv(self.honeypot_hits_csv, index=False)
        pd.DataFrame(columns=['ip', 'hits']).to_csv(self.ip_hits_csv, index=False)
        pd.DataFrame(columns=['Org', 'hits']).to_csv(self.total_company_hits_csv, index=False)
        pd.DataFrame(columns=['@timestamp', 'ports', 'ips']).to_csv(self.time_vs_port_csv, index=False)

    '''
        Method: save_data
        Description: compiles and saves all useful data.
        
        Input:
            - df: cleaned pandas dataframe
        Output: NONE
        
        Last Modified: 07/10/2025
            - CB 07/10/2025: converted to a method
    '''
    def save_data(self, df):
        self.compile_hourly_data(df)
        self.compile_hits_data(df)
        self.save_time_vs_port_data(df)
    
    '''
        Method: process_data
        Description: processes and saves all the data.
        
        Input:
            - df: a pandas dataframe containing an hour of T-pot data.
        Output:
            - logs: list of all string logs accumulated during processing.
        
        Last Modified: 07/11/2025
            - CB 07/10/2025: added timer
            - CB 07/11/2025: added logs
            - CB 07/14/2025: Added df as an input to remove reading a json.
    '''
    def process_data(self, df):
        print()
        start_time = time.time()
        df = self.run_everything(df)
        if df.shape[0] != 0:
            self.save_data(df)
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Processing time: {elapsed_time:.2f} seconds\n")
        return self.logs
    
