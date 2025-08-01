# -*- coding: utf-8 -*-
'''
Honeypot_data_cleaning.ipynb
## **Honeypot Data Cleaning Pipeline**
    *Programmer: Caitlyn Boyd*

    *Last Modified: 07/31/2025*
        - CB 07/11/2025: bug fixes, added logs and timing, converted to a class.
        - CB 07/14/2025: bug fixes, optimization, drop unnecessary columns before
            json serialization.
        - CB 07/15/2025: added multi-threading to speed up data processing.
        - CB 07/20/2025: fixed path for saving honeypot csvs
        - CB 07/21/2025: replaced ~ with not where it depreciated, added more error handling.
        - CB 07/31/2025: Moved all data analysis / data saving to a new class data filer, moved the logs text file
                         to the "logs" directory.

    **Description:** This program is intended to clean 24 hours of data from T-pot
    that is pulled from elastic pot and converted into a .csv file. Future
    modifications will allow for batch processing of jsonl data taken from the same
    location.
'''

from packages import *
import data_filer as filer


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
    Last Modified: 07/31/2025
        - CB 07/11/2025: added logs
        - CB 07/14/2025: added necessary_before_serial to drop more columns and speed up serialization.
        - CB 07/21/2025: added paths to time_vs_honeypot_hits and time_vs_ip csvs
        - CB 07/31/2025: removed all .csv path data members and moved them to data filer class and added data filer.
'''
class DataJanitor:
    # all file paths
    def __init__(self):
        warnings.simplefilter("ignore", PerformanceWarning)
        warnings.simplefilter(action='ignore', category=FutureWarning)
        self.logs = {}
        
        self.filer = filer.DataFiler()
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
        non_list_columns = df.columns[not df.applymap(type).eq(list).any()]
        nunique = df[non_list_columns].nunique(dropna=False)
        constant_columns = [col for col in nunique.index if nunique[col] <= 1 and col != '@timestamp']
        df.drop(columns=constant_columns, inplace=True)
        self.logs['drop_constant_columns'] = 'Success'
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
        self.logs['print_progress_a'] = "Original Dataframe size: " + str(last_l) + " rows and " + str(last_w) + " columns."
        self.logs['print_progress_b'] = "Final Dataframe size: " + str(cur_l) + " rows and " + str(cur_w) + " columns."
        return

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
            - CB 07/21/2025: Drops traffic with destination port 64297 since it is the
                port used only for local updates and data extraction.
            - CB 07/21/2025: Drops all rows with filled out "tag" columns because those
                are just extra Suricata alerts for geoip failures and failure to parse.

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
        
        self.logs['drop_local_traffic'] = "Success"
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
            self.logs['remove_suricata_duplicates'] = "Error, missing a column, could not aggregate duplicates"
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
        self.logs['remove_suricata_duplicates'] = "Success"
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
        needed = ['eventid', 'session', 'message', 'ip_rep', 'type']
        for col in needed:
            if col not in df.columns:
                self.logs['remove_cowrie_duplicates'] = f"Missing {col}, duplicates could not be aggregated"
                return df
        
        duplicates = df[df["type"] == "Cowrie"]
        clean_df = df[df["type"] != "Cowrie"]

        # Step 2: Keep only useful columns
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
        self.logs['remove_cowrie_duplicates'] = "Success"
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
        
        for col in required_cols:
            if col not in df.columns:
                self.logs['remove_P0f_duplicates'] = f"Missing {col}, duplicates could not be aggregated."
                return df

        is_p0f = df["type"] == "P0f"
        p0f_df = df[is_p0f]
        other_df = df[~is_p0f]

        if p0f_df.empty:
            self.logs['remove_P0f_duplicates'] = "There were no P0f duplicates."
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
        self.logs['remove_P0f_duplicates'] = "Success."
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
        always_keep = ['geoip.as_org', 'src_ip', 'dest_port', '@timestamp', 'geoip.city_name', 'geoip.country_name']
        
        row_count = len(df)
        
        # Determine which columns meet the coverage threshold
        columns_to_keep = [
            col for col in df.columns
            if df[col].notnull().sum() >= row_count * min_coverage or col in always_keep
        ]
        
        self.logs['drop_sparse_columns'] = "Success."
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
                    self.logs['drop_unused_columns_flagged'] = f"Error, missing {col}, unused columns could not be dropped"
                    return df
                
            return df[self.necessary_before_serial]
        else:
            for col in self.necessary_columns:
                if col not in df.columns:
                    self.logs['drop_unused_columns_no_flag'] = f"Error, missing {col}, unused columns could not be dropped"
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
            (not (self.is_private_ip(df["dest_port"]))))
        # Modify the "type" where the mask is True
        df.loc[mask, "type"] = honeypot_name
        df.loc[mask2, "type"] = honeypot_name

        # update log
        self.logs[f'id_honeypot_{honeypot_name}'] = "Successful"
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
            self.logs['label_hidden_honeypots'] = "Error, Missing type column, hidden honeypots could not be identified"
            return df

        for honeypot in self.honeypot_info.keys():
            df = self.id_honeypot(df, honeypot, self.honeypot_info[honeypot])

        # assigns all others to honeytrap since it tracks all other ports
        df.loc[~df['type'].isin(self.honeypot_info.keys()), 'type'] = 'Honeytrap'

        # Update logs
        self.logs['id_honeypot_Honeytrap'] = "Success"
        self.logs['label_hidden_honeypots'] = "Success"

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
            self.logs['run_everything'] = "Error, Input data is empty."
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

    '''
        Function: write_logs
        Description: Writes to data_cleaning_logs.txt file
    '''
    def write_logs(self):
        with open("logs/data_cleaning_logs.txt", "w") as f:
            f.write("\nNew_Log:")
            f.writelines(f"{k}:{v}\n" for k, v in self.logs.items())
    
    '''
        Method: process_data
        Description: processes and saves all the data.
        
        Input:
            - df: a pandas dataframe containing an hour of T-pot data.
        Output:
            - logs: list of all string logs accumulated during processing.
        
        Last Modified: 07/31/2025
            - CB 07/10/2025: added timer
            - CB 07/11/2025: added logs
            - CB 07/14/2025: Added df as an input to remove reading a json.
            - CB 07/31/2025: Moved data analysis / saving to data filer class.
    '''
    def process_data(self, df):
        start_time = time.time()
        df = self.run_everything(df)
        
        end_time = time.time()
        elapsed_time = end_time - start_time
        self.logs['process_data'] = f"Processing time = {elapsed_time: .2f} seconds"
        self.write_logs()
        self.filer.save_data(df)
        
        print(f"Processing time: {elapsed_time:.2f} seconds\n")
        return df
    
