from packages import *

'''
    Class: DataFiler
    Description: This class summarizes a dataframe into 'summary' csvs and produces
    two historical trend plots and outputs them as pngs.

    Last Modified: 07/31/2025
        - CB 08/01/2025: added function clean_csvs to ensure missing hours of data
                         are filled in with 0 values.
'''
class DataFiler:
    
    def __init__(self):
        self.total_company_hits_csv = "data/historical_data/company_hits.csv"
        self.destport_hits_csv = "data/historical_data/destport_hits.csv"
        self.honeypot_hits_csv = "data/historical_data/honeypot_hits.csv"
        self.ip_hits_csv = "data/historical_data/ip_hits.csv"
        self.time_vs_port_csv = "data/historical_data/time_vs_port.csv"
        self.hourly_company_hits_csv = "data/hourly_data/company_hits.csv"
        self.full_hourly_data_csv = "data/hourly_data/full_hourly_data.csv"
        self.time_vs_ip_csv = "data/historical_data/time_vs_ip.csv"
        self.time_vs_honeypot_hits = "data/historical_data/time_vs_honeypot_hits.csv"

        self.logs = {}

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
        - CB 07/11/2025: added logging, hid data paths as data members of the data_janitor class.
        - CB 07/31/2025: Moved to DataFiler class

    '''
    def compile_hourly_data(self, df):
        columns_to_keep = ['@timestamp', 'dest_ip', 'dest_port', 'src_ip', 'src_port', 'type', 'geoip.country_name', 'geoip.city_name']
        for col in columns_to_keep:
            if col not in df.columns:
                self.logs['compile_hourly_data'] = f'Error, missing {col}, hourly data could not compile'
                return

        df[columns_to_keep].to_csv('data/hourly_data/full_hourly_data.csv', index=False)

        if 'geoip.as_org' in df.columns:
            hits_df = df.groupby('geoip.as_org').agg(
                Hits=('geoip.as_org', 'count'),
                Total_ips=('src_ip', 'nunique')
            ).reset_index().rename(columns={'geoip.as_org': 'Org'})
            hits_df.to_csv(self.hourly_company_hits_csv, index=False)
        
        self.logs['compile_hourly_data'] = "Success"
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
        
        Last Modified: 07/31/2025
            - CB 07/11/2025: added logging, hid data paths as class data members.
            - CB 07/31/2025: moved to the DataFiler class
    '''
    def compile_hits_data(self, df):
        # Helper function to merge existing and new hits
        def merge_and_save(existing_path, groupby_col, label_col, df, out_col='hits'):
            if groupby_col not in df.columns:
                self.logs['compile_hits_data'] = f"Missing {groupby_col} column, skipping {label_col} hits."
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
        Method: compile_honeypot_hits
        Description: creates a .csv file contining each honeypot and the number of hits on that honeypot
        during an hour.

        Input:
            - df: a dataframe containing honeypot data.
        Output: None

        Last Modified: 07/31/2025
            - CB 07/31/2025: moved to DataFiler class
    '''
    def compile_honeypot_hits(self, df):
        honeypot_counts = {}
        honeypot_counts['@timestamp'] = df["@timestamp"].min()

        for honeypot in self.honeypot_info.keys():
            honeypot_counts[honeypot] =(df["type"] == honeypot).sum()

        honeypot_counts['Honeytrap'] = (df["type"] == 'Honeytrap').sum()
        
        # Append to CSV without writing the header again
        pd.DataFrame([honeypot_counts]).to_csv(self.time_vs_honeypot_hits, mode='a', header=False, index=False)
        self.logs['compile_honeypot_hits'] = 'Success'



    '''
        Function: save_time_vs_port_data
        Description: compiles all the necessary data for the time vs port visualizations and
        saves them into .csv files.

        Input:
            - df: Pandas dataframe
        Output:
            - time_vs_port.csv
        
        Last Modified: 07/31/2025
            - CB 07/11/2025: added logging, hid file paths as class data members,
                changed column timestamp to @timestamp for consistency.
            - CB 07/31/2025: moved to DataFiler class
    '''
    def save_time_vs_port_data(self, df):

        needed = ['@timestamp', 'dest_port', 'src_ip']
        for col in needed:
            if col not in df.columns:
                self.logs['save_time_vs_port_data'] = f"Missing {col}, time_vs_port could not be compiled."
                return
        
        earliest = df["@timestamp"].min()
        port_list = df['dest_port'].unique().tolist()
        ip_list = df["src_ip"].dropna().unique().tolist()

        ip_list_a = ip_list[:len(ip_list) // 2]
        ip_list_b = ip_list[len(ip_list) // 2:]
        entry_a = {"@timestamp": earliest, "ports": port_list}
        entry_b = {"@timestamp" : earliest, "ips_a": ip_list_a, "ips_b": ip_list_b}

        pd.DataFrame([entry_a]).to_csv(self.time_vs_port_csv, mode='a', header=False, index=False)
        pd.DataFrame([entry_b]).to_csv(self.time_vs_ip_csv, mode='a', header=False, index=False)
        self.logs['save_time_vs_port_data'] = "success"

    '''
        Function: reset_csvs
        Description: empties all the .csv files but preserves the columns.

        Input: NONE
        Output: NONE
        
        Last Modfied: 07/11/2025
            - CB 07/11/2025: hid file paths as data members, added ips to time_vs_port
            - CB 07/20/2025: added honeypot summaries
            - CB 07/31/2025: moved to DataFiler class
    '''
    def reset_csvs(self):
        pd.DataFrame(columns=['port', 'hits']).to_csv(self.destport_hits_csv, index=False)
        pd.DataFrame(columns=['honeypot', 'hits']).to_csv(self.honeypot_hits_csv, index=False)
        pd.DataFrame(columns=['ip', 'hits']).to_csv(self.ip_hits_csv, index=False)
        pd.DataFrame(columns=['Org', 'hits']).to_csv(self.total_company_hits_csv, index=False)
        pd.DataFrame(columns=['@timestamp', 'ports']).to_csv(self.time_vs_port_csv, index=False)
        pd.DataFrame(columns=['@timestamp', 'ip_list_a', 'ip_list_b']).to_csv(self.time_vs_ip_csv, index=False)
        pd.DataFrame(columns=['@timestamp', 'Ciscoasa', 'Dicompot', 'Honeyaml', 'Medpot', 'SentryPeer', 'Abdhoney', 
                              'Conpot', 'Cowrie', 'Dionaea', 'Elasticpot', 'H0neytr4p', 'Heralding', 
                              'Ipphoney', 'Mailoney', 'Miniprint', 'Redishoneypot', 'Wordpot', 'Honeytrap']).to_csv(self.time_vs_honeypot_hits, index=False)
        for honeypot in self.honeypot_info.keys():
            pd.DataFrame(columns=["@timestamp", "ip", "port", "country", "city", "org"]).to_csv(f"data/historical_data/honeypot_summaries/{honeypot}_summary.csv", index=False)
        
        self.logs['reset_csvs'] = "Success."

    '''
        Method: honeypot_summaries
        Description: compiles summary data for each honeypot and saves it to individual csvs

        Input:
            - df: dataframe of honeypot data
        Output: None

        Last Modified: 07/31/2025
            - CB 07/31/2025: moved to DataFiler class
    '''
    def honeypot_summaries(self, df):
        summary_info = ['@timestamp', 'ip', 'port', 'country', 'city', 'org']
        needed_cols = ['@timestamp', 'src_ip', 'dest_port', 'geoip.country_name', 'geoip.city_name', 'geoip.as_org']

        # Check required columns
        for col in needed_cols:
            if col not in df.columns:
                self.logs['honeypot_summaries'] = (
                    f"Missing {col}, summary could not be retrieved for {df['@timestamp'].min()}"
                )
                return

        # Add Honeytrap as a catch-all
        temp_list = self.honeypot_info.copy()
        temp_list["Honeytrap"] = []

        for honeypot in temp_list.keys():
            honeypot_df = df[df['type'] == honeypot]
            temp_entry = {'@timestamp': honeypot_df['@timestamp'].min()}

            # Most seen source IP address
            temp_entry['ip'] = honeypot_df['src_ip'].dropna().value_counts().index[0] if not honeypot_df['src_ip'].dropna().empty else 'None'
            # Most seen destination port
            temp_entry['port'] = honeypot_df['dest_port'].dropna().value_counts().index[0] if not honeypot_df['dest_port'].dropna().empty else 'None'
            # Most seen country
            temp_entry['country'] = honeypot_df['geoip.country_name'].dropna().value_counts().index[0] if not honeypot_df['geoip.country_name'].dropna().empty else 'None'
            # Most seen city
            temp_entry['city'] = honeypot_df['geoip.city_name'].dropna().value_counts().index[0] if not honeypot_df['geoip.city_name'].dropna().empty else 'None'
            # Most seen org
            temp_entry['org'] = honeypot_df['geoip.as_org'].dropna().value_counts().index[0] if not honeypot_df['geoip.as_org'].dropna().empty else 'None'

            none_count = sum(val == 'None' for val in temp_entry.values())

            # CSV path
            file_path = f"data/historical_data/honeypot_summaries/{honeypot}_summary.csv"

            # ✅ Check if CSV is empty by trying to read just 1 row
            csv_is_empty = False
            try:
                test_df = pd.read_csv(file_path, nrows=1)
                if test_df.empty:
                    csv_is_empty = True
            except FileNotFoundError:
                csv_is_empty = True
            except pd.errors.EmptyDataError:
                csv_is_empty = True

            # ✅ If empty, write headers first
            if csv_is_empty:
                pd.DataFrame(columns=summary_info).to_csv(file_path, index=False)

            # ✅ Append only if there’s meaningful data
            if none_count <= 4:
                pd.DataFrame([temp_entry]).to_csv(
                    file_path,
                    mode='a',
                    header=False,  # headers already written if needed
                    index=False
                )
                self.logs[f'honeypot_summary_{honeypot}'] = "Success."
            
       
            
    '''
        Method: save_data
        Description: compiles and saves all useful data.
        
        Input:
            - df: cleaned pandas dataframe
        Output: NONE
        
        Last Modified: 08/01/2025
            - CB 07/10/2025: converted to a method
            - CB 07/20/2025: added honeypot summaries
            - CB 07/31/2025: moved to DataFiler class, added ip and port analysis
            - CB 08/01/2025: added call to clean_csvs
    '''
    def save_data(self, df):
        self.compile_hourly_data(df)
        self.compile_hits_data(df)
        self.save_time_vs_port_data(df)
        self.compile_honeypot_hits(df)
        self.honeypot_summaries(df)
        self.analyze_ip_over_time()
        self.analyze_ports_over_time()
        self.clean_csvs()
        self.logs['save_data'] = 'Success.'
        self.write_logs()
    

    '''
        Method: analyze_ports_over_time
        Description: reads the csv file and creates a plot of ports over time.

        Input: NONE
        Output: NONE

        Last Modified: 07/31/2025
            - CB 07/31/2025: moved to DataFiler class
    '''
    def analyze_ports_over_time(self):
        csv_file = self.time_vs_port_csv
        df = pd.read_csv(csv_file)
        df = df.sort_values('@timestamp')
        
        # Step 1: Clean brackets, split into lists
        df['ports'] = df['ports'].astype(str).str.replace(r'[\[\]\'\"]', '', regex=True)
        df['ports'] = df['ports'].str.split(',')

        # Step 2: Explode the port lists into rows
        df = df.explode('ports').reset_index(drop=True)

        # Step 3: Clean individual port entries
        df['ports'] = df['ports'].str.strip()  # strip each item after explode
        df = df[df['ports'].notna() & (df['ports'] != '')]

        # Step 4: Convert types
        df['@timestamp'] = pd.to_datetime(df['@timestamp'], errors='coerce')
        df['ports'] = pd.to_numeric(df['ports'], errors='coerce')

        # Step 5: Drop rows with any remaining NaNs
        df = df.dropna(subset=['@timestamp', 'ports'])

        # Step 6: Final conversion of ports to int
        df['ports'] = df['ports'].astype(int)

        # Plotting
        plt.figure(figsize=(40, 30))
        scatter = plt.scatter(
            df['@timestamp'],
            df['ports'],
            c=df['ports'],
            cmap='viridis',
            alpha=0.6,
            s=1
        )

        plt.title("Destination Port Over Time")
        plt.xlabel("Timestamp")
        plt.ylabel("Destination Port")

        cbar = plt.colorbar(scatter)
        cbar.set_label("Destination Port")

        unique_timestamps = sorted(df['@timestamp'].unique())

            # Only show first and last tick marks on X-axis
        first_tick = df['@timestamp'].min()
        last_tick = df['@timestamp'].max()
        plt.xticks([first_tick, last_tick], [first_tick.strftime("%Y-%m-%d %H:%M:%S"),
                                            last_tick.strftime("%Y-%m-%d %H:%M:%S")],
                rotation=45)

        # No legend (scatter has no legend by default, but ensure it's off)
        plt.legend([], [], frameon=False)
        
        plt.tight_layout()
        plt.savefig("static/data/ports_vs_time.png")
        plt.close()
        self.logs['analyze_ports_over_time'] = "Success."

    '''
        Method: analyze_ip_over_time
        Description: Reads a .csv of ip data and plots ips over time.

        Input: None
        Output: None
        
        Last Modified: 07/31/2025
    '''
    def analyze_ip_over_time(self):
        csv_file = self.time_vs_ip_csv
        df = pd.read_csv(csv_file)
        df = df.sort_values('@timestamp')

        # Step 1: Clean brackets, convert to string, and split
        for col in ["ip_list_a", "ip_list_b"]:
            df[col] = df[col].astype(str).str.replace(r'[\[\]\'\"]', '', regex=True)
            df[col] = df[col].str.split(',')

        # Step 2: Melt both columns into one
        df_long_a = df[["@timestamp", "ip_list_a"]].rename(columns={"ip_list_a": "ip_list"})
        df_long_b = df[["@timestamp", "ip_list_b"]].rename(columns={"ip_list_b": "ip_list"})
        df_long = pd.concat([df_long_a, df_long_b], ignore_index=True)

        # Step 3: Explode the IP lists into rows
        df_long = df_long.explode("ip_list").reset_index(drop=True)
        df_long["ip"] = df_long["ip_list"].str.strip()

        # Step 4: Clean timestamp + drop invalids
        df_long["@timestamp"] = pd.to_datetime(df_long["@timestamp"], errors="coerce")
        df_long = df_long.dropna(subset=["@timestamp", "ip"])
        df_long = df_long[df_long["ip"] != "nan"]

        # Step 5: Map unique IPs to integer Y values for plotting
        unique_ips = sorted(df_long["ip"].unique(), key=lambda ip: ipaddress.IPv4Address(ip))
        ip_to_y = {ip: i for i, ip in enumerate(unique_ips)}
        df_long["ip_y"] = df_long["ip"].map(ip_to_y)

        # Plotting
        plt.figure(figsize=(40, 40))
        scatter = plt.scatter(
            df_long["@timestamp"],
            df_long["ip_y"],
            c=df_long["ip_y"],
            cmap='plasma',
            alpha=0.6,
            s=1
        )

        plt.title("IP Addresses Over Time")
        plt.xlabel("Timestamp")
        plt.ylabel("IP Address")

        # Optional: show only first and last tick on X-axis
        first_tick = df_long['@timestamp'].min()
        last_tick = df_long['@timestamp'].max()
        plt.xticks([first_tick, last_tick],
                [first_tick.strftime("%Y-%m-%d %H:%M:%S"),
                    last_tick.strftime("%Y-%m-%d %H:%M:%S")],
                rotation=45)

        # Y-axis: use IP address strings
        step = 20  # show every 10th IP address
        plt.yticks(
            ticks=range(0, len(unique_ips), step),
            labels=[unique_ips[i] for i in range(0, len(unique_ips), step)],
            fontsize=6
        )

        # Color bar
        cbar = plt.colorbar(scatter)
        cbar.set_label("IP Index")

        plt.legend([], [], frameon=False)  # no legend
        plt.tight_layout()
        plt.savefig("static/data/ip_vs_time.png")
        plt.close()

        self.logs['analyze_ip_over_time'] = "Success."

    '''
        Function: write_logs
        Description: Writes to data_cleaning_logs.txt file

        Input: None
        Output: None

        Last Modified: 07/31/2025
            - CB 07/31/2025: copied from honeypot data cleaning
    '''
    def write_logs(self):
        with open("logs/data_filer_logs.txt", "w") as f:
            f.write("\nNew_Log:")
            f.writelines(f"{k}:{v}\n" for k, v in self.logs.items())

    '''
        Method: clean_csvs
        Description: Ensures the time-based csvs fill in missing hours from pull data with 0s

        Input: None
        Output: None

        Last Modified: 08/01/2025
    '''
    def clean_csvs(self):
        honey_hits_df = pd.read_csv(self.time_vs_honeypot_hits)
        honey_hits_df = honey_hits_df.sort_values('@timestamp').reset_index(drop=True)

        honey_hits_df['@timestamp'] = pd.to_datetime(honey_hits_df['@timestamp'], utc=True)

        new_rows = []

        value_columns = [col for col in honey_hits_df.columns if col != '@timestamp']

        for i in range(len(honey_hits_df) - 1):
            curr_row = honey_hits_df.loc[i]
            next_row = honey_hits_df.loc[i + 1]

            curr_time = curr_row['@timestamp']
            next_time = next_row['@timestamp']

            # Check for >1 hour gap
            diff = next_time - curr_time
            if diff > datetime.timedelta(hours=1):

                num_missing = int(diff.total_seconds() // 3600) - 1

                for j in range(1, num_missing + 1):
                    new_time = curr_time + datetime.timedelta(hours=j)

                    new_row = {'@timestamp' : new_time}
                    new_row.update({col: 0 for col in value_columns})
                    new_rows.append(new_row)
                    
        if new_rows:
            honey_hits_df = pd.concat([honey_hits_df, pd.DataFrame(new_rows)], ignore_index=True)
            honey_hits_df['@timestamp'] = pd.to_datetime(honey_hits_df['@timestamp'], utc=True)
            honey_hits_df.to_csv(self.time_vs_honeypot_hits, index=False)
        self.logs['clean_csvs'] = f'{len(new_rows)} new rows added to time_vs_honeypot_hits.csv'

    
