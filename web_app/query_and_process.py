'''
    File: query_and_process
    Description: Queries Kibana / Elastic search for honeypot data and
    analyzes it in incrementes of 60 minutes.
    
    Programmers: Adam Caudle, Caitlyn Boyd
    Last Modified: 07/08/2025
        - CB 07/08/2025: integrated data pipeline, added support for Windows.
        - CB 07/10/2025: converted into a class, hid data sensitive info as data members.
        - CB 07/11/2025: Removed writes to json for optimization, removed nuisance logs,
            deleted user interface.
        - CB 07/14/2025: optimized by removing writes to json and just collect data to a
            dataframe directly. Only update progress bar every 20 seconds.
            
'''
from packages import *

'''
    Start of Modified by CB 07/08/2025
    Description: Windows support and data pipeline.
'''
import platform
if platform.system() == "Windows":
    import msvcrt

import honeypot_data_cleaning_fixed as hdc
'''
    End of Modified by CB 07/08/2025
'''

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
    Class: DataPlumber
    Description: pipes the data through the entire data processing pipeline.
    
    Last Modified: 07/11/2025
        - CB 07/10/2025: hid sensitive data in the class data members.
        - CB 07/11/2025: added logging, hard coded amount of time to pull,
            and deleted the user interface function.
'''
class DataPlumber:
    def __init__(self):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        self.logs = []
        self.user = None
        self.password = None
        self.auth = None
        self.base_url = None
        self.kibana_version = None
        
        # Configure search and endpoint (had to use kibana/internal/search/es since it's not outwardly hosted for security)
        # I found this by looking through proxy trafic for internal search logic (individual search uses this, aggregate data search uses bsearch)
        self.kibana_url = "https://honeypotlab.cyberrangepoulsbo.com/kibana"
        self.elastic_url = "https://honeypotlab.cyberrangepoulsbo.com/kibana/internal/search/es"        
        
        self.init_credentials()
        self.janitor = hdc.DataJanitor()
    
    '''
        Method: init_credentials
        Description: initializes credentials for the data access by pilling from
        the .env file and gathers the kibana version.
        
        Input: NONE
        Output: NONE
        
        Last Modified: 07/10/2025
    '''
    def init_credentials(self):
        # Pull login from .env file
        load_dotenv()
        self.user = os.getenv("HONEYPOT_USER")
        self.password = os.getenv("HONEYPOT_PASS")
        self.auth = HTTPBasicAuth(self.user, self.password)

        # Dynamically get version
        self.kibana_version = self.get_kibana_version(self.kibana_url, self.auth)     

    '''
        Function: get_kibana_version
        Description: Returns the current Kibana version
        
        Input:
            - base_url: the url to the api status?
            - auth:
        Output:
            - version of kibana
            
        Last Modified: 07/10/2025
            - CB 07/10/2025: converted to a class method
    '''
    def get_kibana_version(self, base_url, auth):
        try:
            response = requests.get(
                f"{base_url}/api/status",
                auth=auth,
                verify=False
            )
            response.raise_for_status()
            version = response.json().get("version", {}).get("number")
            if version:
                return version
            else:
                raise ValueError("Version not found in response.")
        except Exception as e:
            print(f"Error fetching Kibana version: {e}")
            sys.exit(1)



    '''
        Function: collect_honeypot_data
        Description: This function takes the number of hours to fetch and
        a debug parameter (y/n) and requests those hours of data from the
        honeypot. It saves the data to honeypot_data.jsonl and returns the total hits.
        Becuase it is meant to be used once per data collection cycle, it clears the
        honeypot_data.jsonl file before writing to it. It also prints a progress bar
        and allows the user to exit the script at any time by pressing Enter.
        
        Input: NONE
        Output:
            - number of hits.
            
        Programmer: Adam Caudle, Caitlyn Boyd
        Last Modified: 07/11/2025
            - CB 07/08/2025: Integrated data pipeline, added support for Windows
            - CB 07/10/2025: converted to a class method, hid all sensitive data
                and functions in the data members of the class.
            - CB 07/11/2025: integrated the new DataJanitor class, added logging,
                and hard coded the number of hours to pull as 1 hour.
            - CB 07/14/2025: removed writes to a json file and instead pass everything
                directly through a dataframe to improve efficiency.

    '''
    def collect_honeypot_data(self):
       # self.janitor.reset_csvs()
        new_log = ""
        total_hits = 0
        
        # hard code to desired number of hours
        time_to_fetch = 1
        hours_to_fetch = time_to_fetch * 60 
        curr_time = datetime.datetime.now(datetime.timezone.utc)

        # Required headers
        headers = {
            "Content-Type": "application/json",
            "kbn-version": "8.18.3",
            "kbn-xsrf": "true"
        }
        
        df = pd.DataFrame()

        # Clear existing data file
        open("honeypot_data.jsonl", "w").close()
        print("Collecting Data", end=" ")
        
        data_processing_count = 0
        data_list = []
        # Main collection loop
        for i in range(hours_to_fetch):
            # Compute time window
            slice_end = curr_time - datetime.timedelta(minutes=i)
            slice_start = curr_time - datetime.timedelta(minutes=i + 1)

            # Format timestamps in ISO 8601
            gte = slice_start.strftime("%Y-%m-%dT%H:%M:%SZ")
            lte = slice_end.strftime("%Y-%m-%dT%H:%M:%SZ")
            
            new_log = f"Requesting from {gte} to {lte}"
            #self.logs.append(new_log)
            
            
            # check for early exit
            '''
                Start of Modified by CB 07/08/2025:
                Adjusted to work on windows devices since windows hates life.
            '''
            if platform.system() == "Windows":
                if msvcrt.kbhit() and msvcrt.getch() == b'\r':
                    print("\nExiting early via Enter key.")
                    break
            else:
                if select.select([sys.stdin], [], [], 0)[0]:
                    print("\nExiting early via Enter key.")
                    sys.stdin.readline()
                    break
            '''
                End of modified CB 07/08/2025
            '''

            # Build dynamic query
            query_body = {
                "params": {
                    "index": "logstash-*",
                    "body": {
                        "size": 10000,
                        "query": {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte
                                }
                            }
                        },
                        "_source": True
                    }
                }
            }

            response = requests.post(self.elastic_url, headers=headers, auth=self.auth, json=query_body, verify=False)
            
            new_log = "Status Code: " + str(response.status_code)
            #self.logs.append(new_log)
            
            if response.status_code != 200:
                new_log = "Error fetching data: " + str(response.status_code) + " " + response.text
                #self.logs.append(new_log)
            
            '''
                CB 07/14/2025: Changed to support writing directly to a dataframe to remove json writes.
            '''
            try:
                data = response.json()
                hits = data.get("rawResponse", {}).get("hits", {}).get("hits", [])
                total_hits += len(hits)

                # Collect documents
                documents = []
                for hit in hits:
                    doc = hit.get("fields", {}) or hit.get("_source", {})
                    documents.append(doc)

                # Convert list of dicts to DataFrame and append
                if documents:
                    new_df = pd.DataFrame(documents)
                    df = pd.concat([df, new_df], ignore_index=True)

                #self.logs.append("Appended to internal DataFrame")
                
                
            except Exception as e:
                print("Failed to parse JSON:", e)
                print(response.text)
            
                
            '''
                Start of modified by CB 07/08/2025:
                Description: integrates the data pipeline to process
                batches of data at a time. Incremented at 60 minutes.
                Writes the results to .csv files.
            '''
            if (i + 1) % 60 == 0:
                # run data processing
                df = self.janitor.drop_unused_columns(df, True)
                janitor_logs = self.janitor.process_data(df)
                
                df = pd.DataFrame()
    
            '''
                CB 07/14/2025: moved progress bar and increased update
                interval for efficiency.
            '''
            # print progress bar
            if i % 20 == 0 or (i + 1) % 20 == 0:
                bar_width = 40
                progress = int((i + 1) / hours_to_fetch * bar_width)
                percent = int((i + 1) / hours_to_fetch * 100)
                bar = "[" + "#" * progress + "-" * (bar_width - progress) + f"] {percent}%"
                print("\r" + bar, end="", flush=True)
        
        '''
        with open("logs.txt", "w") as outfile:
            for entry in janitor_logs:
                outfile.write(entry + "\n")
        '''
        '''
            End of Modified CB 07/08/2025
        '''
        return total_hits

'''
    Runs the main program
    new avg runtime = 60.49
    
'''
@timeit
def main():
    plumber = DataPlumber()
    #jan = hdc.DataJanitor()
    #jan.reset_csvs()
    plumber.collect_honeypot_data()
    print()
    return 0

if __name__ == "__main__":
    main()
