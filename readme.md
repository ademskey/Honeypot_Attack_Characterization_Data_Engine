# Authors: Adam Caudle, Emily West, Caitlyn Boyd, Jack Crawford
A locally-hosted browser tool for querying, processing, cleaning, and displaying T-Pot Honeypot data. It uses Python's Flask library for the web server and Javascript/HTML for the front end.  

Our development is based on Western Washington University's Cyber Range T-Pot deployment.

[T-Pot](https://github.com/telekom-security/tpotce) : An open-source platform for running 20+ honeypots from one central server, developed by Deutsche Telekom.

# Stack: (At the time of creation)

**ELK Stack**  
T-Pot Version: 24.04.1  
Kibana Version: 8.18.3  
Elastic Version: 1.7.0  
Logstash: 

**Browser App**    
Python: 3.10.12 and 3.13.1  
Flask: 3.1.0/Werkzeung 3.1.3  
Javascript: 12.22.9  

# Setting up:
Create a ".env" file for http authorization (needed to pull information from honeypot)


    Then, make sure the proxies are configured in the script
    ex code:
    proxies = {
    "http": "socks5h://0.tcp.us-cal-1.ngrok.io:19083",
    "https": "socks5h://0.tcp.us-cal-1.ngrok.io:19083"
    }

    You should then be able to request data via the script.

# Running the browser data visualization tool:
Install python3, then connect to Cyberrange Poulsbo's VPN or connect to your T-Pot deployment.  
pip install the libraries found in requirements.txt: 


    pip install -r requirements.txt


Run the Flask app:


    python3 web_app/app.py


Visit http://localhost:5000/ in your web broswer.


# About the Browser Tool

## Security  
This is a locally hosted browser app, so it is safe from common web-based attacks. Security during Elastic querying is provided by access through a VPN, and credentials required. Once the data is in the Flask app, web_app/app.py protects honeypot data from HTTP verb tampering by rejecting unsafe HTTP methods.

## Data Pipeline  
T-Pot stores a log of data for a predetermined amount of time in Elastic. Several honeypots use Suricata and p0f for network analysis and threat detection, and these tools inadvertently show up as honeypot names in the "type" column.

### Collection and Cleaning
query_and_process.py creates a "Data Plumber" that queries Elastic search for honeypot data and analyzes it in increments of 60 minutes.   
honeypot_data_cleaning_fixed.py uses the Data Plumber's jsonl output file and creates a "Data Janitor" that takes the new hour of data, then cleans the data by scanning for then dropping:  
- Empty and duplicate rows
- columns that contain only one value
- Sparse columns (nan > 0.5)
- Internal T-Pot traffic  
- Data from network analysis and threat detection software (Suricata, p0f)

### Organizing
The end result of honeypot_data_cleaning_fixed.py is a collection of CSV files.
These files are divided into hourly data, historical data, and honeypot summary data. This is found in web_app/data/.
- **hourly_data**: Overwritten with each query. Contains number of hits per organization, and a CSV with full columns for that hour (customizable).
- **historical_data**: Appended to with each query. To prevent it from becoming too large to manage and process, this contains summaries of data from the query.
- Historical Data/**honeypot_summaries**: Historical data summaries specific to each honeypot.

### Flask Browser App
Opens port 5000 and reads the contents of the data folder into dataframes. Converts to JSONL tables and serves to the Javascript front end (For better speed, future work should instead read the CSVs in the JS to reduce slowdown caused by Python). Every 3600 seconds (1 hour), the app calls query_and_process.py to get new hourly data and update historical data.

  ### Front End
  The layout of the browser tool is similar to the data folder structure, where the user can choose to view either historical data, data from the past hour, or choose a honeypot to monitor.  
  
**web_app/static**   
Contains a .js file for each html page (web_app/templates). The file chart.js provides helper functions that simplify adding charts to the web page. loadData.js is the communication between app.py and the front end. This is where tables are loaded into the front end.
