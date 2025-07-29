# Authors: Adam Caudle, Emily West, Caitlyn Boyd, Jack Crawford
This project is a locally-hosted browser tool for querying, processing, cleaning, and displaying T-Pot Honeypot data. The T-pot honeypot is stored through Western Washington University's (WWU) cyberange. The honeypot they have been hosting has been gathering data fom various honeypots which mimic different serves (I.e. medical printer, ai-chatbot, etc). Our project uses Python's Flask library for the web server and Javascript/HTML for the front end. It then connects to backend querying and processing scripts to provide succinct prossessed and cleaned data to the end user. 

The idea of this project is to have a lightweight app that could be deployed on a computer for threat analytics at no cost to the user (provided they got WWU's permission and credentials to view the data). This project has a lot of room to expand into ML applications such as forcasting and analysis. Additionally there is potential to create a free-to-use app that is hosted on the internet for anyone to use and view for up-to-date threat analysis at zero cost.

Our development is based on Western Washington University's Cyber Range T-Pot deployment and in collaboration with their cyber-range team.

SBOM:
[T-Pot](https://github.com/telekom-security/tpotce) : An open-source platform for running 20+ honeypots from one central server, developed by Deutsche Telekom.

# Honeypot ELK Stack: (At the time of creation)
T-Pot Version: 24.04.1  
Kibana Version: 8.18.3  
Elastic Version: 1.7.0  
Logstash: 

# Browser Application stack  
Python: 3.14  
Flask: 3.1.0/Werkzeung 3.1.3  
Javascript: 12.22.9  

# Setting up:
Install (if needed) and run the Docker daemon. Create a ".env" file in web_app for HTTP authorization (needed to pull information from honeypot). You should then be able to request data via the script. The .env file should follow this format:

    HONEYPOT_USER=<username>  
    HONEYPOT_PASS=<password>

# Running the browser data visualization tool:

The Dockerfile runs a multistage build. The .env file containing T-Pot username and password should not be copied into container, so mount it at runtime instead.
In project root:

    docker build -t <image-name>

Run with a volume containing data folder and mount user-provided .env file (delete hashes at beginning of lines and keep the newlines):

    docker run -p 5000:5000 \
    -v $(pwd)/web_app/.env:/app/web_app/.env \
    <image-name>

For an interactive shell:

    docker run -p 5000:5000 -it \
    -v $(pwd)/web_app/data:/app/data \
    -v $(pwd)/web_app/.env:/app/web_app/.env \
    <image-name> /bin/sh
    
Then run the app from the container's shell:

    app# python3 web_app/app.py

Visit http://localhost:5000/ in your web broswer.


# About the Browser Tool

## Security  
This is a locally hosted browser app, so it is safe from common web-based attacks. Security during Elastic querying is provided by access through a VPN, and credentials required. Once the data is in the Flask app, web_app/app.py protects honeypot data from HTTP verb tampering by rejecting unsafe HTTP methods.

Due to the lack of functions (no outward querying, use of APIs, forward facing authentication, file upload), most common web-exploits cannot be performed. This app has been through a team-led security review, but will require aditional reviews to be compliant depending on where the system is deployed. Please contact a member of the team if a security vulnerability is found.

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

### Data files
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
