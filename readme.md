# Authors: Adam Caudle, Emily West, Caitlyn Boyd, Jack Crawford
This project is a locally-hosted browser tool for querying, processing, cleaning, and displaying T-Pot Honeypot data. The T-Pot honeypot system is stored through Western Washington University's (WWU) cyberange. Their server has been gathering data fom various honeypots that mimic different services (i.e. medical printer, AI-chatbot, etc). Our project uses Python's Flask library for the web server and Javascript/HTML for the front end. It then connects to backend querying and processing scripts to provide succinct processed and cleaned data to the end user. 

The idea of this project is to have a lightweight app that could be deployed on a computer for threat analytics at no cost to the user (provided they got WWU's permission and credentials to view the data). This project has a lot of room to expand into ML applications such as forecasting and analysis. Additionally there is potential to create a free-to-use app that is hosted on the internet for anyone to use and view for up-to-date threat analysis at zero cost.

Our development is based on Western Washington University's Cyber Range T-Pot deployment. The deployment used the standard.yml docker compose file (contains list of honeypots used and their assigned ports). and in collaboration with their cyber-range team.

[T-Pot](https://github.com/telekom-security/tpotce) : An open-source platform for running 20+ honeypots from one central server, developed by Deutsche Telekom.  

# Honeypot ELK Stack (At the time of creation)
T-Pot Version: 24.04.1  
Kibana Version: 8.18.3  
Elastic Version: 1.7.0  
Logstash: 24.04.1

# Browser Application stack  
Python: 3.14  
Flask: 3.1.0/Werkzeung 3.1.3  
Javascript: 12.22.9  

See [vulnerabilities.md](https://github.com/ademskey/Honeypot_Attack_Characterization_Data_Engine/blob/main/vulnerabilities.md) for a complete SBOM.  

# Setting up  
Install and start the Docker engine. Connect to the Cyberrange VPN to access the T-Pot server. For HTTP authorization, create a ".env" file in the web_app folder (needed to pull information from honeypot). The .env file should follow this format:

    HONEYPOT_USER=<username>  
    HONEYPOT_PASS=<password>

web_app/static/data/configureHoneypots.js contains a list of each active honeypot and the port(s) of the T-Pot server it monitors as well as a sentence summary for the browser pages. This is currently configured to the standard.yml docker compose deployment.

# Running the browser data visualization tool

The Dockerfile runs a multistage build. The .env file containing T-Pot username and password should not be copied into container, so mount it at runtime instead (see Dockerfile and docker run commands).

The easiest way to run is with the Makefile. In the project's root directory:

    make all
    
Then follow the link provided in the terminal's output (http://localhost:5000).

To stop the container:

    make stop

To remove the image and volume (env file with credentials) associated with the container:

    make clean

Alternatively, for an interactive Alpine container shell, first build the image:

    docker build -t <image-name> .
    
Then run the interactive container:

    docker run -p 5000:5000 -it \
    -v $(pwd)/web_app/.env:/app/web_app/.env \
    <image-name> /bin/sh
    
Then run the app from the container's shell:

    app# python3 web_app/app.py

Visit http://localhost:5000/ in your web browser.


# About the Browser Tool

## Security  
This is a locally hosted browser app, so it is safe from common web-based attacks. Security during Elastic querying is provided by access through a VPN and required credentials. Once the data is in the Flask app, web_app/app.py protects honeypot data from HTTP verb tampering by rejecting unsafe HTTP methods.   

Due to the lack of functions (no outward querying, use of APIs, forward facing authentication, file upload), most common web-exploits cannot be performed. This app has been through a team-led security review, but will require aditional reviews to be compliant depending on where the system is deployed. Please contact a member of the team if a security vulnerability is found.  

The base image for the Docker container [python:3.14.0rc1-alpine3.22](https://hub.docker.com/layers/library/python/3.14.0rc1-alpine3.22/images/sha256-926ae7993a3d6f5d0d4a733c6c2fec005aefb9dccf71fef3a9c3ed38254ffb2e) has no reported CVE's according to Dockerhub as of 08/04. Additionally, elevated privileges are not available in the runtime container because the container runs as a non-root user (appuser), and Alpine Linux does not support sudo by default.  

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

# Future Work
Focus on a specific honeypot to analyzes. Work with customers to develop a honeypot that emulates specific municipal services and devices (agriculture, water treatment, other municipal services). Work on saving and storing historical data to implement machine learning for learning and predicting temporal trends.  
