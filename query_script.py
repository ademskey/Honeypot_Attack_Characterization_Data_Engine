# Imports ###############
import requests
from requests.auth import HTTPBasicAuth
import json
import urllib3
from dotenv import load_dotenv
import os
import select
import sys
import datetime

# User Interface #######
print("Welcome to the Honeypot Data Collector")
print("This script will collect data from the honeypot and save it to honeypot_data.jsonl")
print("Running this script will clear the current honeypot_data.jsonl file, and replace it with your new timeframe of data.")
print("You can stop the script at any time by pressing Enter.")
print("Enter the number of request to collect (1,000 increments):")
time = input("Enter the number of hours to fetch (e.g., 1, 2, 3...): ")
debug_input = input("Enter debug mode? (y/n):").strip().lower()

# Variables ############
total_hits = 0
time_to_fetch = int(time)
hours_to_fetch = time_to_fetch * 60 
curr_time = datetime.datetime.now(datetime.timezone.utc)

# Check input validity
if not time.isdigit() or int(time) <= 0:
    print("Invalid input. Please enter a positive integer.")
    sys.exit(1) 

# Pull login from .env file
load_dotenv()
user = os.getenv("HONEYPOT_USER")
password = os.getenv("HONEYPOT_PASS")
auth = HTTPBasicAuth(user, password)

# Configure search and endpoint (had to use kibana/internal/search/es since it's not outwardly hosted for security)
# I found this by looking through proxy trafic for internal search logic (individual search uses this, aggregate data search uses bsearch)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
url = "https://honeypotlab.cyberrangepoulsbo.com/kibana/internal/search/es" 

# Required headers
headers = {
    "Content-Type": "application/json",
    "kbn-version": "8.18.2",
    "kbn-xsrf": "true"
}

# Clear existing data file
open("honeypot_data.jsonl", "w").close()
print("Collecting Data", end=" ")

# Main collection loop
for i in range(hours_to_fetch):
    # Compute time window
    slice_end = curr_time - datetime.timedelta(minutes=i)
    slice_start = curr_time - datetime.timedelta(minutes=i + 1)

    # Format timestamps in ISO 8601
    gte = slice_start.strftime("%Y-%m-%dT%H:%M:%SZ")
    lte = slice_end.strftime("%Y-%m-%dT%H:%M:%SZ")

    if debug_input == "y":
        print(f"Requesting from {gte} to {lte}")
    else:
        # Print progress bar
        bar_width = 40
        progress = int((i + 1) / hours_to_fetch * bar_width)
        percent = int((i + 1) / hours_to_fetch * 100)
        bar = "[" + "#" * progress + "-" * (bar_width - progress) + f"] {percent}%"
        print("\r" + bar, end="", flush=True)


    # Check for user input to exit
    if select.select([sys.stdin], [], [], 0)[0]:
        print("\nExiting")
        line = sys.stdin.readline()
        break

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

    response = requests.post(url, headers=headers, auth=auth, json=query_body, verify=False)

    if debug_input == "y":
        print("Status Code:", response.status_code)
    if response.status_code != 200:
        print("Error fetching data:", response.status_code, response.text)
        continue

    try:
        data = response.json()
        hits = data.get("rawResponse", {}).get("hits", {}).get("hits", [])
        total_hits += len(hits)

        if debug_input == "y":
            print(f"Request Hits: {len(hits)}")

        with open("honeypot_data.jsonl", "a") as outfile:
            for hit in hits:
                doc = hit.get("fields", {}) or hit.get("_source", {})
                outfile.write(json.dumps(doc) + "\n")

        if debug_input == "y":        
            print("Saved to honeypot_data.jsonl")

    except Exception as e:
        print("Failed to parse JSON:", e)
        print(response.text)
        
print("\nData collection complete.")
print(f"{hours_to_fetch} minute slices of data collected")
print(f"{total_hits} total hits")