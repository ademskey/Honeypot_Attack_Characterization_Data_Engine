import requests
from requests.auth import HTTPBasicAuth
import json
import urllib3
from dotenv import load_dotenv
import os
import select
import sys

# Pull login from .env file
load_dotenv()
user = os.getenv("HONEYPOT_USER")
password = os.getenv("HONEYPOT_PASS")
auth = HTTPBasicAuth(user, password)

# Configure search and endpoint (had to use kibana/internal/search/es since it's not outwardly hosted for security)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
url = "https://honeypotlab.cyberrangepoulsbo.com/kibana/internal/search/es" 
# I found this by looking through proxy trafic for internal search logic (individual search uses this, aggregate data search uses bsearch)

# Required headers
headers = {
    "Content-Type": "application/json",
    "kbn-version": "8.18.2",
    "kbn-xsrf": "true"
}

# Search body: match anything in the last week from index "honeypot"
query_body = {
    "params": {
        "index": "logstash-*",
        "body": {
            "size": 1000,
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": "now-1d",
                        "lte": "now"
                    }
                }
            },
            "_source": True
        }
    }
}

total_hits = 0
print("Enter the number of request to collect (1,000 increments):")
days = input()

print("Streaming")
for i in range(int(days)):
    # Quit streaming on user input
    if select.select([sys.stdin], [], [], 0)[0]:
        print("\nExiting")
        line = sys.stdin.readline()
        break

    else:
        # Send POST request
        response = requests.post(url, headers=headers, auth=auth, json=query_body, verify=False)
        print("Status Code:", response.status_code)

        # Output results
        # print("Status:", response.status_code)
        try:
            data = response.json()
            hits = data.get("rawResponse", {}).get("hits", {}).get("hits", [])
            total_hits += len(hits)
            print(f"Request Hits: {len(hits)}")

            with open("honeypot_data.jsonl", "w") as outfile:
                for hit in hits:
                    doc = hit.get("fields", {}) or hit.get("_source", {})  # fallback for format differences
                    outfile.write(json.dumps(doc) + "\n")  # Write each doc as a single JSON line

            #print("Saved to honeypot_data.jsonl")

        except Exception as e:
            print("Failed to parse JSON:", e)
            print(response.text)
        
print(f"{days} days of data collected")
print(f"{total_hits} total hits")
