import datetime
import json
import os
import requests
import sys
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
import urllib3
import select

# Scroll Settings
BATCH_MINUTES = 30  # Fetch 30-minute scroll windows
SCROLL_TIME = "2m"  # Keep scroll context alive for 5 minutes (timeout between requests)
PAGE_SIZE = 10000    # Number of hits per scroll page

print("Welcome to the Honeypot Data Collector")
time = input("Enter the number of hours to fetch (e.g., 1, 2, 3...): ")
debug_input = input("Enter debug mode? (y/n):").strip().lower()

if not time.isdigit() or int(time) <= 0:
    print("Invalid input. Please enter a positive integer.")
    sys.exit(1)

time_to_fetch = int(time)
total_minutes = time_to_fetch * 60
num_batches = total_minutes // BATCH_MINUTES
curr_time = datetime.datetime.now(datetime.timezone.utc)

load_dotenv()
user = os.getenv("HONEYPOT_USER")
password = os.getenv("HONEYPOT_PASS")
auth = HTTPBasicAuth(user, password)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
url = "https://honeypotlab.cyberrangepoulsbo.com/kibana/internal/search/es"

headers = {
    "Content-Type": "application/json",
    "kbn-version": "8.18.2",
    "kbn-xsrf": "true"
}

# Clear existing data file
open("honeypot_data.jsonl", "w").close()

print("Collecting Data")

for batch_idx in range(num_batches):
    # Calculate time window for batch
    slice_end = curr_time - datetime.timedelta(minutes=batch_idx * BATCH_MINUTES)
    slice_start = curr_time - datetime.timedelta(minutes=(batch_idx + 1) * BATCH_MINUTES)
    gte = slice_start.strftime("%Y-%m-%dT%H:%M:%SZ")
    lte = slice_end.strftime("%Y-%m-%dT%H:%M:%SZ")

    if debug_input == "y":
        print(f"\nRequesting data from {gte} to {lte}")

    # Build base query (no scroll here because this endpoint is proxied; see note below)
    query_body = {
        "params": {
            "index": "logstash-*",
            "scroll": SCROLL_TIME,
            "body": {
                "size": PAGE_SIZE,
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

    # Initial request with scroll param
    response = requests.post(
        url + "?scroll=" + SCROLL_TIME,
        headers=headers,
        auth=auth,
        json=query_body,
        verify=False
    )

    if response.status_code != 200:
        print(f"Error: HTTP {response.status_code} for batch {batch_idx}")
        print(response.text)
        continue

    data = response.json()
    scroll_id = data.get('_scroll_id')
    hits = data['hits']['hits'] if 'hits' in data else []
    print(f"Batch {batch_idx + 1}/{num_batches} - Retrieved {len(hits)} documents")
    if debug_input == "y":
        print(f"Scroll ID: {scroll_id}")
    if not hits:
        print("No hits found for this batch, skipping to next.")
        continue

    # Write first page
    with open("honeypot_data.jsonl", "a") as f:
        for doc in hits:
            f.write(json.dumps(doc) + "\n")

    # Scroll loop to get remaining pages
    while hits:
        # User abort check
        if select.select([sys.stdin], [], [], 0)[0]:
            print("\nExiting by user input.")
            sys.exit(0)

        scroll_body = {
            "scroll": SCROLL_TIME,
            "scroll_id": scroll_id
        }

        scroll_response = requests.post(
            "https://honeypotlab.cyberrangepoulsbo.com/_search/scroll",
            headers=headers,
            auth=auth,
            json=scroll_body,
            verify=False
        )

        if scroll_response.status_code != 200:
            print(f"Scroll error HTTP {scroll_response.status_code}")
            print(scroll_response.text)
            break

        scroll_data = scroll_response.json()
        hits = scroll_data['hits']['hits']
        scroll_id = scroll_data.get('_scroll_id')

        if not hits:
            break  # Done with this batch

        with open("honeypot_data.jsonl", "a") as f:
            for doc in hits:
                f.write(json.dumps(doc) + "\n")

                if debug_input == "y":
                    print(f"Writing {len(hits)} documents to file")


    # Progress bar
    bar_width = 40
    progress = int((batch_idx + 1) / num_batches * bar_width)
    percent = int((batch_idx + 1) / num_batches * 100)
    bar = "[" + "#" * progress + "-" * (bar_width - progress) + f"] {percent}%"
    print("\r" + bar, end="", flush=True)

print("\nData collection complete.")