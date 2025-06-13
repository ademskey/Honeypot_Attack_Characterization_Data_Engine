import requests
from requests.auth import HTTPBasicAuth
import json
import urllib3

# Suppresses insecure request warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Kibana endpoint for Elasticsearch search (had to use internal since it's not outwardly hosted for security)
# I found this by looking through proxy trafic since i'm new to kibana
url = "https://honeypotlab.cyberrangepoulsbo.com/kibana/internal/search/es"

# Basic auth
#TODO: Remove plaintext creds
auth = HTTPBasicAuth("tpotteam", "Pr0j3ct!W!n722")

# Required headers
headers = {
    "Content-Type": "application/json",
    "kbn-version": "8.18.1",
    "kbn-xsrf": "true"
}

# Search body: match anything in the last week from index "honeypot"
query_body = {
    "params": {
        "index": "logstash-*",  # Wildcard to catch all daily indices (Wasn't sure where to pull from)
        "body": {
            "size": 10000, # Number of results that i'm grabbing
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": "2025-06-01T00:00:00Z",
                        "lte": "2025-06-12T23:59:59Z"
                    }
                }
            },
            "_source": True  # Get all fields to explore structure
        }
    }
}

# Send POST request
response = requests.post(url, headers=headers, auth=auth, json=query_body, verify=False)

# Output results
print("Status:", response.status_code)
try:
    data = response.json()
    hits = data.get("rawResponse", {}).get("hits", {}).get("hits", [])
    
    print(f"Total hits: {len(hits)}")

    with open("honeypot_data.jsonl", "w") as outfile:
        for hit in hits:
            doc = hit.get("fields", {}) or hit.get("_source", {})  # fallback for format differences
            outfile.write(json.dumps(doc) + "\n")  # Write each doc as a single JSON line

    print("Saved to honeypot_data.jsonl")

except Exception as e:
    print("Failed to parse JSON:", e)
    print(response.text)



# Example log

# {
#   "@timestamp": [
#     "2025-06-12T23:59:58.000Z"
#   ],
#   "@version": [
#     "1"
#   ],
#   "@version.keyword": [
#     "1"
#   ],
#   "dest_ip": [
#     "172.200.200.5"
#   ],
#   "dest_ip.keyword": [
#     "172.200.200.5"
#   ],
#   "dest_port": [
#     8443
#   ],
#   "dist": [
#     "1"
#   ],
#   "dist.keyword": [
#     "1"
#   ],
#   "geoip.as_org": [
#     "Global Connectivity Solutions Llp"
#   ],
#   "geoip.as_org.keyword": [
#     "Global Connectivity Solutions Llp"
#   ],
#   "geoip.asn": [
#     215540
#   ],
#   "geoip.city_name": [
#     "Phoenix"
#   ],
#   "geoip.city_name.keyword": [
#     "Phoenix"
#   ],
#   "geoip.continent_code": [
#     "NA"
#   ],
#   "geoip.continent_code.keyword": [
#     "NA"
#   ],
#   "geoip.country_code2": [
#     "US"
#   ],
#   "geoip.country_code2.keyword": [
#     "US"
#   ],
#   "geoip.country_code3": [
#     "US"
#   ],
#   "geoip.country_code3.keyword": [
#     "US"
#   ],
#   "geoip.country_name": [
#     "United States"
#   ],
#   "geoip.country_name.keyword": [
#     "United States"
#   ],
#   "geoip.dma_code": [
#     753
#   ],
#   "geoip.ip": [
#     "178.130.47.138"
#   ],
#   "geoip.latitude": [
#     33.46875
#   ],
#   "geoip.location": [
#     {
#       "coordinates": [
#         -112.0748,
#         33.4532
#       ],
#       "type": "Point"
#     }
#   ],
#   "geoip.longitude": [
#     -112.0625
#   ],
#   "geoip.postal_code": [
#     "85036"
#   ],
#   "geoip.postal_code.keyword": [
#     "85036"
#   ],
#   "geoip.region_code": [
#     "AZ"
#   ],
#   "geoip.region_code.keyword": [
#     "AZ"
#   ],
#   "geoip.region_name": [
#     "Arizona"
#   ],
#   "geoip.region_name.keyword": [
#     "Arizona"
#   ],
#   "geoip.timezone": [
#     "America/Phoenix"
#   ],
#   "geoip.timezone.keyword": [
#     "America/Phoenix"
#   ],
#   "geoip_ext.as_org": [
#     "NOANET-WA"
#   ],
#   "geoip_ext.as_org.keyword": [
#     "NOANET-WA"
#   ],
#   "geoip_ext.asn": [
#     16713
#   ],
#   "geoip_ext.city_name": [
#     "Poulsbo"
#   ],
#   "geoip_ext.city_name.keyword": [
#     "Poulsbo"
#   ],
#   "geoip_ext.continent_code": [
#     "NA"
#   ],
#   "geoip_ext.continent_code.keyword": [
#     "NA"
#   ],
#   "geoip_ext.country_code2": [
#     "US"
#   ],
#   "geoip_ext.country_code2.keyword": [
#     "US"
#   ],
#   "geoip_ext.country_code3": [
#     "US"
#   ],
#   "geoip_ext.country_code3.keyword": [
#     "US"
#   ],
#   "geoip_ext.country_name": [
#     "United States"
#   ],
#   "geoip_ext.country_name.keyword": [
#     "United States"
#   ],
#   "geoip_ext.dma_code": [
#     819
#   ],
#   "geoip_ext.ip": [
#     "170.39.180.162"
#   ],
#   "geoip_ext.latitude": [
#     47.71875
#   ],
#   "geoip_ext.location": [
#     {
#       "coordinates": [
#         -122.6536,
#         47.7327
#       ],
#       "type": "Point"
#     }
#   ],
#   "geoip_ext.longitude": [
#     -122.625
#   ],
#   "geoip_ext.postal_code": [
#     "98370"
#   ],
#   "geoip_ext.postal_code.keyword": [
#     "98370"
#   ],
#   "geoip_ext.region_code": [
#     "WA"
#   ],
#   "geoip_ext.region_code.keyword": [
#     "WA"
#   ],
#   "geoip_ext.region_name": [
#     "Washington"
#   ],
#   "geoip_ext.region_name.keyword": [
#     "Washington"
#   ],
#   "geoip_ext.timezone": [
#     "America/Los_Angeles"
#   ],
#   "geoip_ext.timezone.keyword": [
#     "America/Los_Angeles"
#   ],
#   "host": [
#     "f02d1e350a1d"
#   ],
#   "host.keyword": [
#     "f02d1e350a1d"
#   ],
#   "mod": [
#     "syn+ack"
#   ],
#   "mod.keyword": [
#     "syn+ack"
#   ],
#   "os": [
#     "???"
#   ],
#   "os.keyword": [
#     "???"
#   ],
#   "params": [
#     "none"
#   ],
#   "params.keyword": [
#     "none"
#   ],
#   "path": [
#     "/data/p0f/log/p0f.json"
#   ],
#   "path.keyword": [
#     "/data/p0f/log/p0f.json"
#   ],
#   "raw_sig": [
#     "4:63+1:0:1460:mss*44,7:mss,nop,nop,sok,nop,ws:df:0"
#   ],
#   "raw_sig.keyword": [
#     "4:63+1:0:1460:mss*44,7:mss,nop,nop,sok,nop,ws:df:0"
#   ],
#   "src_ip": [
#     "178.130.47.138"
#   ],
#   "src_ip.keyword": [
#     "178.130.47.138"
#   ],
#   "src_port": [
#     52946
#   ],
#   "subject": [
#     "srv"
#   ],
#   "subject.keyword": [
#     "srv"
#   ],
#   "t-pot_hostname": [
#     "tpot-u2404"
#   ],
#   "t-pot_hostname.keyword": [
#     "tpot-u2404"
#   ],
#   "t-pot_ip_ext": [
#     "170.39.180.162"
#   ],
#   "t-pot_ip_ext.keyword": [
#     "170.39.180.162"
#   ],
#   "t-pot_ip_int": [
#     "172.200.200.5"
#   ],
#   "t-pot_ip_int.keyword": [
#     "172.200.200.5"
#   ],
#   "type": [
#     "P0f"
#   ],
#   "type.keyword": [
#     "P0f"
#   ],
#   "_id": "PKqWZpcB688l9FjIDWWA",
#   "_index": "logstash-2025.06.12",
#   "_score": null
# }