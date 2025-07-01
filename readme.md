# Authors: Adam Caudle, Emily West, Caitlyn Boyd, Jack Crawford

# Stack:
T-Pot Version:
Kibana Version:
Elastic Version:

# Setting up:
Create a ".env" file for http authorization (needed to pull information from honeypot)

# When on google collab and using data-collection script:
    # Use Socks5 to set up a proxy on personal computer with VPN access
    ex cmd: ssh -N -D 1080 adamcaudle@localhost

    # Then, set expose that proxy to the internet with ngrok
    ex cmd: ngrok tcp 1080

    # Then, make sure the proxies are configured in the script
    ex code:
    proxies = {
    "http": "socks5h://0.tcp.us-cal-1.ngrok.io:19083",
    "https": "socks5h://0.tcp.us-cal-1.ngrok.io:19083"
    }

    You should then be able to request data via the script.
