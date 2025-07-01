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

# Running the web app:
    # Have python3 installed
    # pip install the libraries found in packages.py
    # in Honeypot_Attack_Characterization_Data_Engine/web_app, run [python3 app.py]
    # Visit http://127.0.0.1:5000/ in your web broswer.