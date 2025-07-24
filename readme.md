# Authors: Adam Caudle, Emily West, Caitlyn Boyd, Jack Crawford

# Stack: (At the time of creation)
T-Pot Version: 24.04.1 
Kibana Version: 8.18.3
Elastic Version: 1.7.0
Flask: 

# Setting up:
Create a ".env" file for http authorization (needed to pull information from honeypot)


    # Then, make sure the proxies are configured in the script
    ex code:
    proxies = {
    "http": "socks5h://0.tcp.us-cal-1.ngrok.io:19083",
    "https": "socks5h://0.tcp.us-cal-1.ngrok.io:19083"
    }

    You should then be able to request data via the script.

# Running data visualization (/web_app):
    # Have python3 installed
    # Connect to Cyberrange Poulsbo's VPN
    # pip install the libraries found in requirements.txt: pip install -r requirements.txt
    # in Honeypot_Attack_Characterization_Data_Engine/web_app, run: python3 app.py
    # Visit http://127.0.0.1:5000/ in your web broswer.
