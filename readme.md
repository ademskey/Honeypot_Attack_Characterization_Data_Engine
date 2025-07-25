# Authors: Adam Caudle, Emily West, Caitlyn Boyd, Jack Crawford

# Stack: (At the time of creation)
T-Pot Version: 24.04.1 
Kibana Version: 8.18.3
Elastic Version: 1.7.0

Browser Tool (/web_app):
Python: 3.10.12
Flask: 3.1.0/Werkzeung 3.1.3
Javascript: 12.22.9

# Setting up:
Create a ".env" file for http authorization (needed to pull information from honeypot)


    # Then, make sure the proxies are configured in the script
    ex code:
    proxies = {
    "http": "socks5h://0.tcp.us-cal-1.ngrok.io:19083",
    "https": "socks5h://0.tcp.us-cal-1.ngrok.io:19083"
    }

    You should then be able to request data via the script.

# Running the app:
Have python3 installed
Connect to Cyberrange Poulsbo's VPN
pip install the libraries found in requirements.txt: 
    # pip install -r requirements.txt
In Honeypot_Attack_Characterization_Data_Engine/web_app, run: 
    # python3 web_app/app.py
Visit http://127.0.0.1:5000/ in your web broswer.


# About the Web App:

