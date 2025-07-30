Versions for packages in the app found by running the container in interactive mode and checking pip show [package] or [package] --version  

***T-Pot Elk Stack***  
T-Pot Version: 24.04.1  
Kibana Version: 8.18.3  
Elastic Version: 1.7.0  
Logstash: 24.04.1  

***Base Image***:  [python:3.14.0rc1-alpine3.22](https://hub.docker.com/layers/library/python/3.14.0rc1-alpine3.22/images/sha256-926ae7993a3d6f5d0d4a733c6c2fec005aefb9dccf71fef3a9c3ed38254ffb2e)   
An archived Alpine image. No vulnerabilities as of 07/29/2025.  

***Package Manager***: apk 2.14.6  

***Installs with apk***  
GNU compiler Build Tools: build-base gcc  14.2.0  
gcc runtime library: libstdc++  14.2.0    

***requirements.txt pip installs***  
flask 3.1.1  
Werkzeug 3.1.3  
pandas 2.3.1  
requests 2.32.4  
urllib3 2.5.0  
dotenv 0.9.9  
datetime 5.5  

***Front end***  
HTML5  
[cve.org's list of HTML5 vulnerabilties: 122 as of 07/29/2025](https://www.cve.org/CVERecord/SearchResults?query=html5)  

Javascript on Chrome browser: 211 vulnerabilities as of  07/29/2025  
[NIST's list of Javascript on Chrome vulnerabilities](https://nvd.nist.gov/vuln/search#/nvd/home?keyword=javascript%20chrome&resultType=records)  

Javascript on Firefox browser: 363 vulnerabilities as of 07/29/2025  
[cve.org's list of Javascript on Firefox vulnerabilities](https://nvd.nist.gov/vuln/search#/nvd/home?keyword=javascript%20firefox&resultType=records)  

Javascript on latest Brave browser: 3 vulnerabilities as of 07/29/2025  
[NIST's list of Javascript on Brave vulnerabilities](https://nvd.nist.gov/vuln/search#/nvd/home?keyword=javascript%20brave&resultType=records)  
- CVE-2018-10798, Base score 6.5: "caused by mishandling of JavaScript code that triggers the reload of a page continuously with an interval of 1 second".
    -   Mitigation: Update to Brave version beyond 0.14.0.  

Note that the long list of CVEs on HTML and Javascript found by cve.org are limited to the libraries and packages in the SBOM for this app.  
Chart.js  
(https://www.cve.org/CVERecord/SearchResults?query=chart.js)
