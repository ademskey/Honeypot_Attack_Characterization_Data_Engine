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
Note that the long list of CVEs on HTML and Javascript found by cve.org are limited to the libraries and packages in the SBOM for this app.  
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


Chart.js  
(https://www.cve.org/CVERecord/SearchResults?query=chart.js)


Semgrep Analysis:
  Dockerfile
   ❯❯❱ dockerfile.security.missing-user.missing-user
          By not specifying a USER, a program in the container may run as 'root'. This is a security hazard.
          If an attacker can control a process running as root, they may have control over the container.   
          Ensure that the last USER in a Dockerfile is a USER other than 'root'.                            
          Details: https://sg.run/Gbvn                                                                      
                                                                                                            
           ▶▶┆ Autofix ▶ USER non-root CMD ["flask", "run", "--host=0.0.0.0"]
           65┆ CMD ["flask", "run", "--host=0.0.0.0"]
                                               
    web_app/query_and_process.py
   ❯❯❱ python.requests.security.disabled-cert-validation.disabled-cert-validation
          Certificate verification has been explicitly disabled. This permits insecure connections to insecure
          servers. Re-enable certification validation.                                                        
          Details: https://sg.run/AlYp                                                                        
                                                                                                              
           ▶▶┆ Autofix ▶ requests.get( f"{base_url}/api/status", auth=auth, verify=True )
          112┆ response = requests.get(
          113┆     f"{base_url}/api/status",
          114┆     auth=auth,
          115┆     verify=False
          116┆ )
            ⋮┆----------------------------------------
           ▶▶┆ Autofix ▶ requests.post(self.elastic_url, headers=headers, auth=self.auth, json=query_body, verify=True)
          229┆ response = requests.post(self.elastic_url, headers=headers, auth=self.auth,
               json=query_body, verify=False)                                             
                                          
    web_app/query_script.py
   ❯❯❱ python.requests.security.disabled-cert-validation.disabled-cert-validation
          Certificate verification has been explicitly disabled. This permits insecure connections to insecure
          servers. Re-enable certification validation.                                                        
          Details: https://sg.run/AlYp                                                                        
                                                                                                              
           ▶▶┆ Autofix ▶ requests.get( f"{base_url}/api/status", auth=auth, verify=True )
           17┆ response = requests.get(
           18┆     f"{base_url}/api/status",
           19┆     auth=auth,
           20┆     verify=False
           21┆ )
            ⋮┆----------------------------------------
           ▶▶┆ Autofix ▶ requests.post(url, headers=headers, auth=auth, json=query_body, verify=True)
          121┆ response = requests.post(url, headers=headers, auth=auth, json=query_body, verify=False)
                                                    
    web_app/templates/historical.html
    ❯❱ html.security.audit.missing-integrity.missing-integrity
          This tag is missing an 'integrity' subresource integrity attribute. The 'integrity' attribute allows
          for the browser to verify that externally hosted files (for example from a CDN) are delivered       
          without unexpected manipulation. Without this attribute, if an attacker can modify the externally   
          hosted resource, this could lead to XSS and other types of attacks. To prevent this, include the    
          base64-encoded cryptographic hash of the resource (file) you’re telling the browser to fetch in the 
          'integrity' attribute for all externally hosted files.                                              
          Details: https://sg.run/krXA                                                                        
                                                                                                              
            7┆ <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            ⋮┆----------------------------------------
            8┆ <script src="https://cdn.jsdelivr.net/npm/luxon"></script>
            ⋮┆----------------------------------------
            9┆ <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-luxon"></script>
                                                  
    web_app/templates/honeypot.html
    ❯❱ html.security.audit.missing-integrity.missing-integrity
          This tag is missing an 'integrity' subresource integrity attribute. The 'integrity' attribute allows
          for the browser to verify that externally hosted files (for example from a CDN) are delivered       
          without unexpected manipulation. Without this attribute, if an attacker can modify the externally   
          hosted resource, this could lead to XSS and other types of attacks. To prevent this, include the    
          base64-encoded cryptographic hash of the resource (file) you’re telling the browser to fetch in the 
          'integrity' attribute for all externally hosted files.                                              
          Details: https://sg.run/krXA                                                                        
                                                                                                              
            9┆ <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
                                                
    web_app/templates/hourly.html
    ❯❱ html.security.audit.missing-integrity.missing-integrity
          This tag is missing an 'integrity' subresource integrity attribute. The 'integrity' attribute allows
          for the browser to verify that externally hosted files (for example from a CDN) are delivered       
          without unexpected manipulation. Without this attribute, if an attacker can modify the externally   
          hosted resource, this could lead to XSS and other types of attacks. To prevent this, include the    
          base64-encoded cryptographic hash of the resource (file) you’re telling the browser to fetch in the 
          'integrity' attribute for all externally hosted files.                                              
          Details: https://sg.run/krXA                                                                        
                                                                                                              
            7┆ <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            ⋮┆----------------------------------------
            8┆ <script src="https://cdn.jsdelivr.net/npm/luxon"></script>
            ⋮┆----------------------------------------
            9┆ <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-luxon"></script>

                
                
┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
 • Findings: 12 (12 blocking)
 • Rules run: 466
 • Targets scanned: 65
 • Parsed lines: ~100.0%
 • Scan skipped: 
   ◦ Files larger than  files 1.0 MB: 2
 • Scan was limited to files tracked by git
 • For a detailed list of skipped files and lines, run semgrep with the --verbose flag
Ran 466 rules on 65 files: 12 findings.
💎 Missed out on 1390 pro rules since you aren't logged in!
⚡ Supercharge Semgrep OSS when you create a free account at https://sg.run/rules.