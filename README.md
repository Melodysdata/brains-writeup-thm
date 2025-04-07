# brains-writeup-thm
Write-up for TryHackMe room Brains

> 🧠 Room: [Brains](https://tryhackme.com/room/brains)  
> 📅 Date: April 6, 2025  
> 🛡️ Goal: Gain reverse shell & capture the flag  
> 🚨 CVE used: CVE-2024-27198

# RED exploit the server!

1. First Step in the Terminal "nmap -p- <Target_IP_Address>"
```bash
nmap -p- 10.10.252.192
````
# "nmap" -> The network scanner tool
# "-p-"  -> Scans all ports (from 1 to 65535). By default, Nmap scans only the top 1000 most common ports.
# "<Target_IP_Address>" -> The IP address of the target — in the case of the Brains room


