<h1>Network Analysis with Nmap and Wireshark</h1>


<h2>Description</h2>
I used Nmap to discover and fingerprint hosts on a virtual network, determine the network topology, and identify potential vulnerabilities among the discovered hosts. I also conducted packet analysis on the virtual network using Wireshark. I then provided recommended mitigations for the identified vulnerabilities. 
<br />


<h2>Utilities Used</h2>

- <b>Nmap</b> 
- <b>Wireshark</b>

<h2>Environments Used </h2>

- <b>Kali Linux</b>

<h2>Nmap walk-through:</h2>

<p>
  I conducted a scan of the virtual network using Nmap. The target of the scan was the entire IP address range of 10.168.27.0/24. The type of Nmap scan used was a quick scan plus.
</p>
<p align="center">
Nmap Scan Results: <br/>
<img src="https://i.imgur.com/CTyyrPw.jpeg" height="90%" width="90%" alt="Nmap Scan Results"/>
</p>
<p>
  The Nmap quick scan of the target network 10.168.27.0/24 revealed six hosts arranged in a star topology. The first host, 10.168.27.1, had no identifiable OS and no open ports. The second host, 10.168.27.10, runs either Microsoft Windows Server 2012 or 2012 R2, with 8 open ports and 92 filtered ports. The third host, 10.168.27.14, runs Linux 2.6.32, with 1 open port and 99 filtered ports. The fourth host, 10.168.27.15, runs either Microsoft Windows Server 2008 R2 or Windows 8.1, with 10 open ports and 90 filtered ports. Hosts 10.168.27.20 and 10.168.27.132 both run Linux 2.6.32, each with 1 open port and 99 filtered ports.
</p>
<p align="center">
Network Topology:  <br/>
<img src="https://i.imgur.com/HOHWnoE.jpeg" height="90%" width="90%" alt="Network Topology"/>
</p>
<p>
  According to the network topology tab in Nmap, the hosts on the 10.168.27.0/24 network were arranged in a star topology, where each host connects solely to a central point without direct connections to others. This setup requires communication between hosts to pass through the central point. For instance, if host 10.168.27.14 wants to communicate with host 10.168.27.10, it must route its message through the central point. Direct communication between hosts is not possible as they only connect to the central point.
</p>
<p align="center">
Network Vulnerabilites Identified: <br/>
</p>
<p>
  One vulnerability present on the 10.168.27.0/24 network was found on host 10.168.27.15. The Nmap scan results identified the operating system of host 10.168.27.15 as either being Microsoft Windows Server 2008 R2 or Windows 8.1. Both of these operating systems are affected by CVE-2019-0583, which is a remote code execution vulnerability that occurs when the Windows Jet Database Engine has issues handling objects in memory (The MITRE Corporation, 2018a). <br/><br/>
  One possible negative implication of this vulnerability is an attacker being able to socially engineer a victim into downloading a file with malicious code (Microsoft, 2019a). If the victim executes the file, the malicious code would also execute on the victim’s client PC. This could cause a number of issues. One potential attack that could result from this vulnerability would be a remote access trojan or RAT. The RAT could be the malicious code embedded into the file. Once the file is executed by the victim, the RAT would give the attacker access to the victim’s PC. This would allow the attacker to do things such as access the files and data located on the PC. This could also allow the attacker to carry out further malicious activities on the network, especially if the victim has administrative privileges. <br/><br/>
  Another vulnerability identified on the network was found on host 10.168.27.10. The Nmap scan results identified the operating system of host 10.168.27.10 as either being Microsoft Windows Server 2012 or Windows Server 2012 R2. Both of these operating systems are affected by CVE-2019-0570, which is a vulnerability that allows privilege escalation due to Windows Runtime improperly handling objects in memory (The MITRE Corporation, 2018b). This vulnerability could allow an attacker to escalate the privileges of the victim’s user account (Microsoft, 2019b). By doing this, the attacker may be able to access or edit data that the account would not normally be allowed to access or edit, carry out actions that the account normally would not be allowed to do such as changing firewall rules, or perform other actions that the account should not be allowed to do. <br/><br/>
  There was a vulnerability discovered on the network that affects hosts 10.168.27.14, 10.168.27.20, and 10.168.27.132 because they all are running Linux 2.6.32 as their operating system. Linux 2.6.32 is affected by CVE-2017-1000251 which is a vulnerability in the Bluetooth stack of the operating system that can lead to remote code execution in the kernel space or even denial of service by crashing the system when exploited (The MITRE Corporation, 2017). This vulnerability can be exploited by an attacker connecting to the device via Bluetooth and then executing a buffer overflow attack in the Bluetooth stack (Red Hat, 2017). <br/>
</p>

<h2>Wireshark walk-through:</h2>

<p align="center">
Pcap1 File Analysis:  <br/>
<img src="https://i.imgur.com/aPvgTsl.jpeg" height="90%" width="90%" alt="Pcap1 FTP"/>
</p>
<p>
  While analyzing the Pcap1 file using Wireshark, several anomalies were discovered. One anomaly that was apparent in the network traffic was found when inspecting the use of the unsecured version of file transfer protocol (FTP).  If sensitive information such as login credentials were to be sent over the network using the unsecure version of this protocol, anyone who could capture this traffic on the network would be able to analyze the traffic and read its contents. While inspecting frames 213816 and 213821 of the Pcap1 file, it appears that login credentials were passed over the network in cleartext. 
</p>
<p align="center">
<img src="https://i.imgur.com/kT6psIP.jpeg" height="90%" width="90%" alt="Pcap1 HTTP"/>
</p>
<p>
  Another anomaly discovered while analyzing the network traffic in the Pcap1 file involved HTTP traffic. There were multiple, consecutive HTTP requests sent to host 10.168.27.10, which is believed to be a server on the network. These HTTP requests originated from an outside IP address of 10.16.80.243. This traffic could be an indication of an attempted denial of service (DoS) attack on the server located at 10.168.27.10.
</p>
<p align="center">
<img src="https://i.imgur.com/zRSB36t.jpeg" height="90%" width="90%" alt="Pcap1 MySQL 1"/>
<br />
<br />
<img src="https://i.imgur.com/a4iduj6.jpeg" height="90%" width="90%" alt="Pcap1 MySQL 2"/>
</p>
<p>
  There was also an anomaly discovered while inspecting network traffic involving the use of the MySQL protocol. The outside host located at 10.16.80.243 attempted to continuously connect to the SQL database located at 10.168.27.10. The outside host is not authorized to connect to the SQL database located at 10.168.27.10, therefore multiple attempts to connect is suspicious. There are also packets present that indicate host 10.16.80.243 was attempting to send host 10.168.27.10 invalid SQL commands that resulted in malformed packet errors. This could potentially indicate an attempt at a SQL injection attack.
</p>

<h2>Mitigation Strategies for Identified Vulnerabilities:</h2>

<p align="center">
Nmap Scan Results Vulnerability Mitigation:  <br/>
</p>
<p>
  There are several ways to mitigate the vulnerabilities and anomalies discovered through the Nmap scan as well as the network traffic analyzed in Wireshark. One way to mitigate CVE-2019-0583 that is present on host 10.168.27.15 is to make sure that the operating system has the latest security updates installed, specifically the security update that addresses the vulnerability itself (Microsoft 2019a). Though there is a security update available for this vulnerability, it should be noted that Microsoft has ended support for both Microsoft Windows Server 2008 R2 and Windows 8.1 (Baker, 2022; dknappettmsft et al., 2023). Host 10.168.27.15 should be remediated by upgrading to a Windows operating system that is still being supported and receives updates if possible. <br/><br/>
  The second vulnerability discovered from the Nmap scan results, CVE-2019-0570, should be remediated in the same manner as the previously listed vulnerability. According to the Nmap scan results, host 10.168.27.10 is either running Microsoft Windows Server 2012 or Windows Server 2012 R2 as its operating system. There is a security update for these operating systems that addresses CVE-2019-0570, and it is recommended that it be installed in order to address this vulnerability. However, upgrading the operating system, if possible, should also be considered because Microsoft will be ended official support for Microsoft Windows Server 2012 and Windows Server 2012 R2 on October 10th, 2023 (dknappettmsft et al., 2023). <br/><br/>
  The third vulnerability identified from the Nmap scan results was CVE-2017-1000251. This vulnerability affects hosts 10.168.27.14, 10.168.27.20, and 10.168.27.132 because they are all running Linux 2.6.32 as their operating system. There are several recommendations to address this vulnerability. Since this vulnerability utilizes Bluetooth as its attack vector, Bluetooth should be disabled on these systems if it is not necessary to perform work duties (Red Hat, 2017). If Bluetooth is a necessity, then it is recommended to upgrade the operating system to a more current distribution of Linux that is not affected by this vulnerability. <br/><br/>
</p>

<p align="center">
Wireshark Pcap1 File Analysis Vulnerability Mitigation:  <br/>
</p>
<p>
  This first anomaly identified in the Wireshark packet capture file involved the use of FTP. FTP is not a secure protocol and passes data in cleartext. This means anyone with access to the network can sniff the contents of the packets. This can be a problem if sensitive data such as login credentials, personal identifiable information (PII), personal health information (PHI), and other data is being passed over the network. One method of preventing this information from being passed over the network in cleartext is to use a secure alternative protocol to FTP that will not pass the data in cleartext. The data itself could also be encrypted. If possible, a virtual private network (VPN) could also be established to encrypt the data as it is being transferred on the network (Microsoft, 2023). <br/><br/>
  The second anomaly identified in the Wireshark packet capture file involved HTTP traffic. It was noticed that an outside host with the IP address of 10.16.80.243 was sending consecutive HTTP requests to the server located at 10.168.27.10. This traffic appeared to be abnormal due to the number of consecutive requests that were being sent from 10.16.80.243, and it is a possible indication of an attempted denial of service (DoS) attack on host 10.168.27.10. One way to mitigate this issue is to implement a firewall rule that would block inbound HTTP traffic from host 10.16.80.243 or to use an intrusion detection system that could send automated alerts once this type of traffic has been identified (Velimirovic, 2021). <br/><br/>
  The third anomaly identified in the Wireshark packet capture file involved the use of MySQL protocol. It appeared that host 10.16.80.243 was continuously trying to connect to the server located at 10.168.27.10 via the MySQL protocol. The analyzed network traffic not only identified multiple connection attempts, but also MySQL error messages stating that host 10.16.80.243 is not allowed to connect to the database at 10.168.27.10. The error messages also mentioned that invalid commands were sent from host 10.16.80.243, possibly indicating an attempt at SQL injection. In order to prevent this from happening, a firewall can be used to block any outside connection attempts from host 10.16.80.243. Even if host 10.16.80.243 or any other outside host were able to connect to the server, input validation can be used in order to mitigate the execution of malicious code (OWASP, 2021). <br/><br/>
</p>

<p align="center">
References:  <br/>
</p>

<p>
  Baker, T. (2022). Windows 8.1 end of support on January 10, 2023 - microsoft lifecycle. Microsoft Lifecycle | Microsoft Learn. https://learn.microsoft.com/en-us/lifecycle/announcements/windows-8-1-end-support-january-2023 <br/><br/>
dknappettmsft, Heidilohr, & v-alje. (2023, August 4). Overview of extended security updates for windows server 2008, 2008 R2, 2012, and 2012 R2. Overview of Extended Security Updates for Windows Server 2008, 2008 R2, 2012, and 2012 R2 | Microsoft Learn. https://learn.microsoft.com/en-us/windows-server/get-started/extended-security-updates-overview <br/><br/>
Microsoft. (2019a, January 8). Jet Database Engine Remote Code Execution Vulnerability. Security Update Guide - Microsoft Security Response Center. https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-0583 <br/><br/>
Microsoft. (2019b, January 8). Windows Runtime Elevation of Privilege Vulnerability. Security Update Guide - Microsoft Security Response Center. https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-0570 <br/><br/>
Microsoft. (2023). What is a VPN? why should I use a VPN?: Microsoft Azure. Why Should I Use a VPN? | Microsoft Azure. https://azure.microsoft.com/en-us/resources/cloud-computing-dictionary/what-is-vpn/#what-is-a-vpn <br/><br/>
The MITRE Corporation. (2017, September 12). CVE-2017-1000251. CVE. https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000251 <br/><br/>
The MITRE Corporation. (2018a, November 26). CVE-2019-0570. CVE. https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0570 <br/><br/>
The MITRE Corporation. (2018b, November 26). CVE-2019-0583. CVE. https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0583 <br/><br/>
OWASP. (2021). SQL injection prevention cheat sheet. SQL Injection Prevention - OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html <br/><br/>
Red Hat. (2017, September 29). Blueborne - Linux kernel remote denial of service in bluetooth subsystem - CVE-2017-1000251. Red Hat Customer Portal. https://access.redhat.com/security/vulnerabilities/blueborne <br/><br/>
Velimirovic, A. (2021, December 2). How to prevent ddos attacks: 7 tried-and-tested methods. phoenixNAP Blog. https://phoenixnap.com/blog/prevent-ddos-attacks <br/><br/>
</p>


<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
