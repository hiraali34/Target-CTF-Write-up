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



**Flag Format** CVE-<year>-<number>
# Solution:
I started by looking at the network diagram to understand what was going on 
The network diagram is simple: Traffic from the internet passes through the firewall, then the router, and is segmented into the internal network/DMZ via the router, each containing four machines or servers.
Next, I started analyzing CVEs for each system and looked for the word  “critical” and found 5 vulnerabilities with a severity level of critical and used the JSON viewer website to get the data organized: https://jsonviewer.stack.hu/


# Offensive labeled with "O"

