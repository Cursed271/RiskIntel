# RiskIntel

## Project Description

RiskIntel is a Python script aimed at making a penetration tester's life easier through the automation of threat modeling and external threat reconnaissance. This is quite a powerful tool for security professionals to systematically identify an organization's threat landscape that provides insightful information regarding the most likely vulnerabilities.

> With RiskIntel, the job of conducting deep external threat reconnaissance activities is easier for a penetration tester. The script is designed to search and compile information related to the security posture of an organization, which helps in the early detection of threats and vulnerabilities before those can actually be exploited. Automation and refinement of the threat modeling process with RiskIntel empower the security teams to stay ahead of the game with their potential adversaries and work out more solid defense mechanisms.

> Whether you are an experienced security expert or a growing professional within the sphere, RiskIntel offers the most convenient and effective solution to improve your threat assessment workflows and enhance your organization's security posture.

## Features

- Enumerate Identities from Crt.sh: Enable the automated collection and processing of Certificate Transparency logs to expose multiple types of domain identities associated with an organization and give context about its web exposure.
- Alive Check Identities: Verify that identified domains and subdomains are alive-that they are in active use and reachable.
- Extract IP Addresses: Extract all the IP addresses associated with the identified domains in order to outline the network exposure of an organization.
- Identify IP Netblocks: Extract IP netblocks to identify the size of the range of IPs that can be used by an organization.
- Evaluate the Abuse Score of the IP: Determine the risk of an IP address based on its abuse score, to measure potentially malicious or compromised IPs.
- Typosquatting Domains Extraction: The domains that are likely to be generated to leverage the typical typos or misspelling of the organization's main domains, which might be used to spread phishing or any other kind of attack.
- Extract Email Addresses: Collect email addresses affiliated with the organization in order to find possible targets of social engineering attacks, or even to check exposure.
- DNS Health Checks: Perform health and configuration appraisals of DNS records to see if their setup and securities are indeed correct to minimize the chances of DNS-related vulnerabilities.
- Web Technologies Extraction: Extract the set of technologies and frameworks used by the organization's website in order to understand the underlying technology stack and pinpoint potential security weaknesses.
- Web Title Extraction: Extracting web page titles will provide more context and metadata about the organization's web presence.
- Extract HTTP Headers: Capture the HTTP headers and analyze them for security configurations and potential misconfigurations that can be used. 
- Check SSL/TLS Versions: Analyze the SSL/TLS versions of the web servers to see whether an organization is using the latest secure versions protecting against known vulnerabilities.

## Installation

### Pre-requisites

1. Python: The script requires Python to execute. Ensure you have Python 3.6 or higher installed. You can download it from the [official Python website](https://www.python.org/downloads/).
2. Python Libraries: RiskIntel depends on several Python Libraries. These will be installed automatically when you run the `pip install -r requirements.txt`. 
3. Network Connectivity: As RiskIntel performs various network-related operations, ensure that your system has a stable internet connection and the necessary network permissions to perform external threat reconnaissannce. 
4. Authorization: Ensure you have proper authorization to perform reconnaissance and assessments on the target doamins to comply with legal and ethical guidelines. 

### Installation Steps

1. Clone the project using "git clone"
2. Go to the project directory: ```cd RiskIntel```
3. Install dependencies: ```pip3 install -r requirements.txt```
4. Run RiskIntel: ```python3 RiskIntel.py```

## Usage

To use **RiskIntel**, follow these steps:

1. Run the script: ```python3 RiskIntel.py```
2. Enter Domain Name: When prompted by the script, enter the domain name you wish to enumerate. The script will then proceed with the threat modelling and reconnaissance based on the provided domain. 

## Screenshots

![RiskIntel](https://github.com/Cursed271/RiskIntel/blob/main/RiskIntel.png)

## Script Configuration

Before running the script, you need to configure API tokens for various services. Follow these steps to obtain and set up the tokens. 
1. Create Accounts: Sign up for accounts on the following websites
	- [IpInfo](https://ipinfo.io/)
	- [AbuseIPDB](https://www.abuseipdb.com/)
	- [Prospeo](https://prospeo.io/)
2. Obtain API Tokens: Once you have created accounts, navigate to the account settings or API section to find your API tokens. 
3. Add Tokens to the Script: Open the RiskIntel.py script and locate the Global Declaration section. Replace the placeholder values with your API tokens. 

## Contribution

1. Create a personal copy of the project by forking the repository on Github
2. Make a new branch for your changes
3. Implement your improvements or fixes
4. Commit your changes and push them to your fork
5. Submit a pull request from your branch to the main repository
6. Respond to any feedback and make revisions as needed

## License

This project is licensed under the GPLv3 License. See the LICENSE file for details. 

### Summary

- Freedom to Use: You can use, modify, and distribute the software for any purpose. 
- Source Code Access: The source code is available, and you can modify it to suit your needs. 
- Copyleft: Any derivative work must also be distributed under the same GPL license, ensuring that all modifications remain open and free
- No Warranty: The software is provided "as-is" without any warranty of any kind. The author is not liable for any damages arising from the use of the software. 

## About Me

Hello, this is Steven Pereira, but most in cybersecurity refer to me as Cursed. I am from India and very much love doing Red Teaming. Presently, I work at Protiviti India Member Firm as a Senior Cybersecurity Consultant. Day to day, I do several cybersecurity-related tasks; examples include Network Reviews, web application security testing, Penetration Testing, and red teaming. I provide the implementation of security controls, audits of cloud security, and integrated information security audits.

Outside of work, I enjoy writing and contributing to various cybersecurity blogs. With my proficiency in Python development, I develop offensive cybersecurity scripts that are an integral piece for any penetration tester or red teamer. I am working on a cybersecurity book that will help and mentor junior penetration testers through some of the obstacles they might have in their early years.

When not trying to encourage cybersecurity, he can be found playing badminton, strumming his ukulele, or spending quality time with his cat and rabbits. Feel free to connect with me here on GitHub about what I am working on, and please reach out if you have any questions or would like to talk about anything in general!

- **GitHub:** [@Cursed271](https://github.com/Cursed271)
- **LinkedIn:** [@Cursed271](https://www.linkedin.com/in/cursed271/)
- **Website:** [Black Screen Of Death](https://github.com/Cursed271)

## FAQ

**Q**: What input does RiskIntel require?

**A**: RiskIntel typically requires a domain name to perform its assessments. Just mention the domain name when prompted by the script. 

**Q**: Can RiskIntel be used on any domain?

**A**: Yes, RiskIntel can be used on any domain. However, ensure that you have proper authorization before running the script against any target to comply with legal and ethical guidelines. 

**Q**: Can RiskIntel perform vulnerability scanning or port scanning?

**A**: No, RiskIntel does not include features for vulnerability scanning or port scanning. For port scanning, you can use my other scripts, IPScan or HolyScan. For vulnerability scanning, consider using dedicated tools such as Nessus or Qualys. These tools are specialized for identifying vulnerabilities and performing in-depth security assessments. 

**Q**: How can I contribute to RiskIntel?

**A**: If you'd like to contribute, you can fork the repository, make your changes, and submit a pull request. Please ensure your contributions follow the project's coding standards and include relevant tests. 

**Q**: Who do I connect for support or questions?

**A**: For support or questions, you can open an issue on the Github repository or contact me directly through the provided communication channels in this README file. 