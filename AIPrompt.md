# Generative AI Prompt

### Generative AI Format 

```
Main Header (#)

Sub Header (##)

Bullet points (-) or (*)

Bold txt (**) or (__)

Italicize txt (*) or (_)

numbered list, use a number followed by a period and space. like
1. **Step 1**
2. **Step 2**
3. …

```  

### Create Analysis Report (Bullet Points Format)
```
Create an analysis report of the Lockbit  Ransomware Attack as it relates to the cyber kill chain, using the following format:

# Threat Report

## Overview

- **Threat Name:**

- **Date of Occurrence:**

- **Industries Affected:**

- **Impact:**

## Cyber Kill Chain Analysis
1. **Kill chain step 1:**
2. **Kill chain step 2:**
3. …

## Mitigation Recommendations
- *Mitigation recommendation 1*
- *Mitigation recommendation 2*
…
```
### Create Table Format 
```
Create a table comparing 5 different security controls. The table should have the folling columns: Control Name, Description, Implementation Cost, Maintenance Cost, Effectiveness, and Ease of Implementation.
```

### VA Planning Prompt 

```
Using cybersecurity industry standards and best practices, create a complete and detailed assessment plan (not a penetration test) that includes: Introduction, outline of the process/methodology, tools needed, and a very detailed multi-layered outline of the steps. Provide a thorough and descriptive introduction and as much detail and description as possible throughout the plan. The plan should not be the only assessment of technical vulnerabilities on systems but also policies, procedures, and compliance. It should include the use of scanning tools as well as configuration review, staff interviews, and site walk-around. All recommendations should follow industry standard best practices and methods. The plan should be a minimum of 1500 words.
Create the plan so that it is specific for the following details:
Network Size: {Large}
Number of Nodes: {1000}
Type of Devices: {Desktops, Laptops, Printers, Routers}
Specific systems or devices that need to be excluded from the assessment: {None}
Operating Systems: {Windows11, Windows 10, MacOS,Linux}
Network Topology: {Star}
Access Controls: {Role-based access control}
Previous Security Incidents: {3 incidents in the last year}
Compliance Requirements: {NIST CSF}
Business Critical Assets: {Identity Data, Financial data, Personal health information}
Data Classification: {Highly confidential}
Goals and objectives of the vulnerability assessment: {To identify and prioritize potential vulnerabilities in the network and provide recommendations for remediation and risk mitigation.}
Timeline for the vulnerability assessment: {4 weeks}
Team: {3 cybersecurity professionals, including a vulnerability assessment lead and two security analysts}
Expected deliverables of the assessment: {A detailed report outlining the results of the vulnerability assessment, including identified vulnerabilities, their criticality, potential impact on the network, and recommendations for remediation and risk mitigation.}
Audience: {The organization's IT department, senior management, and any external auditors or regulators.}
Provide the plan using the following format and markdown language:
#Vulnerability Assessment Plan
##Introduction
Thorough Introduction to the plan including the scope, reasons for doing it, goals and objectives, and summary of the plan
##Process/Methodology
Description and Outline of the process/Methodology
##Tools Required
List of required tools and applications, with their descriptions and reasons needed
##Assessment Steps
Detailed, multi-layered outline of the assessment steps
```

### Threat Summary
```
Provide a detailed report about {threat_name}, using the following template (and proper markdown language formatting, headings, bold keywords, tables, etc.):
Threat Name (Heading 1)
Summary (Heading 2)
Short executive summary
Details (Heading 2)
Description and details including history/background, discovery, characteristics and TTPs, known incidents
MITRE ATT&CK TTPs (Heading 2)
Table containing all of the known MITRE ATT&CK TTPs that the {threat_name} attack uses. Include the following columns: Tactic, Technique ID, Technique Name, Procedure (How WannaCry uses it)
Indicators of Compromise (Heading 2)
Table containing all of the known indicators of compromise. Include the following columns: Type, Value, Description
```


### Command Generation for VA
```
You are a professional cybersecurity red team specialist and an expert in penetration testing as well as vulnerability scanning tools such as NMap, OpenVAS, Nessus, Burpsuite, Metasploit, and more.

Provide me with the Linux command necessary to complete the following request:

{user_input}

Assume I have all the necessary apps, tools, and commands necessary to complete the request. Provide me with the command only and do not generate anything further. Do not provide any explanation. Provide the simplest form of the command possible unless I ask for special options, considerations, output, etc. If the request does require a compound command provide all necessary operators, pipes, etc. as a single one-line command. Do not provide me with more than one variation or more than one line.

#### Example ####

You are a professional cybersecurity red team specialist and an expert in penetration testing as well as vulnerability scanning tools such as NMap, OpenVAS, Nessus, Burpsuite, Metasploit, and more.

Provide me with the Linux command necessary to complete the following request:

"Use the command line version of OpenVAS to scan my 192.168.20.0 class C network starting by identifying hosts that are up. then look for running web servers, and the perform a vulnerability scan of those web servers."

Assume I have all the necessary apps, tools, and commands necessary to complete the request. Provide me with the command only and do not generate anything further. Do not provide any explanation. Provide the simplest form of the command possible unless I ask for special options, considerations, output, etc. If the request does require a compound command provide all necessary operators, pipes, etc. as a single one-line command. Do not provide me with more than one variation or more than one line.

#####################################################################################################
```

### SDLC Development Lifecycle (SSDLC) Planning (Planning Phase)


```
#system role
You are an experienced software development manager with expertise in secure software development and the Secure Software Development Lifecycle (SSDLC).

#overview of the SSDLC
Provide a detailed overview of the Secure Software Development Lifecycle (SSDLC), highlighting the main phases and their significance.

#Initiate the planning
Considering a project for developing a secure online banking system, detail the key considerations for the initial concept and feasibility phase.

#create the requirements-gathering process
Outline a checklist for gathering and analyzing requirements for the online banking system project during the requirements phase of the SSDLC.

#Learn about the design considerations and step
Highlight important considerations when designing a secure online banking system during the system design phase of the SSDLC.

#delve into the secure coding practices
Discuss secure coding best practices to follow when developing an online banking system during the development phase of the SSDLC.

#create a list of tests
Enumerate the key types of testing that should be conducted on an online banking system during the testing phase of the SSDLC.

#Get guidance on best practices 
List some best practices for deploying an online banking system during the deployment phase of the SSDLC.

#understanding the activities during the maintenance phase 
Describe the main activities during the maintenance phase of an online banking system and how they can be managed effectively.
```
