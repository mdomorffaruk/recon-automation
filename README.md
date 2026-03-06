# Recon Automation Pipeline

A lightweight reconnaissance automation script designed to speed up the initial attack surface discovery phase during web application security testing and bug bounty hunting.

This script combines several popular open-source security tools into a single workflow to automate common reconnaissance tasks.

---

## Features

The script performs the following steps automatically:

• Subdomain enumeration  
• Active host detection  
• Port scanning  
• Directory and file discovery  
• Web Application Firewall detection  
• Automated vulnerability scanning  
• Web crawling for endpoint discovery  

---

## Tools Used

This script integrates the following tools:

- subfinder
- amass
- dnsx
- httpx
- naabu
- feroxbuster
- wafw00f
- nuclei
- katana

These tools are widely used during attack surface mapping and vulnerability discovery.

---

## Recon Workflow

The pipeline follows a typical reconnaissance process used during bug bounty hunting.

1. **Subdomain Enumeration**

```

subfinder
amass
dnsx

```

2. **Live Host Detection**

```

httpx

```

3. **Port Scanning**

```

naabu

```

4. **Directory & Content Discovery**

```

feroxbuster

```

5. **WAF Detection**

```

wafw00f

```

6. **Automated Vulnerability Scanning**

```

nuclei

```

7. **Endpoint Crawling**

```

katana

```

---

## Usage

Clone the repository:

```

git clone [https://github.com/mdomorffaruk/recon-automation.git](https://github.com/mdomorffaruk/recon-automation.git)
cd recon-automation

```

Make the script executable:

```

chmod +x hybrid_recon_v2.sh

```

Run the script:

```

./hybrid_recon_v2.sh target.com

```

The script will create a folder named after the target domain and store all results inside it.

---

## Output Structure

After running the script, results will be organized like this:

```

target.com/
├── subfinder.txt
├── amass.txt
├── dnsx.txt
├── final_subdomains.txt
├── targets.txt
├── naabu_results.txt
├── feroxbuster_results.txt
├── waf_detection.txt
└── nuclei_results.txt

```

This structure helps organize recon data for further manual testing.

---

## Purpose

This project was created as part of my offensive security practice and bug bounty workflow.

The goal is to automate repetitive reconnaissance tasks so more time can be spent on manual vulnerability testing.

---

## Disclaimer

This tool is intended for **educational purposes and authorized security testing only**.

Do not use this script against systems without proper authorization.

