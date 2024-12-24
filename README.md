# Pyload RCE Exploit 

## Overview

`pyload_rce.py` is a Python script designed to exploit vulnerabilities in Pyload and js2py. This script allows an attacker to achieve remote code execution (RCE) on vulnerable instances of Pyload by escaping the js2py sandbox environment.

## Features

- **Vulnerability Check**: Determines if the target Pyload instance is vulnerable to command injection.
- **Remote Command Execution**: Executes arbitrary commands on the target system if it's vulnerable.
- **JavaScript Payload Generation**: Constructs a JavaScript payload to escape the js2py sandbox.
- **Secure Randomness**: Utilizes cryptographically secure random number generation for unpredictable payloads.
- **User-Friendly Interface**: Simple command-line interface for easy usage.

## Prerequisites

- **Python 3.6 or higher**
- **Required Python Libraries**:
  - `requests`
  
  Install the required libraries using pip:

  ```bash
  pip install requests
