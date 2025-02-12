# MISPionage - README

## Overview 

MISPionage is a Python script designed to automate the process of fetching Indicators of Compromise (IoCs) from the MISP (Malware Information Sharing Platform & Threat Sharing) API, extracting relevant IoC information, and then updating QRadar reference sets with these IoCs using batch updates. The script also allows you to save the IoCs to a CSV file for further analysis and schedule the script to run periodically on Windows or Linux systems. 

## Features 

- **Fetch IoCs from MISP:** Retrieve IoCs by filtering on event IDs or attribute types (e.g., IPs, domains, file hashes). 
- **Filter and Extract IoCs:** Only extracts IoCs that are marked with `to_ids=True` in MISP. 
- **CSV Export:** Saves the extracted IoCs to a CSV file for offline analysis. 
- **Batch Updates to QRadar:** Updates QRadar reference sets with the fetched IoCs using a bulk API endpoint. If a batch update fails, the script will fall back to updating IoCs one-by-one. 
- **Grouping Strategy:** Groups IoCs based on the reference set name (e.g., `MISP_domain`, `MISP_ip-src`) for efficient updates. 
- **Task Scheduling:** Schedule the script to run automatically on Windows (via Task Scheduler) or Linux (via cron jobs). 

## Requirements 
- **Python 3.x:** Ensure Python 3.6 or higher is installed. 
- **Required Libraries:** 
- `requests` 
- `csv` 
- `json` 
- `urllib3` 
- `logging` 
- `tqdm` 
- `colorama` 
- `pyfiglet` 
- `python-dotenv` 


Install the required libraries with:  pip install requests tqdm colorama pyfiglet python-dotenv

Configuration
-------------

Before running the script, create a `.env` file (plain text, no extension) in the same directory as the script with the following content:


-   `MISP_URL`: URL of your MISP instance (e.g., `https://your.misp.instance/`).
-   `MISP_API_KEY`: Your MISP API key.
-   `QRADAR_API`: The URL for the QRadar reference set API.
-   `QRADAR_API_KEY`: Your QRadar API key.

> **Note:** The `.env` file must be named exactly `.env` (without any extension) so that it is properly loaded by `python-dotenv`.


Command Line Arguments
----------------------

### Available Arguments

-   `--event-ids`:\
    Specify one or more MISP event IDs to fetch IoCs from.

-   `--attribute-type`:\
    Specify the type of MISP attribute to filter by (e.g., `ip-src`, `domain`, `md5`).

-   `--limit`:\
    Limit the number of IoCs returned for attribute-based searches.

-   `--batch`:\
    Enable batch update mode for QRadar reference sets.

-   `--namespace`:\
    Set the namespace for QRadar reference sets. Default is `SHARED`. You can toggle this to `TENANT` by specifying `--namespace TENANT`.

-   `--domain-id`:\
    Set the domain ID for the reference set in QRadar. Default is `SHARED`.

-   `--fields`:\
    Specify additional fields to return in the response. Leave empty for now, as it is optional.

-   `--help`:\
    Displays this help message.

Example Usage
-------------

**Example 1:** Fetch IoCs for Specific MISP Event IDs


- `python3 mispionage.py --event-ids 1234 5678`

**Example 2:** Fetch IoCs for a Specific Attribute Type (e.g., IP addresses)


- `python3 mispionage.py --attribute-type ip-src`

**Example 3:** Limit the Number of IoCs for an Attribute Type Search


- `python3 mispionage.py --attribute-type ip-src --limit 10`

**Example 4:** Batch Update IoCs to QRadar


- `python3 mispionage.py --attribute-type ip-src --batch`

**Example 5:** Set QRadar Namespace to `TENANT`


- `python3 mispionage.py --namespace TENANT --attribute-type ip-src --batch`


Task Scheduling
---------------

### Scheduling on Windows

The script can be scheduled to run automatically using Windows Task Scheduler (`schtasks`).


### Scheduling on Linux

On Linux, the script can be scheduled using cron jobs.


Logging
-------

Logs are stored in the file specified by the `LOG_FILE` configuration and can be reviewed to track script activities, including successful and failed operations.

### Example Output

#### MISP Fetching IoCs:


- `[*] Fetching IoCs for MISP event ID: 1234... `
- `[+] Found 10 IoCs for event ID 1234.`
- `[*] Fetching IoCs for MISP event ID: 5678...` 
- `[+] Found 5 IoCs for event ID 5678.`
- `[+] Successfully updated 'MISP_ip-src' with IoC: 192.168.1.1`

#### QRadar Update:



- `[+] Successfully updated 'MISP_ip-src' with IoC: 192.168.1.1`
- `[-] Error updating QRadar reference set 'MISP_ip-src': HTTP 500 - Internal Server Error`

#### CSV Save:

- `[+] IoCs saved to misp_values_20250101_120000.csv`

Error Handling
--------------

If the script fails to fetch IoCs from MISP or update QRadar, error messages will be logged and printed to the terminal.

If no IoCs are found for the provided filters, the script will inform the user and continue.

Disabling SSL Warnings
----------------------

The script disables SSL warnings when connecting to MISP using the `urllib3` library. This is particularly useful when working with servers using self-signed certificates or when SSL verification issues are present.



`urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)`

### Why It's Disabled:

-   **Prevent Clutter:** Prevents unnecessary SSL warnings in the terminal, especially useful in automated runs.
-   **Self-Signed Certificates:** Many internal servers use self-signed certificates, and this setting ensures uninterrupted execution.

**Note:** While convenient, disabling SSL verification can expose you to security risks. It's recommended only for controlled, trusted environments.

License
-------

This script is open-source and licensed under the MIT License. You are free to use, modify, and distribute it under the terms of the MIT License.

Contact
-------

For questions or support, feel free to open an issue on the GitHub repository or contact the author at chrisvasileia93@gmail.com.
