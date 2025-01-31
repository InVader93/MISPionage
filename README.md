MISPionage - README
===================

Overview
--------

**MISPionage** is a Python script designed to automate the process of fetching Indicators of Compromise (IoCs) from the MISP (Malware Information Sharing Platform & Threat Sharing) API, extracting relevant IoC information, and then updating QRadar reference sets with these IoCs. Additionally, it allows the user to save the IoCs to a CSV file for further analysis and scheduling the script to run periodically.

### Features

-   Fetch IoCs from MISP based on event IDs or attribute types (e.g., IPs, domains, file hashes).
-   Filter and extract IoCs that are marked with `to_ids=True` in MISP.
-   Save the extracted IoCs to a CSV file.
-   Update QRadar reference sets with the fetched IoCs.
-   Schedule the script to run periodically on Windows or Linux systems.

Requirements
------------

-   **Python 3.x**: Ensure that Python 3.6 or higher is installed.
-   **Libraries**:
    -   `requests`: For making HTTP requests to MISP and QRadar.
    -   `csv`: To write the IoCs to a CSV file.
    -   `json`: For parsing JSON responses.
    -   `urllib3`: To handle HTTP connections with retry mechanisms.
    -   `logging`: For logging script activities.
    -   `tqdm`: For displaying a progress bar during script execution.
    -   `colorama`: For colored terminal output.
    -   `pyfiglet`: To display ASCII art in the terminal.

Install the required libraries by running:


`pip install requests tqdm colorama pyfiglet`

Configuration
-------------

Before running the script, modify the configuration variables in the script:

-   `MISP_URL`: URL of your MISP instance (e.g., `https://your.misp.instance/`).
-   `MISP_API_KEY`: Your MISP API key.
-   `QRADAR_API`: The URL for the QRadar reference set API.
-   `QRADAR_API_KEY`: Your QRadar API key.
-   `OUTPUT_CSV_FILE`: Filename template for saving the IoCs as CSV.
-   `LOG_FILE`: Log file for storing script logs.

Make sure you have valid credentials and access to both MISP and QRadar.

Usage
-----

The script allows you to fetch IoCs from MISP and either filter them by event ID or attribute type. You can also limit the number of IoCs returned.

### Command Line Arguments

-   `--event-ids`: Specify one or more MISP event IDs to fetch IoCs from.
-   `--attribute-type`: Specify the type of MISP attribute to filter by (e.g., `ip-src`, `domain`, `md5`).
-   `--limit`: Limit the number of IoCs returned for attribute-based searches.

#### Example 1: Fetch IoCs for Specific MISP Event IDs



`python3 mispionage.py --event-ids 1234 5678`

#### Example 2: Fetch IoCs for a Specific Attribute Type (e.g., IP addresses)



`python3 mispionage.py --attribute-type ip-src`

#### Example 3: Limit the Number of IoCs for an Attribute Type Search



`python3 mispionage.py --attribute-type ip-src --limit 10`

Task Scheduling
---------------

The script can be scheduled to run automatically at a specified time on both Windows and Linux systems.

1.  When prompted, choose whether you want to schedule the task.
2.  Specify your operating system (Windows or Linux).
3.  Set the time (in 24-hour format) at which you want the script to run.

For Windows:

-   Uses Windows Task Scheduler (`schtasks`) to schedule the script.

For Linux:

-   Uses cron jobs to schedule the script.

Logging
-------

Logs are stored in the file specified by `LOG_FILE` and can be reviewed to track script activities, including successful and failed operations.

Example Output
--------------

-   **MISP Fetching IoCs**:

  

    `[*] Fetching IoCs for MISP event ID: 1234...
    [+] Found 10 IoCs for event ID 1234.
    [*] Fetching IoCs for MISP event ID: 5678...
    [+] Found 5 IoCs for event ID 5678.
    [+] Successfully updated 'MISP_ip-src' with IoC: 192.168.1.1`

-   **QRadar Update**:

 

    `[+] Successfully updated 'MISP_ip-src' with IoC: 192.168.1.1
    [-] Error updating QRadar reference set 'MISP_ip-src': HTTP 500 - Internal Server Error`

-   **CSV Save**:

 
    `[+] IoCs saved to misp_values_20250101_120000.csv`

Error Handling
--------------

-   If the script fails to fetch IoCs from MISP or update QRadar, error messages will be logged and printed to the terminal.
-   If no IoCs are found for the provided filters, the script will inform the user.




Functionality
-------------

### Scheduling Task on Windows

On Windows, the script uses `schtasks` to schedule the task.

#### Command to schedule the task:

`schtasks /create /tn "MISPionage Task" /tr "python <path_to_script>" /sc once /st <HH:MM> /f`

-   **/create**: Create a new scheduled task.
-   **/tn "MISPionage Task"**: Task name.
-   **/tr "python <path_to_script>"**: The command to run (Python script).
-   **/sc once**: Run only once at the specified time.
-   **/st HH:MM**: Start time in 24-hour format.
-   **/f**: Force the creation without confirmation.

**Example:**


`schtasks /create /tn "MISPionage Task" /tr "python C:\scripts\MISPionage Task" /sc once /st 18:00 /f`

#### Deleting the Scheduled Task:

To delete the task:


`schtasks /delete /tn "MISPionage Task" /f`

### Scheduling Task on Linux

On Linux, the script will automatically add a cron job at the specified time.

#### Cron Job:



`echo "<minute> <hour> * * * python <path_to_script>" | crontab -`

Example for 6:00 PM (18:00):



`echo "00 18 * * * python /home/user/MISPionage Task" | crontab -`

#### Deleting the Cron Job:

You can remove a specific cron job by editing the crontab or using the following command:



`crontab -l | grep -v 'MISPionage Task' | crontab -`

This will remove the line related to the MISPionage task from the crontab.

* * * * *

Troubleshooting
---------------

### Windows

-   Ensure you have Administrator privileges to create and manage scheduled tasks.
-   Use `schtasks /query` to check if the task was successfully created:

   

    `schtasks /query /tn "MISPionage Task"`

### Linux

-   Ensure that Python is installed and available in your system's PATH.
-   Check cron logs if the job doesn't run as expected.

* * * * *

### Disabling SSL Warnings

**MISPionage** disables SSL warnings by using the `urllib3` library. This is particularly useful when working with servers that use self-signed certificates or have SSL verification issues, preventing unnecessary warnings from cluttering the output.


`urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)`

#### Why It's Disabled:

-   **Prevent Clutter**: Disabling SSL warnings ensures a clean terminal output, which is especially helpful during automated or scheduled runs of the script.
-   **Self-Signed Certificates**: Many internal or test servers use self-signed certificates. By disabling the warning, the script can run without interruptions even on servers where SSL verification is not required.
-   **Automation**: When the script is scheduled to run periodically, removing these warnings ensures that the execution proceeds without errors or excessive log entries.

#### Considerations:

-   **Security Risk**: Disabling SSL warnings does not validate the server's authenticity, leaving the connection vulnerable to potential man-in-the-middle attacks. It's critical to ensure that you trust the server you're connecting to when disabling these warnings.
-   **Use in Trusted Environments**: This approach is best suited for controlled, trusted environments (e.g., internal networks), where the risk of SSL attacks is minimal. In production or public-facing environments, it's recommended to use valid SSL certificates to ensure secure connections.

Disabling these warnings streamlines the script's operation, but it's important to balance convenience with security, especially when dealing with sensitive or external systems.

License
-------

This script is open-source and licensed under the MIT License. You are free to use, modify, and distribute it under the terms of the MIT License.

* * * * *


Contact
-------

For questions or support, feel free to open an issue on the GitHub repository or contact me at chrisvasileia93@gmail.com.
