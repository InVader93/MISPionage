import requests
import csv
import json
import urllib3
import os
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from datetime import datetime
import urllib.parse
import argparse
import platform
import time
import subprocess
import sys
from tqdm import tqdm  # To display progress bar
from colorama import Fore, Style, init # For colored output
import pyfiglet


# Initialize colorama
init(autoreset=True)

# Print ASCII art for MISPionage in yellow
ascii_art = pyfiglet.figlet_format("-->MISPionage", font="slant")
print(Fore.YELLOW + ascii_art)



# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
MISP_URL = "<MISP_URL>"
MISP_API_KEY = "<MISP_API_KEY>"
QRADAR_API = "https://<YOUR_QRADAR_IP_OR_DOMAIN>/api/reference_data/sets/"  # QRadar API endpoint
QRADAR_API_CREATE = "https://<YOUR_QRADAR_IP_OR_DOMAIN>/api/reference_data/sets"  # QRadar API endpoint (Used only for Reference Set Creation)
QRADAR_API_KEY = "<QRADAR_API_KEY>"  # QRadar token
OUTPUT_CSV_FILE = f"misp_values_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
LOG_FILE = "MISPionage_log.log"

# Setup logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

MISP_HEADERS = {
    "Authorization": MISP_API_KEY,
    "Content-Type": "application/json",
    "Accept": "application/json"
}

QRADAR_HEADERS = {
    "SEC": QRADAR_API_KEY,  # Correct header for QRadar token
    "Content-Type": "application/json",
    "Accept": "application/json"
}

# Retry logic for robust requests
def requests_retry_session(retries=3, backoff_factor=1, status_forcelist=(500, 502, 503, 504)):
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

def fetch_misp_iocs(event_id=None, attribute_type=None, limit=None):
    """
    Fetch IoCs from MISP based on either event ID or attribute type (or both).
    """
    if event_id:
        url = f"{MISP_URL}/events/restSearch/json"
        payload = {"eventid": event_id, "returnFormat": "json"}
    else:
        url = f"{MISP_URL}/attributes/restSearch/json"
        payload = {"returnFormat": "json", "enforceWarninglist": False}
        if attribute_type:
            payload["type"] = attribute_type
        if limit:
            payload["limit"] = limit

    try:
        response = requests_retry_session().post(url, headers=MISP_HEADERS, json=payload, verify=False)
        response.raise_for_status()
        
        misp_data = response.json()
        
        #DEBUG: Print the raw response from MISP API
        #print(Fore.YELLOW + f"[DEBUG] MISP API response: {misp_data}")  # <-- Add this line to enable debug output
        
        return misp_data
    except Exception as e:
        print(Fore.RED + f"Error fetching IoCs from MISP: {e}")
        logging.error(f"Error fetching IoCs from MISP for event_id={event_id}, attribute_type={attribute_type}, limit={limit}: {e}")
        return None


def extract_iocs(misp_data):
    """
    Extract IoCs from MISP data. Filters by `to_ids=True`.
    Handles both event-based and attribute-based responses.
    """
    if not misp_data:
        print(Fore.RED + "[!] No data received from MISP.")
        return []

    # Ensure misp_data is a dictionary
    if isinstance(misp_data, str):
        try:
            misp_data = json.loads(misp_data)
        except json.JSONDecodeError:
            print(Fore.RED + "[!] Received invalid JSON from MISP.")
            return []

    if "response" not in misp_data:
        print(Fore.RED + "[!] Invalid MISP data format. Missing 'response' key.")
        return []

    attributes = []
    response_data = misp_data["response"]
    
    # Handle attribute-based search response
    if "Attribute" in response_data:
        attributes.extend(response_data["Attribute"])
    # Handle event-based search response
    else:
        for event in response_data:
            if isinstance(event, dict) and "Event" in event:
                event_attributes = event["Event"].get("Attribute", [])
                attributes.extend(event_attributes)

    iocs = []
    for attr in attributes:
        if attr.get("to_ids", False):
            # Get event info from either the attribute's Event field or parent event
            event_info = ""
            if "Event" in attr:
                event_info = attr["Event"].get("info", "")
            
            iocs.append({
                "Event ID": attr.get("event_id", ""),
                "Attribute Type": attr.get("type", ""),
                "Value": attr.get("value", ""),
                "Category": attr.get("category", ""),
                "Timestamp": attr.get("timestamp", ""),
                "Event Info": event_info,
                "to_ids": attr.get("to_ids", False)
            })

    return iocs


def save_to_csv(iocs, filename=OUTPUT_CSV_FILE):
    """
    Save IoCs to a CSV file.
    """
    if not iocs:
        print(Fore.YELLOW + "[!] No IoCs to save.")
        logging.warning("No IoCs to save.")
        return

    fieldnames = ["Event ID", "Attribute Type", "Value", "Category", "Timestamp", "Event Info", "to_ids"]
    with open(filename, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for ioc in iocs:
            writer.writerow(ioc)

    print(Fore.GREEN + f"[+] IoCs saved to {filename}")
    logging.info(f"[+] IoCs saved to {filename}")

def check_qradar_ref_set_exists(ref_set_name):
    """
    Check if a QRadar reference set with the given name exists.
    """
    url = f"{QRADAR_API}{ref_set_name}"

    try:
        response = requests_retry_session().get(url, headers=QRADAR_HEADERS, verify=False)

        if response.status_code == 200:
            print(Fore.GREEN + f"[+] QRadar reference set '{ref_set_name}' exists.")
            logging.info(f"[+] QRadar reference set '{ref_set_name}' exists.")
            return True
        elif response.status_code == 404:
            print(Fore.RED + f"[!] QRadar reference set '{ref_set_name}' not found.")
            logging.warning(f"[!] QRadar reference set '{ref_set_name}' not found.")
            return False
        else:
            print(Fore.YELLOW + f"[-] Error checking QRadar reference set '{ref_set_name}': HTTP {response.status_code} - {response.text}")
            logging.error(f"[-] Error checking QRadar reference set '{ref_set_name}': HTTP {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(Fore.RED + f"[!] Exception when checking QRadar reference set '{ref_set_name}': {e}")
        logging.error(f"Exception when checking QRadar reference set '{ref_set_name}': {e}")
        return False

def create_qradar_ref_set(ref_set_name, element_type="ALNIC", time_to_live=None, timeout_type=None):
    """
    Create a QRadar reference set if it doesn't exist.
    According to QRadar API documentation:
    POST /api/reference_data/sets
    Required parameters: name, element_type
    """
    url = f"{QRADAR_API_CREATE}"  # Base URL without reference set name

    # Required parameters according to API doc
    params = {
        "name": ref_set_name,
        "element_type": element_type
    }
    
    if time_to_live:
        params["time_to_live"] = time_to_live
    if timeout_type:
        params["timeout_type"] = timeout_type

    headers = {
        'SEC': QRADAR_API_KEY,
        'Accept': 'application/json'
    }

    try:
        response = requests_retry_session().post(
            url, 
            headers=headers, 
            params=params,  # Using URL parameters as per API doc
            verify=False
        )
        
        if response.status_code in [200, 201]:
            print(Fore.GREEN + f"[+] Successfully created QRadar reference set '{ref_set_name}'.")
            logging.info(f"[+] Successfully created QRadar reference set '{ref_set_name}'.")
            return True
        elif response.status_code == 409:
            print(Fore.YELLOW + f"[!] QRadar reference set '{ref_set_name}' already exists.")
            logging.warning(f"[!] QRadar reference set '{ref_set_name}' already exists.")
            return True
        else:
            print(Fore.RED + f"[-] Error creating QRadar reference set '{ref_set_name}': HTTP {response.status_code} - {response.text}")
            logging.error(f"[-] Error creating QRadar reference set '{ref_set_name}': HTTP {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(Fore.RED + f"[!] Exception when creating QRadar reference set '{ref_set_name}': {e}")
        logging.error(f"Exception when creating QRadar reference set '{ref_set_name}': {e}")
        return False


def update_qradar_ref_set(ref_set_name, ioc_value, element_type="ALNIC"):
    """
    Update QRadar reference set with the specified IoC.
    """
    ref_set_name = ref_set_name.replace("|", "_")

    # First, try to create the reference set if it doesn't exist
    if not check_qradar_ref_set_exists(ref_set_name):
        if not create_qradar_ref_set(ref_set_name, element_type):
            print(Fore.RED + f"[!] Failed to create reference set '{ref_set_name}'. Skipping update.")
            return False

    # Now update the reference set
    url = f"{QRADAR_API}{ref_set_name}"
    
    # Add the value as a URL parameter
    params = {
        "value": ioc_value,
        "source": "MISP Integration"
    }
    
    headers = {
        'SEC': QRADAR_API_KEY,
        'Accept': 'application/json'
    }

    try:
        response = requests_retry_session().post(
            url, 
            headers=headers, 
            params=params,
            verify=False
        )

        if response.status_code in [200, 201]:
            print(Fore.GREEN + f"[+] Successfully updated '{ref_set_name}' with IoC: {ioc_value}")
            logging.info(f"[+] Successfully updated '{ref_set_name}' with IoC: {ioc_value}")
            return True
        else:
            print(Fore.RED + f"[-] Error updating QRadar reference set '{ref_set_name}': HTTP {response.status_code} - {response.text}")
            logging.error(f"[-] Error updating QRadar reference set '{ref_set_name}': HTTP {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(Fore.RED + f"[!] Exception when updating QRadar: {e}")
        logging.error(f"Exception when updating QRadar: {e}")
        return False

def process_and_save_iocs(misp_event_ids=None, attribute_type=None, limit=None):
    all_iocs = []

    print("\n[INFO] Starting IoC processing...\n")
    
    # Process for MISP event IDs
    if misp_event_ids:
        with tqdm(total=len(misp_event_ids), desc="Processing MISP Events", unit="event") as pbar:
            for i, misp_event_id in enumerate(misp_event_ids):
                tqdm.write(Fore.CYAN + f"[*] Fetching IoCs for MISP event ID: {misp_event_id}...")
                misp_data = fetch_misp_iocs(event_id=misp_event_id)
                iocs = extract_iocs(misp_data)

                if not iocs:
                    tqdm.write(Fore.YELLOW + f"[!] No IoCs found for event ID {misp_event_id}.")
                else:
                    tqdm.write(Fore.GREEN + f"[+] Found {len(iocs)} IoCs for event ID {misp_event_id}.")
                    all_iocs.extend(iocs)
                    for ioc in iocs:
                        update_qradar_ref_set(f"MISP_{ioc['Attribute Type']}", ioc["Value"], "ALNIC")

                pbar.update(1)

    # Process for multiple attribute types
    if attribute_type:
        for attr_type in attribute_type:
            tqdm.write(Fore.CYAN + f"[*] Fetching IoCs for attribute type: {attr_type}...")
            misp_data = fetch_misp_iocs(attribute_type=attr_type, limit=limit)
            iocs = extract_iocs(misp_data)

            if not iocs:
                tqdm.write(Fore.YELLOW + f"[!] No IoCs found for attribute type: {attr_type}.")
            else:
                tqdm.write(Fore.GREEN + f"[+] Found {len(iocs)} IoCs for attribute type: {attr_type}.")
                all_iocs.extend(iocs)
                for ioc in iocs:
                    update_qradar_ref_set(f"MISP_{ioc['Attribute Type']}", ioc["Value"], "ALNIC")

    # Save IoCs to CSV if any were found
    if all_iocs:
        tqdm.write(Fore.GREEN + f"[+] Saving {len(all_iocs)} IoCs to CSV...")
        save_to_csv(all_iocs)
    else:
        tqdm.write(Fore.RED + "[!] No IoCs found.")


def check_scheduled_task(task_name, os_type="Windows"):
    """ Check if a scheduled task exists (Windows or Linux) """
    
    if os_type == "Windows":
        # Check if the task exists using schtasks query command
        try:
            result = subprocess.run(f'schtasks /query /tn "{task_name}"', shell=True, capture_output=True, text=True)
            if result.returncode == 0:  # Return code 0 means task found
                print(f"[+] The task '{task_name}' is scheduled on Windows.")
                return True
            else:
                print(f"[-] The task '{task_name}' does not exist on Windows.")
                return False
        except subprocess.CalledProcessError as e:
            print(f"[!] Error checking task: {e}")
            return False
    
    elif os_type == "Linux":
        # Check if the task exists in cron using crontab -l
        try:
            result = subprocess.run("crontab -l", shell=True, capture_output=True, text=True)
            if task_name in result.stdout:
                print(f"[+] The task '{task_name}' is scheduled on Linux.")
                return True
            else:
                print(f"[-] The task '{task_name}' does not exist on Linux.")
                return False
        except subprocess.CalledProcessError as e:
            print(f"[!] Error checking task: {e}")
            return False
    else:
        print("[!] Unsupported OS type. Only Windows and Linux are supported.")
        return False



def schedule_task(script_name, time_str, os_type="Windows"):
    script_path = os.path.abspath(script_name)

    if os_type == "Windows":
        # Windows task scheduling (using schtasks)
        command = f'schtasks /create /tn "MISPionage Task" /tr "{script_path}" /sc daily /st {time_str} /f'
        try:
            subprocess.run(command, shell=True, check=True)
            print(f"[+] Scheduled task created for script: {script_path}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to create scheduled task: {e}")

    elif os_type == "Linux":
        # Linux task scheduling (using cron)
        cron_time = convert_to_cron_format(time_str)
        if cron_time:
            cron_job = f"{cron_time} python3 {script_path}"
            try:
                # Add to crontab
                subprocess.run(f'(crontab -l ; echo "{cron_job}") | crontab -', shell=True, check=True)
                print(f"[+] Scheduled task created for script: {script_path} (using cron)")
            except subprocess.CalledProcessError as e:
                print(f"[!] Failed to create scheduled task: {e}")
        else:
            print("[!] Invalid time format for Linux. Ensure it’s in 24-hour format (e.g., 18:00)")

    else:
        print("[!] Unsupported OS type. Only Windows and Linux are supported.")

def convert_to_cron_format(time_str):
    """ Convert time format (HH:MM) to cron format (minute hour) """
    try:
        hour, minute = map(int, time_str.split(":"))
        return f"{minute} {hour} * * *"
    except ValueError:
        print("[!] Invalid time format. Expected HH:MM")
        return None

def ask_user_for_scheduling():
    """ Prompt user for scheduling options and schedule the task """

    schedule_choice = input("Do you want to schedule this task? (yes/no): ").strip().lower()

    if schedule_choice == "yes":
        os_type = input("Please specify your OS (Windows/Linux): ").strip().capitalize()
        time_str = input("At what time would you like to run the task? (e.g., 08:00 PM or 18:00): ").strip()

        # Schedule the task based on user input
        schedule_task(__file__, time_str, os_type)

        # Check if the task was created
        task_name = "MISPionage Task"
        check_scheduled_task(task_name, os_type)
    else:
        print("[!] Task scheduling skipped.")

if __name__ == "__main__":
    ask_user_for_scheduling()

    # Argument parser to pass event IDs or attribute type
    parser = argparse.ArgumentParser(description="Process MISP IoCs and update QRadar reference sets.")
    parser.add_argument(
        "--event-ids",
        metavar="event_id",
        type=int,
        nargs="*",
        help="Event ID(s) to filter by, e.g., 6961 or multiple IDs: 6961 1234 5678"
    )
    parser.add_argument(
        "--attribute-type",
        metavar="attribute_type",
        type=str,
        nargs="*",
        help="Attribute type to filter by, e.g., ip-src or multiple types domain md5"
    )
    parser.add_argument(
        "--limit",
        metavar="limit",
        type=int,
        default=None,
        help="Limit the number of IoCs returned (only applicable for attribute type searches)."
    )

    args = parser.parse_args()

    # Ensure at least one filter option is provided
    if not args.event_ids and not args.attribute_type:
        print(Fore.RED + "[!] Please provide either --event-ids or --attribute-type.")
        exit(1)

    # Process IoCs for event IDs or attribute type
    process_and_save_iocs(misp_event_ids=args.event_ids, attribute_type=args.attribute_type, limit=args.limit)
