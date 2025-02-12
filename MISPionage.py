import requests
import csv
import json
import urllib3
import os
import logging
import argparse
import platform
import time
import subprocess
import sys
from datetime import datetime
from collections import defaultdict
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tqdm import tqdm
from colorama import Fore, Style, init
import pyfiglet
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Initialize colorama for colored output
init(autoreset=True)

# Print ASCII art for MISPionage in yellow
ascii_art = pyfiglet.figlet_format("-->MISPionage", font="slant")
print(Fore.YELLOW + ascii_art)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration (read from environment variables)
MISP_URL = os.getenv("MISP_URL")
MISP_API_KEY = os.getenv("MISP_API_KEY")
QRADAR_API = os.getenv("QRADAR_API")  
QRADAR_API_CREATE = os.getenv("QRADAR_API_CREATE", QRADAR_API)
QRADAR_API_KEY= os.getenv("QRADAR_API_KEY")

# Output and log files
OUTPUT_CSV_FILE = f"misp_values_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
LOG_FILE = "MISPionage_log.log"

# Setup logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Define headers for MISP and QRadar
MISP_HEADERS = {
    "Authorization": MISP_API_KEY,
    "Content-Type": "application/json",
    "Accept": "application/json"
}

QRADAR_HEADERS = {
    "SEC": QRADAR_API_KEY,
    "Content-Type": "application/json",
    "Accept": "application/json"
}

# --- Helper Functions ---

def requests_retry_session(retries=3, backoff_factor=1, status_forcelist=(500, 502, 503, 504)):
    """ Create a requests session that retries on certain HTTP status codes. """
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

def fetch_misp_iocs(event_id=None, attribute_type=None, limit=None, last_value=None):
    """
    Fetch IoCs from MISP based on either an event ID or an attribute type.
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
        if last_value:
            payload["last"] = last_value

    try:
        response = requests_retry_session().post(url, headers=MISP_HEADERS, json=payload, verify=False)
        response.raise_for_status()
        misp_data = response.json()
        logging.info("MISP response: %s", json.dumps(misp_data, indent=4))
        return misp_data
    except Exception as e:
        print(Fore.RED + f"Error fetching IoCs from MISP: {e}")
        logging.error(f"Error fetching IoCs from MISP (event_id={event_id}, attribute_type={attribute_type}): {e}")
        return None

def extract_iocs(misp_data):
    """
    Extract IoCs from MISP data, filtering on 'to_ids' == True.
    Works with both event-based and attribute-based responses.
    """
    if not misp_data:
        print(Fore.RED + "[!] No data received from MISP.")
        return []
    
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
    if "Attribute" in response_data:
        attributes.extend(response_data["Attribute"])
    else:
        for event in response_data:
            if isinstance(event, dict) and "Event" in event:
                event_attributes = event["Event"].get("Attribute", [])
                attributes.extend(event_attributes)

    iocs = []
    for attr in attributes:
        if attr.get("to_ids", False):
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
    Save the list of IoCs to a CSV file.
    """
    if not iocs:
        print(Fore.YELLOW + "[!] No IoCs to save.")
        logging.warning("No IoCs to save.")
        return

    fieldnames = ["Event ID", "Attribute Type", "Value", "Category", "Timestamp", "Event Info", "to_ids"]
    try:
        with open(filename, mode="w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for ioc in iocs:
                writer.writerow(ioc)
        print(Fore.GREEN + f"[+] IoCs saved to {filename}")
        logging.info(f"IoCs saved to {filename}")
    except Exception as e:
        print(Fore.RED + f"[!] Error saving to CSV: {e}")
        logging.error(f"Error saving IoCs to CSV: {e}")

def check_qradar_ref_set_exists(ref_set_name):
    """
    Check if a QRadar reference set exists.
    """
    url = f"{QRADAR_API}{ref_set_name}"
    try:
        response = requests_retry_session().get(url, headers=QRADAR_HEADERS, verify=False)
        if response.status_code == 200:
            print(Fore.GREEN + f"[+] QRadar reference set '{ref_set_name}' exists.")
            logging.info(f"QRadar reference set '{ref_set_name}' exists.")
            return True
        elif response.status_code == 404:
            print(Fore.RED + f"[!] QRadar reference set '{ref_set_name}' not found.")
            logging.warning(f"QRadar reference set '{ref_set_name}' not found.")
            return False
        else:
            print(Fore.YELLOW + f"[-] Error checking QRadar reference set '{ref_set_name}': HTTP {response.status_code} - {response.text}")
            logging.error(f"Error checking QRadar reference set '{ref_set_name}': HTTP {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(Fore.RED + f"[!] Exception when checking QRadar reference set '{ref_set_name}': {e}")
        logging.error(f"Exception when checking QRadar reference set '{ref_set_name}': {e}")
        return False

def create_qradar_ref_set(ref_set_name, element_type="ALNIC", time_to_live=None, timeout_type=None):
    """
    Create a QRadar reference set if it doesn't already exist.
    """
    url = f"{QRADAR_API_CREATE}"
    params = {"name": ref_set_name, "element_type": element_type}
    if time_to_live:
        params["time_to_live"] = time_to_live
    if timeout_type:
        params["timeout_type"] = timeout_type

    headers = {
        "SEC": QRADAR_API_KEY,
        "Accept": "application/json"
    }
    try:
        response = requests_retry_session().post(url, headers=headers, params=params, verify=False)
        if response.status_code in [200, 201]:
            print(Fore.GREEN + f"[+] Successfully created QRadar reference set '{ref_set_name}'.")
            logging.info(f"Successfully created QRadar reference set '{ref_set_name}'.")
            return True
        elif response.status_code == 409:
            print(Fore.YELLOW + f"[!] QRadar reference set '{ref_set_name}' already exists.")
            logging.warning(f"QRadar reference set '{ref_set_name}' already exists.")
            return True
        else:
            print(Fore.RED + f"[-] Error creating QRadar reference set '{ref_set_name}': HTTP {response.status_code} - {response.text}")
            logging.error(f"Error creating QRadar reference set '{ref_set_name}': HTTP {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(Fore.RED + f"[!] Exception when creating QRadar reference set '{ref_set_name}': {e}")
        logging.error(f"Exception when creating QRadar reference set '{ref_set_name}': {e}")
        return False

def update_qradar_ref_set(ref_set_name, ioc_value, element_type="ALNIC"):
    """
    Update a QRadar reference set with a single IoC value.
    """
    ref_set_name = ref_set_name.replace("|", "_")
    if not check_qradar_ref_set_exists(ref_set_name):
        if not create_qradar_ref_set(ref_set_name, element_type):
            print(Fore.RED + f"[!] Failed to create reference set '{ref_set_name}'. Skipping update.")
            return False

    url = f"{QRADAR_API}{ref_set_name}"
    params = {"value": ioc_value, "source": "MISP Integration"}
    try:
        response = requests_retry_session().post(url, headers=QRADAR_HEADERS, params=params, verify=False)
        response.raise_for_status()
        if response.status_code in [200, 201]:
            print(Fore.GREEN + f"[+] Successfully updated '{ref_set_name}' with IoC: {ioc_value}")
            logging.info(f"Successfully updated '{ref_set_name}' with IoC: {ioc_value}")
            return True
        else:
            print(Fore.RED + f"[-] Error updating QRadar reference set '{ref_set_name}': HTTP {response.status_code} - {response.text}")
            logging.error(f"Error updating QRadar reference set '{ref_set_name}': HTTP {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(Fore.RED + f"[!] Exception when updating QRadar: {e}")
        logging.error(f"Exception when updating QRadar: {e}")
        return False

def update_qradar_ref_set_batch(ref_set_name, ioc_values, namespace, domain_id, element_type="ALNIC", batch_size=50):
    """
    Update a QRadar reference set with a batch of IoC values using the bulk endpoint.
    Endpoint: POST /reference_data/sets/bulk_load/{namespace}/{name}/{domain_id}
    
    If the number of IoCs exceeds the batch_size, they will be split into batches.
    In case of a failure, the function falls back to one-by-one updates.
    """
    ref_set_name = ref_set_name.replace("|", "_")
    # Ensure the reference set exists
    if not check_qradar_ref_set_exists(ref_set_name):
        if not create_qradar_ref_set(ref_set_name, element_type):
            print(Fore.RED + f"[!] Failed to create reference set '{ref_set_name}'. Skipping batch update.")
            return False

    # Helper to split list into chunks
    def chunks(lst, n):
        for i in range(0, len(lst), n):
            yield lst[i:i + n]

    success = True
    for batch in chunks(ioc_values, batch_size):
        # Build the bulk update URL
        url = f"{QRADAR_API}bulk_load/{namespace}/{ref_set_name}/{domain_id}"
        # Payload is just the array of strings (IoC values)
        payload = batch
        try:
            response = requests_retry_session().post(url, headers=QRADAR_HEADERS, json=payload, verify=False)
            response.raise_for_status()
            if response.status_code in [200, 201]:
                print(Fore.GREEN + f"[+] Successfully batch updated '{ref_set_name}' with IoCs: {batch}")
                logging.info(f"Successfully batch updated '{ref_set_name}' with IoCs: {batch}")
            else:
                print(Fore.RED + f"[-] Error batch updating '{ref_set_name}': HTTP {response.status_code} - {response.text}")
                logging.error(f"Error batch updating '{ref_set_name}': HTTP {response.status_code} - {response.text}")
                raise Exception("Batch update failed")
        except Exception as e:
            print(Fore.RED + f"[!] Batch update failed for '{ref_set_name}' with batch {batch}: {e}")
            logging.error(f"Batch update failed for '{ref_set_name}' with batch {batch}: {e}")
            print(Fore.YELLOW + "Falling back to individual updates for this batch...")
            # Fallback: update one by one
            for value in batch:
                update_qradar_ref_set(ref_set_name, value, element_type)
            success = False
    return success

def process_and_save_iocs(misp_event_ids=None, attribute_type=None, limit=None, last_value=None,
                           namespace="SHARED", domain_id="SHARED", batch_size=50):
    """
    Process IoCs: fetch from MISP (by event IDs or attribute type), update QRadar in batches,
    and save the resulting IoCs to a CSV file.
    """
    all_iocs = []
    print("\n[INFO] Starting IoC processing...\n")
    
    # Process by event IDs
    if misp_event_ids:
        for misp_event_id in tqdm(misp_event_ids, desc="Processing MISP Events", unit="event"):
            tqdm.write(Fore.CYAN + f"[*] Fetching IoCs for MISP event ID: {misp_event_id}...")
            misp_data = fetch_misp_iocs(event_id=misp_event_id)
            iocs = extract_iocs(misp_data)
            if not iocs:
                tqdm.write(Fore.YELLOW + f"[!] No IoCs found for event ID {misp_event_id}.")
            else:
                tqdm.write(Fore.GREEN + f"[+] Found {len(iocs)} IoCs for event ID {misp_event_id}.")
                all_iocs.extend(iocs)
    
    # Process by attribute type
    if attribute_type:
        for attr_type in attribute_type:
            tqdm.write(Fore.CYAN + f"[*] Fetching IoCs for attribute type: {attr_type}...")
            misp_data = fetch_misp_iocs(attribute_type=attr_type, limit=limit, last_value=last_value)
            iocs = extract_iocs(misp_data)
            if not iocs:
                tqdm.write(Fore.YELLOW + f"[!] No IoCs found for attribute type: {attr_type}.")
            else:
                tqdm.write(Fore.GREEN + f"[+] Found {len(iocs)} IoCs for attribute type: {attr_type}.")
                all_iocs.extend(iocs)
    
    # Group IoCs by reference set name (e.g. "MISP_domain", "MISP_ip-src", etc.)
    grouped_iocs = defaultdict(list)
    for ioc in all_iocs:
        ref_set_name = f"MISP_{ioc['Attribute Type']}".replace("|", "_")
        grouped_iocs[ref_set_name].append(ioc["Value"])
    
    # Batch update each reference set
    for ref_set_name, ioc_values in grouped_iocs.items():
        update_qradar_ref_set_batch(ref_set_name, ioc_values, namespace, domain_id, element_type="ALNIC", batch_size=batch_size)
    
    # Save all IoCs to CSV
    if all_iocs:
        tqdm.write(Fore.GREEN + f"[+] Saving {len(all_iocs)} IoCs to CSV...")
        save_to_csv(all_iocs)
    else:
        tqdm.write(Fore.RED + "[!] No IoCs found.")

# --- Scheduling Functions (same as version #1) ---

def schedule_task(script_name, time_str, os_type="Windows"):
    script_path = os.path.abspath(script_name)
    if os_type == "Windows":
        command = f'schtasks /create /tn "MISPionage Task" /tr "{script_path}" /sc daily /st {time_str} /f'
        try:
            subprocess.run(command, shell=True, check=True)
            print(f"[+] Scheduled task created for script: {script_path}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to create scheduled task: {e}")
    elif os_type == "Linux":
        cron_time = convert_to_cron_format(time_str)
        if cron_time:
            cron_job = f"{cron_time} python3 {script_path}"
            try:
                subprocess.run(f'(crontab -l ; echo "{cron_job}") | crontab -', shell=True, check=True)
                print(f"[+] Scheduled task created for script: {script_path} (using cron)")
            except subprocess.CalledProcessError as e:
                print(f"[!] Failed to create scheduled task: {e}")
        else:
            print("[!] Invalid time format for Linux. Ensure it’s in 24-hour format (e.g., 18:00)")
    else:
        print("[!] Unsupported OS type. Only Windows and Linux are supported.")

def convert_to_cron_format(time_str):
    try:
        hour, minute = map(int, time_str.split(":"))
        return f"{minute} {hour} * * *"
    except ValueError:
        print("[!] Invalid time format. Expected HH:MM")
        return None

def check_scheduled_task(task_name, os_type="Windows"):
    if os_type == "Windows":
        try:
            result = subprocess.run(f'schtasks /query /tn "{task_name}"', shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[+] The task '{task_name}' is scheduled on Windows.")
                return True
            else:
                print(f"[-] The task '{task_name}' does not exist on Windows.")
                return False
        except subprocess.CalledProcessError as e:
            print(f"[!] Error checking task: {e}")
            return False
    elif os_type == "Linux":
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

def ask_user_for_scheduling():
    schedule_choice = input("Do you want to schedule this task? (yes/no): ").strip().lower()
    if schedule_choice == "yes":
        os_type = input("Please specify your OS (Windows/Linux): ").strip().capitalize()
        time_str = input("At what time would you like to run the task? (e.g., 08:00 or 18:00): ").strip()
        schedule_task(__file__, time_str, os_type)
        task_name = "MISPionage Task"
        check_scheduled_task(task_name, os_type)
    else:
        print("[!] Task scheduling skipped.")

# --- Main Execution ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""
    MISPionage - A tool for processing MISP IoCs and updating QRadar reference sets.
    ---------------------------------------------------------------------------
    This script performs the following tasks:
      - Fetches IoCs (Indicators of Compromise) from a MISP instance based on either
        event IDs or attribute types.
      - Groups IoCs by reference set name (e.g., MISP_domain, MISP_ip-src).
      - Updates QRadar reference sets in batches using the QRadar Bulk Update API.
      - Falls back to updating individual IoCs if a batch update fails.
      - Saves all fetched IoCs to a CSV file.
      - Optionally, schedules the task for periodic execution (Windows or Linux).

    Usage Examples:
      1. Fetch IoCs for a specific attribute type:
           python script.py --attribute-type domain --limit 10

      2. Fetch IoCs by event IDs and update QRadar reference sets:
           python script.py --event-ids 6961 1234

      3. Specify QRadar settings (namespace, domain ID, and batch size):
           python script.py --attribute-type ip-src --namespace TENANT --domain-id 100 --batch-size 50

      4. Schedule the task for periodic execution:
           python script.py --schedule
    """,
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "--event-ids",
        metavar="event_id",
        type=int,
        nargs="*",
        help="One or more MISP event IDs to fetch IoCs from. Example: 6961 1234 5678"
    )

    parser.add_argument(
        "--attribute-type",
        metavar="attribute_type",
        type=str,
        nargs="*",
        help="One or more attribute types to filter IoCs from MISP. Example: ip-src domain md5"
    )

    parser.add_argument(
        "--limit",
        metavar="limit",
        type=int,
        default=None,
        help="Limit the number of IoCs returned (only applicable for attribute type searches)."
    )

    parser.add_argument(
        "--schedule",
        action="store_true",
        help="Schedule the task for periodic execution (you will be prompted for scheduling details)."
    )

    parser.add_argument(
        "--namespace",
        metavar="namespace",
        type=str,
        choices=["SHARED", "TENANT"],
        default="SHARED",
        help="Namespace for QRadar reference set bulk update. Options: SHARED (default) or TENANT."
    )

    parser.add_argument(
        "--domain-id",
        metavar="domain_id",
        type=str,
        default="SHARED",
        help="Domain ID for QRadar reference set bulk update. Default is 'SHARED'.\nFor admin users, use SHARED, or provide a numeric domain ID."
    )

    parser.add_argument(
        "--batch-size",
        metavar="batch_size",
        type=int,
        default=50,
        help="Maximum number of IoCs per batch update. Default is 50."
    )

    args = parser.parse_args()

    if args.schedule:
        ask_user_for_scheduling()
    else:
        if not args.event_ids and not args.attribute_type:
            print(Fore.RED + "[!] Please provide either --event-ids or --attribute-type.")
            sys.exit(1)
        last_value = None
        if not args.event_ids:
            last_value = input("Please enter the 'last' value (e.g., 1d, 2h, 30m): ").strip()
        process_and_save_iocs(
            misp_event_ids=args.event_ids,
            attribute_type=args.attribute_type,
            limit=args.limit,
            last_value=last_value,
            namespace=args.namespace,
            domain_id=args.domain_id,
            batch_size=args.batch_size
        )
