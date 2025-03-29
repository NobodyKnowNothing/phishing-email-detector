import requests
import hashlib
import os # Added for file path operations
from typing import Tuple, Optional

# (Keep the check_url_content_hash function as defined before)
def check_url_content_hash(url: str, previous_hash: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    Fetches content from a URL, calculates its SHA-256 hash, and compares
    it with a previously saved hash.

    Args:
        url: The URL of the resource to check.
        previous_hash: The previously calculated SHA-256 hash (hex digest string)
                       to compare against. Use None or an empty string if no
                       previous hash exists (e.g., first run).

    Returns:
        A tuple (is_match, current_hash):
        - is_match (bool): True if the current hash matches the previous_hash,
                           False otherwise. Returns False if an error occurs
                           during fetch or hashing.
        - current_hash (Optional[str]): The calculated SHA-256 hash of the
                                        current content from the URL (hex digest).
                                        Returns None if an error occurred.

    Raises:
        requests.exceptions.RequestException: Can be raised if there's a fundamental
                                              issue with the request (network, DNS etc.).
                                              It's often better to catch this in the
                                              calling code for specific handling.
    """
    current_hash = None
    is_match = False

    try:
        # Set a reasonable timeout (e.g., 15 seconds)
        response = requests.get(url, timeout=15)

        # Raise an exception for bad status codes (4xx client error, 5xx server error)
        response.raise_for_status()

        # Get content as bytes - important for consistent hashing across systems/encodings
        content_bytes = response.content

        # Calculate SHA-256 hash
        hasher = hashlib.sha256()
        hasher.update(content_bytes)
        current_hash = hasher.hexdigest()

        # Perform the comparison
        # Check if previous_hash exists and is non-empty before comparing
        if previous_hash and current_hash == previous_hash:
            is_match = True
        else:
            # Handles cases where previous_hash is None, empty, or simply doesn't match
            is_match = False

        return is_match, current_hash

    except requests.exceptions.Timeout:
        print(f"Error: Request timed out for URL: {url}")
        return False, None # Indicate failure: no match, no current hash
    except requests.exceptions.HTTPError as e:
        print(f"Error: HTTP Error {e.response.status_code} for URL: {url}")
        return False, None
    except requests.exceptions.RequestException as e:
        # Catch other potential requests errors (ConnectionError, TooManyRedirects, etc.)
        print(f"Error: Failed to fetch URL {url}: {e}")
        # Optionally re-raise if the caller should handle it: raise
        return False, None
    except Exception as e:
        # Catch any other unexpected errors during hashing etc.
        print(f"Error: An unexpected error occurred during hash check for {url}: {e}")
        return False, None

# --- New Function for Monitoring Logic ---
def monitor_url_change(url: str, hash_file_path: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Monitors a URL for content changes based on its SHA-256 hash.
    Loads the previous hash from a file, checks the URL, compares hashes,
    and saves the new hash if a change is detected or if it's the first run.

    Args:
        url: The URL of the resource to monitor.
        hash_file_path: The path to the file where the hash is stored.

    Returns:
        A tuple (content_changed, current_hash, previous_hash):
        - content_changed (bool): True if the content hash changed compared to the
                                  stored hash (or if no previous hash existed).
                                  False if the hash matches or if an error occurred
                                  during the check.
        - current_hash (Optional[str]): The hash of the content fetched during
                                        this check. None if an error occurred.
        - previous_hash (Optional[str]): The hash loaded from the file. None if
                                         the file didn't exist or was empty.
    """
    previous_saved_hash = None
    content_changed = False
    latest_hash = None

    # --- Load Previous Hash ---
    try:
        if os.path.exists(hash_file_path):
            with open(hash_file_path, 'r') as f:
                previous_saved_hash = f.read().strip()
                if not previous_saved_hash: # Handle empty file case
                    previous_saved_hash = None
                    print(f"Info: Hash file '{hash_file_path}' was empty. Treating as first check.")
                else:
                     print(f"Loaded previous hash from '{hash_file_path}': {previous_saved_hash}")
        else:
            print(f"Info: Hash file '{hash_file_path}' not found. Assuming first check.")
    except Exception as e:
        print(f"Warning: Error reading hash file '{hash_file_path}': {e}. Proceeding as first check.")
        previous_saved_hash = None # Ensure it's None if read fails

    # --- Perform the Check ---
    print(f"\nChecking URL: {url}...")
    try:
        match_status, latest_hash = check_url_content_hash(url, previous_saved_hash)

        if latest_hash is not None: # Check succeeded
            print(f"Previous Hash: {previous_saved_hash if previous_saved_hash else 'N/A'}")
            print(f"Current Hash:  {latest_hash}")

            if not match_status:
                # Content changed OR it's the first run (previous_saved_hash was None/empty)
                content_changed = True
                print("Result: Content HAS CHANGED (or this is the first run/hash file was empty/unreadable).")
                # Save the new hash
                try:
                    with open(hash_file_path, 'w') as f:
                        f.write(latest_hash)
                    print(f"Saved new hash to '{hash_file_path}'.")
                except Exception as e:
                    print(f"Error: Failed to save new hash to '{hash_file_path}': {e}")
                    # Note: content_changed remains True, but the state for the *next* run is now uncertain.
            else:
                # Hashes match
                content_changed = False
                print("Result: Content HAS NOT CHANGED.")

        else:
            # check_url_content_hash failed and already printed an error
            print("Result: Could not determine content status due to an error during fetch/hash.")
            content_changed = False # Cannot confirm change if check failed

    except requests.exceptions.RequestException as e:
         # Catching errors explicitly raised by check_url_content_hash or requests itself
         print(f"A critical network or request error occurred: {e}")
         print("Result: Could not perform check.")
         content_changed = False # Cannot confirm change if check failed
         latest_hash = None # Ensure current_hash is None on critical failure

    return content_changed, latest_hash, previous_saved_hash

# --- Example Usage of the New Function ---

if __name__ == "__main__":
    # Configuration
    url_to_watch = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-domains-ACTIVE.txt"
    hash_storage_file = "readme_last_hash.txt" # Use a more specific name

    # Execute the monitoring process
    changed, current, previous = monitor_url_change(url_to_watch, hash_storage_file)

    print("\n--- Monitoring Summary ---")
    if current:
        if changed:
            print(f"Action Recommended: Content at {url_to_watch} has changed.")
            print(f"  Previous Hash: {previous if previous else 'None (first run or file error)'}")
            print(f"  New Hash:      {current}")
        else:
            print(f"No Change Detected: Content at {url_to_watch} remains the same.")
            print(f"  Current Hash: {current}")
    else:
        print(f"Check Failed: Could not verify content at {url_to_watch}.")
        print(f"  Previous Hash from file (if loaded): {previous if previous else 'N/A'}")

    # Example of how you might use the boolean 'changed' flag
    if changed:
        # Trigger some notification or action here
        print("\nTriggering notification (simulation)...")
        # send_email("admin@example.com", f"Content changed: {url_to_watch}", f"New hash: {current}")
        pass