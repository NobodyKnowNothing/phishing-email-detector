import requests
import hashlib
import os
from typing import Tuple, Optional, Union
import urllib.parse
import re

def url_to_filename(url):
    # Decode URL-encoded characters
    decoded = urllib.parse.unquote(url)
    # Remove protocol and fragments
    cleaned = re.sub(r"^https?://(www\.)?", "", decoded.split('?')[0].split('#')[0])
    # Replace invalid characters with underscores
    cleaned = re.sub(r"[^\w\-\.]", "_", cleaned)
    # Collapse underscores and trim
    cleaned = re.sub(r"_+", "_", cleaned).strip("_.")
    # Truncate to 255 characters
    return cleaned[:255]

def check_url_content_hash(url: str, previous_hash: Optional[str]) -> Tuple[bool, Optional[str], Optional[bytes]]:
    """
    Fetches content from a URL, calculates its SHA-256 hash, and compares it with a previously saved hash.

    Args:
        url: The URL of the resource to check.
        previous_hash: The previously calculated SHA-256 hash (hex digest string) to compare against.

    Returns:
        A tuple (is_match, current_hash, content_bytes):
        - is_match (bool): True if the current hash matches the previous_hash, False otherwise.
        - current_hash (Optional[str]): The calculated SHA-256 hash of the content.
        - content_bytes (Optional[bytes]): The content bytes fetched from the URL. None if an error occurred.
    """
    current_hash = None
    is_match = False
    content_bytes = None

    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        content_bytes = response.content

        hasher = hashlib.sha256()
        hasher.update(content_bytes)
        current_hash = hasher.hexdigest()

        if previous_hash and current_hash == previous_hash:
            is_match = True
        else:
            is_match = False

        return is_match, current_hash, content_bytes

    except requests.exceptions.Timeout:
        print(f"Error: Request timed out for URL: {url}")
        return False, None, None
    except requests.exceptions.HTTPError as e:
        print(f"Error: HTTP Error {e.response.status_code} for URL: {url}")
        return False, None, None
    except requests.exceptions.RequestException as e:
        print(f"Error: Failed to fetch URL {url}: {e}")
        return False, None, None
    except Exception as e:
        print(f"Error: An unexpected error occurred during hash check for {url}: {e}")
        return False, None, None

def monitor_url_change(url: str, hash_file_path: str) -> Tuple[bool, Optional[str], Optional[str], Optional[bytes]]:
    """
    Monitors a URL for content changes and returns the content if changed.

    Args:
        url: The URL of the resource to monitor.
        hash_file_path: Path to the file storing the previous hash.

    Returns:
        A tuple (content_changed, current_hash, previous_hash, content_bytes):
        - content_changed (bool): True if content changed or first run.
        - current_hash (Optional[str]): Current content hash.
        - previous_hash (Optional[str]): Previous hash from file.
        - content_bytes (Optional[bytes]): Content bytes from the URL.
    """
    previous_saved_hash = None
    content_changed = False
    latest_hash = None
    content_bytes = None

    try:
        if os.path.exists(hash_file_path):
            with open(hash_file_path, 'r') as f:
                previous_saved_hash = f.read().strip()
                if not previous_saved_hash:
                    previous_saved_hash = None
    except Exception as e:
        print(f"Warning: Error reading hash file: {e}")
        previous_saved_hash = None

    try:
        match_status, latest_hash, content_bytes = check_url_content_hash(url, previous_saved_hash)
        if latest_hash is not None:
            content_changed = not match_status
            if content_changed:
                try:
                    with open(hash_file_path, 'w') as f:
                        f.write(latest_hash)
                except Exception as e:
                    print(f"Error saving new hash: {e}")
        else:
            content_changed = False
    except requests.exceptions.RequestException as e:
        print(f"Critical error during request: {e}")
        content_changed = False

    return content_changed, latest_hash, previous_saved_hash, content_bytes

def webrawTxtScan(url_to_watch: str, hash_storage_file: str) -> None:
    """
    Checks for changes in the URL content and updates the specified file if changed.

    Args:
        url_to_watch: URL to monitor for content changes.
        hash_storage_file: File to store the content hash.
        content_file_path: File to update with the latest content.
    """
    changed, current_hash, previous_hash, content_bytes = monitor_url_change(url_to_watch, hash_storage_file)
    content_file_path = f"Data Acquisition\Data\{url_to_filename(url_to_watch)}.txt"
    print("\n--- Monitoring Summary ---")
    if current_hash:
        if changed:
            print(f"Content changed. Updating {content_file_path}.")
            if content_bytes is not None:
                try:
                    with open(content_file_path, 'wb') as f:
                        f.write(content_bytes)
                    print(f"Successfully updated {content_file_path}")
                except Exception as e:
                    print(f"Error updating content file: {e}")
            else:
                print("No content to save.")
        else:
            print("No change detected.")
    else:
        print("Check failed. Unable to verify content.")

# Example usage
if __name__ == "__main__":
    url = "https://raw.githubusercontent.com/python/cpython/main/README.rst"
    hash_file = "Data Acquisition\Data\hash_blacklist.txt"
    webrawTxtScan(url, hash_file)