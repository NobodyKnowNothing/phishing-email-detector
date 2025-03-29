import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService # Or FirefoxService, etc.
from webdriver_manager.chrome import ChromeDriverManager # Or FirefoxDriverManager, etc.
from selenium.common.exceptions import WebDriverException

def trace_redirects_and_get_final_html(start_url, poll_interval=0.2, stability_timeout=2.0, max_wait=30.0):
    """
    Traces redirects for a given URL using Selenium by polling driver.current_url
    and retrieves the HTML source of the final page.

    Args:
        start_url (str): The initial URL to navigate to.
        poll_interval (float): How often (in seconds) to check the current URL.
        stability_timeout (float): How long (in seconds) the URL must remain
                                   unchanged to be considered stable (final).
        max_wait (float): Maximum total time (in seconds) to wait for redirects.

    Returns:
        tuple: A tuple containing:
            - list: A list of URLs visited during the redirect chain, in order.
                    Returns an empty list if an error occurs during setup or initial load.
            - str or None: The HTML source code of the final page, or None if
                           it couldn't be retrieved or no redirects occurred.
    """
    redirect_urls = []
    final_html = None
    driver = None  # Initialize driver to None for finally block

    print(f"Starting redirect trace for: {start_url}")
    print("-" * 30)

    try:
        # --- WebDriver Setup ---
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36")

        print("Initializing WebDriver...")
        # Use webdriver_manager for easier setup
        driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
        # Or for Firefox:
        # from selenium.webdriver.firefox.service import Service as FirefoxService
        # from webdriver_manager.firefox import GeckoDriverManager
        # options = webdriver.FirefoxOptions()
        # options.add_argument("--headless")
        # driver = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()), options=options)
        print("WebDriver initialized.")

        # --- Navigation and Polling ---
        last_recorded_url = None
        start_time = time.time()
        last_change_time = time.time()

        print(f"Navigating to initial URL: {start_url}...")
        try:
            driver.get(start_url)
            time.sleep(poll_interval * 2) # Give it a moment to start loading/redirecting
        except WebDriverException as e:
            print(f"\nError during initial navigation: {e}")
            return [], None # Return empty list and None for HTML

        print("Starting URL polling...")

        while True:
            # 1. Check Overall Timeout
            if time.time() - start_time > max_wait:
                print(f"\nMaximum wait time ({max_wait}s) exceeded. Stopping trace.")
                break

            # 2. Get Current URL
            try:
                current_url = driver.current_url
                if not current_url or current_url == 'about:blank':
                     time.sleep(poll_interval)
                     continue
            except WebDriverException as e:
                print(f"\nError getting current URL: {e}. Stopping trace.")
                break

            # 3. Check for Change and Record
            if current_url != last_recorded_url:
                if not redirect_urls:
                     print(f"[{len(redirect_urls) + 1}] Initial Load/Redirect to: {current_url}")
                else:
                     print(f"[{len(redirect_urls) + 1}] Redirected to: {current_url}")

                redirect_urls.append(current_url)
                last_recorded_url = current_url
                last_change_time = time.time()

            # 4. Check for Stability
            elif time.time() - last_change_time > stability_timeout:
                print(f"\nURL has been stable ({current_url}) for {stability_timeout:.1f}s. Assuming final destination.")
                break

            # 5. Wait before next poll
            time.sleep(poll_interval)

        # --- Get Final HTML (after loop finishes, before quit) ---
        if redirect_urls: # Only if we actually navigated somewhere
            print("\nAttempting to retrieve final page source...")
            try:
                # Add a small wait for potential final rendering after URL stabilization
                time.sleep(0.5)
                final_html = driver.page_source
                print("Successfully retrieved final page source.")
            except WebDriverException as e:
                print(f"Error retrieving final page source: {e}")
                final_html = f"<!-- Error retrieving page source: {e} -->" # Store error message
            except Exception as e_gen:
                 print(f"Unexpected error retrieving final page source: {e_gen}")
                 final_html = f"<!-- Unexpected error retrieving page source: {e_gen} -->"

    except Exception as e:
        print(f"\nAn unexpected error occurred during the process: {e}")
    finally:
        if driver:
            print("Closing WebDriver...")
            driver.quit()
            print("WebDriver closed.")

    print("-" * 30)
    if not redirect_urls:
         print("No URLs were captured.")
    else:
        print("Redirect chain complete.")

    return redirect_urls, final_html


if __name__ == "__main__":

    url_to_trace = "https://fishmoxfishflex.us8.list-manage.com/track/click?u=9b36e2e86de48fb31a055da16&id=6c35e5e819&e=a2c18624b3"

    if not url_to_trace.startswith(('http://', 'https://')):
         print(f"Warning: URL '{url_to_trace}' doesn't start with http:// or https://. Adding http://")
         url_to_trace = "http://" + url_to_trace

    final_url_list, html_content = trace_redirects_and_get_final_html(url_to_trace)

    print("\n--- Summary ---")
    print(f"Initial URL: {url_to_trace}")
    if final_url_list:
        print("Captured Redirect Chain (driver.current_url):")
        for i, url in enumerate(final_url_list):
            print(f"  {i+1}. {url}")
        print(f"Final Destination: {final_url_list[-1]}")
    else:
        print("Could not determine redirect chain.")

"""    print("\n--- Final Page HTML ---")
    if html_content:
        print(html_content)
    elif final_url_list: # If we had URLs but no HTML
        print("Could not retrieve the HTML source for the final page.")
    else: # If we didn't even get URLs
        print("No final page reached or HTML available.")"""