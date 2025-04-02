import argparse
import requests
import logging
from bs4 import BeautifulSoup
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="vscan-http-header-scanner: Performs lightweight scans of HTTP headers to identify common security vulnerabilities and misconfigurations.")
    parser.add_argument("url", help="The URL to scan.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("-o", "--output", help="Output file to save results (optional).")
    parser.add_argument("-r", "--raw", action="store_true", help="Print raw headers (optional).")
    return parser

def get_headers(url):
    """
    Fetches HTTP headers from the given URL.

    Args:
        url (str): The URL to fetch headers from.

    Returns:
        dict: A dictionary containing the HTTP headers.  Returns None on error.
    """
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.headers
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching headers from {url}: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def check_security_headers(headers, url):
    """
    Checks for the presence and configuration of common security headers.

    Args:
        headers (dict): A dictionary of HTTP headers.
        url (str): The URL being scanned.

    Returns:
        dict: A dictionary of found vulnerabilities and misconfigurations.
    """
    results = {}

    # Strict-Transport-Security (HSTS)
    if 'Strict-Transport-Security' not in headers:
        results['Strict-Transport-Security'] = "Missing HSTS header.  This can leave users vulnerable to man-in-the-middle attacks."
        logging.warning(f"{url}: Missing Strict-Transport-Security header")
    else:
        hsts_header = headers['Strict-Transport-Security']
        if 'max-age' not in hsts_header.lower():
            results['Strict-Transport-Security'] = f"HSTS header present, but missing max-age directive. Configuration: {hsts_header}"
            logging.warning(f"{url}: HSTS header present, but missing max-age directive. Configuration: {hsts_header}")

    # X-Frame-Options
    if 'X-Frame-Options' not in headers:
        results['X-Frame-Options'] = "Missing X-Frame-Options header. Vulnerable to clickjacking attacks."
        logging.warning(f"{url}: Missing X-Frame-Options header")
    else:
         xfo_header = headers['X-Frame-Options']
         if xfo_header.lower() not in ('deny', 'sameorigin'):
             results['X-Frame-Options'] = f"X-Frame-Options configured with unsafe value: {xfo_header}"
             logging.warning(f"{url}: X-Frame-Options configured with unsafe value: {xfo_header}")

    # X-Content-Type-Options
    if 'X-Content-Type-Options' not in headers:
        results['X-Content-Type-Options'] = "Missing X-Content-Type-Options header. Could lead to MIME sniffing vulnerabilities."
        logging.warning(f"{url}: Missing X-Content-Type-Options header")
    elif headers['X-Content-Type-Options'].lower() != 'nosniff':
         results['X-Content-Type-Options'] = f"X-Content-Type-Options configured with unsafe value: {headers['X-Content-Type-Options']}"
         logging.warning(f"{url}: X-Content-Type-Options configured with unsafe value: {headers['X-Content-Type-Options']}")

    # Content-Security-Policy (CSP)
    if 'Content-Security-Policy' not in headers:
        results['Content-Security-Policy'] = "Missing Content-Security-Policy header.  Reduces protection against XSS attacks."
        logging.warning(f"{url}: Missing Content-Security-Policy header")
    else:
        csp_header = headers['Content-Security-Policy']
        if "unsafe-inline" in csp_header.lower() or "unsafe-eval" in csp_header.lower():
             results['Content-Security-Policy'] = f"Content-Security-Policy includes potentially unsafe directives: {csp_header}"
             logging.warning(f"{url}: Content-Security-Policy includes potentially unsafe directives: {csp_header}")

    # Referrer-Policy
    if 'Referrer-Policy' not in headers:
        results['Referrer-Policy'] = "Missing Referrer-Policy header. The referring origin might be sent to other sites."
        logging.warning(f"{url}: Missing Referrer-Policy header")

    #Permissions-Policy
    if 'Permissions-Policy' not in headers:
        results['Permissions-Policy'] = "Missing Permissions-Policy header. The browser default policy applies. Implement Permissions-Policy header to prevent other sites from using your website resources."
        logging.warning(f"{url}: Missing Permissions-Policy header")

    return results

def crawl_and_scan(url):
    """
    Crawls the given URL for links and scans each link for security headers.

    Args:
        url (str): The URL to crawl and scan.

    Returns:
        dict: A dictionary of results for each scanned URL.
    """
    results = {}
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        links = [a['href'] for a in soup.find_all('a', href=True)]

        results[url] = scan_url(url) # Scan the initial URL

        for link in links:
            # Handle relative URLs
            absolute_url = link if link.startswith('http') else f"{url.rstrip('/')}/{link.lstrip('/')}"

            #Avoid external URLs in the crawling process
            if absolute_url.startswith(url):
                results[absolute_url] = scan_url(absolute_url) # Scan each discovered link
            else:
                logging.info(f"Skipping external URL: {absolute_url}")

    except requests.exceptions.RequestException as e:
        logging.error(f"Error crawling {url}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during crawling: {e}")
    return results

def scan_url(url):
    """
    Scans a single URL for security headers.

    Args:
        url (str): The URL to scan.

    Returns:
        dict: A dictionary of results for the URL.
    """
    headers = get_headers(url)
    if headers:
        return check_security_headers(headers, url)
    else:
        return {}

def print_results(results, raw_headers=False):
    """
    Prints the scan results to the console.

    Args:
        results (dict): A dictionary of scan results.
        raw_headers (bool): Whether to print raw headers.
    """
    for url, findings in results.items():
        print(f"Scanning URL: {url}")
        if findings:
            for header, issue in findings.items():
                print(f"  - {header}: {issue}")
        else:
            print("  - No security issues found.")

def save_results(results, filename):
    """
    Saves the scan results to a file.

    Args:
        results (dict): A dictionary of scan results.
        filename (str): The name of the file to save the results to.
    """
    try:
        with open(filename, "w") as f:
            for url, findings in results.items():
                f.write(f"Scanning URL: {url}\n")
                if findings:
                    for header, issue in findings.items():
                        f.write(f"  - {header}: {issue}\n")
                else:
                    f.write("  - No security issues found.\n")
    except Exception as e:
        logging.error(f"Error saving results to {filename}: {e}")

def main():
    """
    Main function to execute the vscan-http-header-scanner.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    url = args.url

    logging.info(f"Starting scan for URL: {url}")
    results = crawl_and_scan(url)  # Crawl and scan the URL

    print_results(results, args.raw)

    if args.output:
        save_results(results, args.output)
        logging.info(f"Results saved to: {args.output}")

    logging.info("Scan completed.")

if __name__ == "__main__":
    main()