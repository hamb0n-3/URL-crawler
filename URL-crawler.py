#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web Crawler for Red Teaming Assessments
---------------------------------------
This script is designed to crawl web pages starting from a given URL
and extract all unique URLs found on those pages.
It's intended for use in red teaming assessments to discover potential
targets or gather information.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import argparse
import time
import logging
import random # For randomized delays and User-Agent selection
import re # For URL filtering using regular expressions
import json # For parsing JSON content
import urllib.robotparser
import sys

# Configure logging for better feedback
# This will show informational messages and any errors encountered.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set to store all unique URLs found to avoid processing the same URL multiple times.
# Using a set ensures that each URL is stored only once.
visited_urls = set()

# Set to store all unique URLs that have been collected.
collected_urls = set()

# Counter for the number of HTTP requests made
requests_made = 0

def is_valid_url(url):
    """
    Checks if a URL is valid and not a mailto or tel link.
    A valid URL should have a scheme (like http or https) and a network location (like www.example.com).
    """
    parsed = urlparse(url)
    return bool(parsed.scheme) and bool(parsed.netloc) and parsed.scheme not in ['mailto', 'tel']

def get_page_content(url, timeout=10, headers=None, user_agents=None, proxy=None):
    """
    Fetches the content of a web page.
    Includes a timeout to prevent the script from hanging indefinitely.
    Allows custom headers, which can be useful for mimicking different user agents.
    Supports User-Agent rotation and proxies.
    Returns a tuple: (content, content_type) or (None, None) on error.
    """
    global requests_made  # Use the global counter
    try:
        current_headers = {}
        if headers:
            current_headers.update(headers)

        # Select a random User-Agent if a list is provided
        if user_agents:
            current_headers['User-Agent'] = random.choice(user_agents)
        elif 'User-Agent' not in current_headers: # Set default if no UA provided at all
            current_headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'

        proxies = None
        if proxy:
            # Requests library expects proxies in a dict like:
            # {'http': 'http://user:pass@host:port/', 'https': 'https://user:pass@host:port/'}
            # For simplicity, this example assumes the proxy works for both http and https.
            proxies = {'http': proxy, 'https': proxy}
        
        # Increment the requests_made counter before making the request
        requests_made += 1
        response = requests.get(url, headers=current_headers, timeout=timeout, allow_redirects=True, proxies=proxies)
        response.raise_for_status()
        content_type = response.headers.get('content-type', '').lower()
        return response.content, content_type # Return content and its type
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching {url}: {e}")
        return None, None

def extract_urls(html_content, base_url, parse_scripts=False):
    """
    Parses HTML content and extracts all unique absolute URLs.
    It converts relative URLs (like /about) to absolute URLs (like http://example.com/about).
    If parse_scripts is True, also extracts URLs from inline <script> tags.
    """
    urls = set() # Use a set to store found URLs to ensure uniqueness within this page.
    if not html_content:
        return urls

    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Find all <a> tags with an 'href' attribute, as these are hyperlinks.
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href'].strip()
        if href and not href.startswith('#'): # Ignore empty links and page anchors.
            # Convert relative URLs to absolute URLs using the base_url.
            absolute_url = urljoin(base_url, href)
            if is_valid_url(absolute_url):
                urls.add(absolute_url)
    
    # Also consider other tags that might contain URLs, e.g., <link>, <script src="">, <img src="">
    # For <link> tags (often stylesheets or other resources)
    for link_tag in soup.find_all('link', href=True):
        href = link_tag['href'].strip()
        absolute_url = urljoin(base_url, href)
        if is_valid_url(absolute_url):
            urls.add(absolute_url)

    # For <script> tags with a 'src' attribute
    for script_tag in soup.find_all('script', src=True):
        src = script_tag['src'].strip()
        absolute_url = urljoin(base_url, src)
        if is_valid_url(absolute_url):
            urls.add(absolute_url)

    # For <img> tags with a 'src' attribute
    for img_tag in soup.find_all('img', src=True):
        src = img_tag['src'].strip()
        # Ensure src is not empty and join with base_url if relative
        if src:
            absolute_url = urljoin(base_url, src)
            if is_valid_url(absolute_url):
                urls.add(absolute_url)

    # NEW: Extract URLs from inline <script> tags if parse_scripts is enabled
    if parse_scripts:
        for script_tag in soup.find_all('script', src=False):
            # Only consider inline scripts (no src attribute)
            script_text = script_tag.string
            if script_text:
                js_urls = extract_urls_from_javascript(script_text, base_url)
                urls.update(js_urls)

    logging.info(f"Extracted {len(urls)} HTML URLs from {base_url}")
    return urls

def extract_urls_from_javascript(script_content, base_url):
    """
    Extracts potential URLs from JavaScript code using regex.
    This is a best-effort approach and might find non-URLs or miss some.
    Converts relative paths found in strings to absolute URLs.
    """
    # Regex to find absolute URLs and common relative paths in JavaScript strings.
    # This regex matches:
    #   - URLs starting with http:// or https://
    #   - URLs starting with // (protocol-relative)
    #   - Relative paths starting with /, ./, ../
    #   - Strings that look like domain.tld/path or domain.tld
    url_pattern = re.compile(
        r'(["\\'])(https?:\/\/[\w\-\.\/?#=&;%:+~@!$\'()*\[\],]+|\/\/[^"\'\s]+|\.{0,2}\/[^"\'\s]+|[\w\-]+\.[a-zA-Z]{2,}(?:\/[\w\-\.\/?#=&;%:+~@!$\'()*\[\],]*)?)(["\\'])'
    )
    # The above regex is intentionally broad to catch most URL-like strings in JS.
    # It may catch some false positives, but that's better than missing URLs for recon.

    found_strings = set()
    try:
        # Iterate over all matches in the script content.
        for match in url_pattern.finditer(script_content):
            potential_url = match.group(2) # Group 2 is the URL-like string.
            # Basic sanity checks - avoid very short strings or obviously non-URL patterns
            if not potential_url or len(potential_url) < 3 or potential_url.startswith("javascript:"):
                continue
            # Clean common JS escape sequences like \/
            cleaned_url = potential_url.replace("\\/", "/")
            # Check if it's already a full URL or needs to be joined with base_url
            parsed = urlparse(cleaned_url)
            if parsed.scheme and parsed.netloc:
                if is_valid_url(cleaned_url):
                    found_strings.add(cleaned_url)
            else:
                # Attempt to join with base_url for relative paths
                if cleaned_url.startswith(("/", "./", "../")) or not parsed.scheme:
                    absolute_url = urljoin(base_url, cleaned_url)
                    if is_valid_url(absolute_url):
                        found_strings.add(absolute_url)
    except Exception as e:
        logging.warning(f"Error parsing JavaScript content from {base_url}: {e}")
    if found_strings:
        logging.info(f"Extracted {len(found_strings)} potential URLs from JavaScript at {base_url}")
    return found_strings

def extract_urls_from_json(json_data, base_url):
    """
    Recursively extracts string values that are valid URLs from JSON data.
    """
    urls = set()
    if isinstance(json_data, dict):
        for key, value in json_data.items():
            urls.update(extract_urls_from_json(value, base_url))
    elif isinstance(json_data, list):
        for item in json_data:
            urls.update(extract_urls_from_json(item, base_url))
    elif isinstance(json_data, str):
        # Check if the string is a potential URL
        # Attempt to join with base_url if it looks relative
        potential_url = json_data.strip()
        if potential_url:
            absolute_url = urljoin(base_url, potential_url)
            if is_valid_url(absolute_url):
                is_potential_absolute = urlparse(potential_url).scheme and urlparse(potential_url).netloc
                # Check if the absolute_url's domain is the same as the base_url's domain.
                # This is important if stay_on_domain_global_for_json_check is True.
                new_url_is_same_domain_as_base = urlparse(absolute_url).netloc == urlparse(base_url).netloc

                if is_potential_absolute: # If it was already an absolute URL
                    urls.add(absolute_url)
                else: # If it was a relative URL that we made absolute
                    if not stay_on_domain_global_for_json_check: # If we can leave the domain
                        urls.add(absolute_url)
                    elif new_url_is_same_domain_as_base: # If we must stay on domain AND it is on the same domain
                        urls.add(absolute_url)

    # No logging for each string, parent function will log summary for JSON.
    return urls

# A global or passed-in variable to respect stay_on_domain for JSON checks.
# This is a simplification. Ideally, stay_on_domain would be passed to extract_urls_from_json.
stay_on_domain_global_for_json_check = True 

def is_allowed_by_robots(url, robots_parser):
    """
    Checks if the given URL is allowed to be crawled according to robots.txt.
    Returns True if allowed, False if disallowed or robots.txt cannot be fetched.
    """
    if robots_parser is None:
        return True  # No robots.txt, allow by default
    user_agent = '*'  # We use * for generic crawling
    return robots_parser.can_fetch(user_agent, url)

def crawl(start_url, max_depth=2, min_delay=1, max_delay=3, stay_on_domain=True, output_file=None, headers=None, user_agents=None, proxy=None, include_pattern=None, exclude_pattern=None, parse_scripts=False, parse_json=False, respect_robots=False, max_urls=None, shallow=False):
    """
    Main crawling function.
    Recursively crawls web pages up to a specified depth.
    Includes randomized delays, URL filtering, and optional script/JSON parsing.
    Optionally respects robots.txt if respect_robots is True.
    Stops crawling if max_urls is reached (if set).
    If shallow is True, only collects URLs from the initial page and does not follow links.
    """
    queue = [(start_url, 0)]
    start_domain = urlparse(start_url).netloc
    include_regex = re.compile(include_pattern) if include_pattern else None
    exclude_regex = re.compile(exclude_pattern) if exclude_pattern else None
    robots_parser = None
    if respect_robots:
        robots_url = urljoin(start_url, '/robots.txt')
        robots_parser = urllib.robotparser.RobotFileParser()
        try:
            robots_parser.set_url(robots_url)
            robots_parser.read()
            logging.info(f"Loaded robots.txt from {robots_url}")
        except Exception as e:
            logging.warning(f"Could not load robots.txt from {robots_url}: {e}")
            robots_parser = None
    while queue:
        # Stop if we've reached the max_urls limit
        if max_urls is not None and len(collected_urls) >= max_urls:
            logging.info(f"Reached max_urls limit: {max_urls}. Stopping crawl.")
            break
        current_url, depth = queue.pop(0)
        if current_url in visited_urls or depth > max_depth:
            continue
        if stay_on_domain and urlparse(current_url).netloc != start_domain:
            logging.info(f"Skipping {current_url} (outside target domain {start_domain})")
            continue
        if respect_robots and not is_allowed_by_robots(current_url, robots_parser):
            logging.info(f"Skipping {current_url} (disallowed by robots.txt)")
            continue
        if include_regex and not include_regex.search(current_url):
            logging.debug(f"Skipping {current_url} (does not match include pattern)")
            continue
        if exclude_regex and exclude_regex.search(current_url):
            logging.debug(f"Skipping {current_url} (matches exclude pattern)")
            continue
        logging.info(f"Crawling (depth {depth}): {current_url}")
        visited_urls.add(current_url)
        collected_urls.add(current_url)
        # --- Progress indicator ---
        print(f"[Progress] Visited: {len(visited_urls)} | Collected: {len(collected_urls)} | In Queue: {len(queue)}", end='\r', flush=True)
        # --- End progress indicator ---
        page_content, content_type = get_page_content(current_url, headers=headers, user_agents=user_agents, proxy=proxy)
        extracted_new_urls = set()
        if page_content:
            if 'text/html' in content_type:
                extracted_new_urls.update(extract_urls(page_content, current_url, parse_scripts))
            elif parse_scripts and ('javascript' in content_type or current_url.endswith('.js') or 'text/javascript' in content_type):
                logging.info(f"Attempting to parse JavaScript content from: {current_url}")
                script_text = page_content.decode('utf-8', errors='ignore') 
                extracted_new_urls.update(extract_urls_from_javascript(script_text, current_url))
            elif parse_json and ('json' in content_type or current_url.endswith('.json')):
                logging.info(f"Attempting to parse JSON content from: {current_url}")
                try:
                    json_text = page_content.decode('utf-8', errors='ignore')
                    json_data = json.loads(json_text)
                    global stay_on_domain_global_for_json_check
                    stay_on_domain_global_for_json_check = stay_on_domain
                    json_extracted = extract_urls_from_json(json_data, current_url)
                    if json_extracted:
                        logging.info(f"Extracted {len(json_extracted)} URLs from JSON at {current_url}")
                        extracted_new_urls.update(json_extracted)
                except json.JSONDecodeError as e:
                    logging.warning(f"Could not parse JSON from {current_url}: {e}")
                except Exception as e:
                    logging.error(f"Error processing JSON from {current_url}: {e}")
            else:
                logging.debug(f"Skipping content parsing for {current_url} (content type: {content_type})")
            for new_url in extracted_new_urls:
                if new_url not in visited_urls:
                    if max_urls is not None and len(collected_urls) >= max_urls:
                        break
                    if include_regex and not include_regex.search(new_url):
                        logging.debug(f"Skipping {new_url} from queue (does not match include pattern)")
                        continue
                    if exclude_regex and exclude_regex.search(new_url):
                        logging.debug(f"Skipping {new_url} from queue (matches exclude pattern)")
                        continue
                    # If shallow mode is enabled, do not queue new URLs for crawling
                    if not shallow:
                        queue.append((new_url, depth + 1))
                    collected_urls.add(new_url)
        actual_delay = random.uniform(min_delay, max_delay)
        logging.debug(f"Waiting for {actual_delay:.2f} seconds...")
        # In shallow mode, only process the first page, so break after first iteration
        if shallow:
            break
        time.sleep(actual_delay)
    print()  # Move to next line after progress bar
    logging.info(f"Crawling finished. Found {len(collected_urls)} unique URLs.")
    if output_file:
        save_urls_to_file(output_file)

def save_urls_to_file(filename):
    """Saves the collected URLs to a specified file."""
    try:
        with open(filename, 'w') as f:
            for url in sorted(list(collected_urls)): # Sort for consistent output.
                f.write(url + '\n')
        logging.info(f"Collected URLs saved to {filename}")
    except IOError as e:
        logging.error(f"Error saving URLs to {filename}: {e}")

def main():
    """
    Parses command-line arguments and starts the crawling process.
    """
    parser = argparse.ArgumentParser(description="Web Crawler for Red Teaming Assessments.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("start_url", help="The URL to start crawling from.")
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum depth to crawl.")
    parser.add_argument("--min-delay", type=float, default=1.0, help="Minimum delay in seconds between requests.")
    parser.add_argument("--max-delay", type=float, default=3.0, help="Maximum delay in seconds between requests.")
    parser.add_argument("--stay-on-domain", action="store_true", default=True, help="Stay on the same domain as the start URL.")
    parser.add_argument("--no-stay-on-domain", action="store_false", dest="stay_on_domain", help="Allow crawling to external domains.")
    parser.add_argument("-o", "--output", help="File to save the collected URLs. If not specified, URLs are printed to console.")
    parser.add_argument("--user-agent-file", help="Path to a file containing User-Agent strings (one per line). A random one is chosen for each request.")
    parser.add_argument("--proxy", help="Proxy server to use (e.g., http://user:pass@host:port or socks5://host:port).")
    parser.add_argument("--include-pattern", help="Regex pattern for URLs to include. Only URLs matching this pattern will be crawled and collected.")
    parser.add_argument("--exclude-pattern", help="Regex pattern for URLs to exclude. URLs matching this pattern will be ignored.")
    parser.add_argument("--parse-scripts", action="store_true", help="Attempt to extract URLs from JavaScript files.")
    parser.add_argument("--parse-json", action="store_true", help="Attempt to extract URLs from JSON responses.")
    parser.add_argument("--user-agent-string", help="Specify a single User-Agent string directly.")
    parser.add_argument("--respect-robots", action="store_true", help="Respect robots.txt rules (default: off)")
    parser.add_argument("--max-urls", type=int, help="Maximum number of URLs to crawl (default: unlimited)")
    parser.add_argument("--json-output", action="store_true", help="Output collected URLs as JSON array to stdout (overrides -o if set)")
    # Add the shallow option
    parser.add_argument("--shallow", action="store_true", help="Only collect URLs from the initial page, do not follow links.")

    args = parser.parse_args()

    if not is_valid_url(args.start_url):
        logging.error(f"Invalid start URL: {args.start_url}. Please provide a full URL (e.g., http://example.com).")
        return

    custom_headers = None # Custom headers can be expanded later if needed, for now, User-Agent is handled separately.
    
    user_agent_list = []
    if args.user_agent_file:
        try:
            with open(args.user_agent_file, 'r') as f:
                user_agent_list = [line.strip() for line in f if line.strip()]
            if not user_agent_list:
                logging.warning(f"User-Agent file {args.user_agent_file} is empty.")
            else:
                logging.info(f"Loaded {len(user_agent_list)} User-Agents from {args.user_agent_file}")
        except IOError as e:
            logging.error(f"Could not read User-Agent file {args.user_agent_file}: {e}")
    elif args.user_agent_string: # If a single UA string is provided
        user_agent_list = [args.user_agent_string]
        logging.info(f"Using single User-Agent: {args.user_agent_string}")

    logging.info(f"Starting crawl from: {args.start_url}")
    logging.info(f"Max depth: {args.max_depth}, Randomized Delay: ({args.min_delay:.2f}s - {args.max_delay:.2f}s), Stay on domain: {args.stay_on_domain}")
    if args.proxy:
        logging.info(f"Using proxy: {args.proxy}")
    if args.include_pattern:
        logging.info(f"Including URLs matching: {args.include_pattern}")
    if args.exclude_pattern:
        logging.info(f"Excluding URLs matching: {args.exclude_pattern}")
    if args.parse_scripts:
        logging.info("Parsing of JavaScript files for URLs is enabled.")
    if args.parse_json:
        logging.info("Parsing of JSON responses for URLs is enabled.")
    if args.output:
        logging.info(f"Output will be saved to: {args.output}")
    if args.shallow:
        logging.info("Shallow mode enabled: Only collecting URLs from the initial page.")

    crawl(
        args.start_url, 
        args.max_depth, 
        args.min_delay, 
        args.max_delay, 
        args.stay_on_domain, 
        args.output, 
        custom_headers, # Retained for now, but UA is handled by user_agent_list
        user_agent_list if user_agent_list else None, # Pass the list of UAs
        args.proxy,
        args.include_pattern,
        args.exclude_pattern,
        args.parse_scripts,
        args.parse_json,
        args.respect_robots,
        args.max_urls,
        args.shallow # Pass the shallow flag
    )

    # Output results as JSON if requested
    if args.json_output:
        # Output both URLs and requests_made as a JSON object
        print(json.dumps({
            "urls": sorted(list(collected_urls)),
            "requests_made": requests_made
        }, indent=2))
        return
    if not args.output:
        # If no output file is specified, print to console.
        print("\n--- Collected URLs ---")
        if collected_urls:
            for url in sorted(list(collected_urls)):
                print(url)
        else:
            print("No URLs collected.")
        print(f"--- Found {len(collected_urls)} unique URLs ---")
        print(f"--- Total HTTP requests made: {requests_made} ---")


if __name__ == "__main__":
    main() 