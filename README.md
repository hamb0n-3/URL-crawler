# Web Crawler for Red Teaming

This Python script is a simple web crawler designed to traverse web pages starting from a given URL and extract all unique URLs found. It is intended for use in red teaming assessments to aid in the discovery of potential targets or to gather information about a web application's structure.

## Features

- Crawls web pages starting from a specified URL.
- Extracts unique URLs from HTML (`<a>`, `<link>`, `<script src="">`, `<img src="">`), JavaScript files, and JSON responses.
- Option to limit crawling depth.
- Option to stay within the same domain as the starting URL or crawl externally.
- Configurable randomized delay between requests (min/max) to mimic human behavior and reduce server load.
- Advanced URL filtering using regular expression patterns (include/exclude).
- Saves collected URLs to an output file or prints them to the console.
- Allows setting a custom User-Agent string directly or rotating through User-Agents from a provided file.
- Support for using an HTTP/HTTPS proxy.
- Detailed logging for monitoring progress, decisions, and errors.
- Respects robots.txt rules if requested.
- Limits the number of unique URLs crawled.
- Outputs collected URLs as a JSON array to stdout if requested.
- Optionally only collects URLs from the initial page (shallow mode) to minimize requests.
- Shows the total number of HTTP requests made in the output.

## Requirements

- Python 3.x
- `requests` library
- `beautifulsoup4` library

## Installation

1.  **Clone the repository or download the script.**

2.  **Install the required Python libraries:**

    It's recommended to use a virtual environment:

    ```bash
    python3 -m venv crawler-env
    source crawler-env/bin/activate  # On Windows use `crawler-env\Scripts\activate
    pip install -r requirements.txt
    ```

## Usage

Run the crawler with default settings (max depth 2, stay on domain, 1s delay between requests):

```bash
python crawler.py http://example.com
```

### Command-Line Options

-   `-m, --max-depth N`: Maximum crawl depth (default: 2).
-   `--no-stay-on-domain`: Allow crawling external domains (default: stay on the initial domain only).
-   `--min-delay SECONDS`: Minimum delay between requests (default: 1).
-   `--max-delay SECONDS`: Maximum delay between requests (default: 2).
-   `-o, --output FILE`: Output file to save collected URLs.
-   `--user-agent-string STRING`: Set a custom User-Agent string.
-   `--user-agent-file FILE`: Provide a file with multiple User-Agent strings for rotation.
-   `--proxy URL`: Use an HTTP/HTTPS proxy (e.g., `http://host:port` or `socks5://host:port` - note: SOCKS proxy requires `requests[socks]` to be installed separately).
-   `--include-pattern REGEX`: Regex pattern for URLs to include. Only URLs matching this pattern will be crawled and collected.
-   `--exclude-pattern REGEX`: Regex pattern for URLs to exclude. URLs matching this pattern will be ignored.
-   `--parse-scripts`: (Flag) Attempt to extract URLs from JavaScript files/content and inline <script> tags in HTML.
-   `--parse-json`: (Flag) Attempt to extract URLs from JSON responses.
-   `--respect-robots`: (Flag) Respect robots.txt rules (default: off). If set, the crawler will skip URLs disallowed by robots.txt for User-Agent '*'.
-   `--max-urls N`: Maximum number of unique URLs to crawl (default: unlimited).
-   `--json-output`: (Flag) Output collected URLs as a JSON array to stdout (overrides -o if set).
-   `--shallow`: (Flag) Only collect URLs from the initial page and do not follow links. This minimizes the number of requests made to the target domain (useful for stealthy red teaming).

### Output Metrics

-   The output now includes a metric showing the total number of HTTP requests made during the crawl. This is shown in both the console output and the JSON output (as `requests_made`).

### Examples

1.  **Crawl a website with default settings (max depth 2, stay on domain, 1s delay):**

    ```bash
    python crawler.py http://example.com
    ```

2.  **Crawl with a maximum depth of 3 and save output to `urls.txt`:**

    ```bash
    python crawler.py http://example.com --max-depth 3 -o found_urls.txt
    ```

3.  **Crawl and allow following links to external domains:**

    ```bash
    python crawler.py http://example.com --no-stay-on-domain
    ```

4.  **Crawl with a 0.5 second delay and a custom User-Agent:**
    ```bash
    python crawler.py http://example.com --min-delay 0.5 --user-agent-string "MyCustomCrawler/1.0"
    ```

5.  **Crawl with randomized delay (1-3s), filter for URLs containing `/api/`, and use a proxy:**
    ```bash
    python crawler.py https://example.com --min-delay 1 --max-delay 3 --include-pattern "/api/" --proxy http://localhost:8080 -o api_urls.txt
    ```

6.  **Crawl and parse JavaScript/JSON for URLs, using a list of user agents:**
    ```bash
    python crawler.py http://example.com --parse-scripts --parse-json --user-agent-file user_agents.txt
    ```

7.  **Crawl with robots.txt respected, limit to 100 URLs, and output as JSON:**
    ```bash
    python crawler.py http://example.com --respect-robots --max-urls 100 --json-output
    ```

8.  **Shallow crawl (only collect URLs from the initial page, do not follow links):**
    ```bash
    python crawler.py http://example.com --shallow
    ```

    This will minimize the number of requests made to the target domain (only one request for the initial page).

## How it Works

1.  **Initialization**: Takes a starting URL and other parameters.
2.  **Queue**: Uses a queue to manage URLs to visit.
3.  **Fetching**: Downloads the HTML content of the current URL. If JavaScript or JSON parsing is enabled, it fetches these content types too.
4.  **Parsing**: Uses BeautifulSoup to parse HTML. For JavaScript and JSON, it uses regular expressions and the `json` library respectively to find URL-like strings.
5.  **URL Validation & Normalization**: Converts relative URLs to absolute URLs and validates them. Applies include/exclude filters.
6.  **Storing**: Stores all unique collected URLs in a set to avoid duplicates and keeps track of visited URLs to prevent re-crawling.
7.  **Recursion/Iteration**: Adds newly found, unvisited URLs (within the specified depth and domain constraints) to the queue.
8.  **Output**: Saves the list of unique URLs to a file or prints them. The output also includes the total number of HTTP requests made during the crawl (shown in the console and in JSON output as `requests_made`).

## Ethical Considerations & Disclaimer

-   **Be Responsible**: Always ensure you have explicit permission to crawl a website. Unauthorized crawling can be mistaken for malicious activity and may have legal consequences.
-   **Server Load**: Be mindful of the target server's load. Use the `--delay` option to avoid overwhelming the server.
-   **Robots.txt**: This script can respect `robots.txt` if you use the `--respect-robots` flag. For general-purpose, non-assessment crawling, always check `robots.txt` if unsure.
-   **Proxies & Anonymity**: While proxy support is included, ensure your proxy setup provides the desired level of anonymity. SOCKS proxies (`socks5://...`) require `pip install requests[socks]`.
-   **Scope**: Clearly define your scope when using this tool for an assessment. Only crawl targets you are authorized to assess.

This tool is provided for educational and authorized red teaming purposes only. The author is not responsible for any misuse or damage caused by this script. 

