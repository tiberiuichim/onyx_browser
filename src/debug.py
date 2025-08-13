import time
import io
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from playwright.sync_api import BrowserContext, Playwright, sync_playwright

from pdf_utils import read_pdf_file, is_pdf_content
from html_utils import web_html_cleanup


logger = logging.getLogger("debug")
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

eea_global_auth = {}

WEB_CONNECTOR_MAX_SCROLL_ATTEMPTS = 20
# Threshold for determining when to replace vs append iframe content
IFRAME_TEXT_LENGTH_THRESHOLD = 700
# Message indicating JavaScript is disabled, which often appears when scraping fails
JAVASCRIPT_DISABLED_MESSAGE = "You have JavaScript disabled in your browser"

# Define common headers that mimic a real browser
DEFAULT_USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
DEFAULT_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
        "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Sec-CH-UA": '"Google Chrome";v="123", "Not:A-Brand";v="8"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"macOS"',
}


def protected_url_check(url: str) -> None:
    # do nothing
    return


def _handle_cookies(context: BrowserContext, url: str) -> None:
    """Handle cookies for the given URL to help with bot detection"""
    try:
        # Parse the URL to get the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Add some common cookies that might help with bot detection
        cookies: list[dict[str, str]] = [
            {
                "name": "cookieconsent",
                "value": "accepted",
                "domain": domain,
                "path": "/",
            },
            {
                "name": "consent",
                "value": "true",
                "domain": domain,
                "path": "/",
            },
            {
                "name": "session",
                "value": "random_session_id",
                "domain": domain,
                "path": "/",
            },
        ]
        if eea_global_auth.get("login") is not None:
            cookies.append(
                {
                    "name": "__ac__eea",
                    "value": eea_global_auth["login"]["__ac__eea"],
                    "domain": "www.eea.europa.eu",
                    "path": "/",
                },
            )
            cookies.append(
                {
                    "name": "auth_token",
                    "value": eea_global_auth["login"]["auth_token"],
                    "domain": "www.eea.europa.eu",
                    "path": "/",
                }
            )
        # Add cookies to the context
        for cookie in cookies:
            try:
                context.add_cookies([cookie])  # type: ignore
            except Exception as e:
                logger.debug(
                    "Failed to add cookie %s for %s: %s", cookie["name"], domain, e
                )
    except Exception:
        logger.exception(
            "Unexpected error while handling cookies for Web Connector with URL %s",
            url,
        )


def set_auth_cookies():
    cookies = {}
    if eea_global_auth.get("login") is not None:
        cookies["__ac__eea"] = eea_global_auth["login"]["__ac__eea"]
        cookies["auth_token"] = eea_global_auth["login"]["auth_token"]

    return cookies


def start_playwright() -> tuple[Playwright, BrowserContext]:
    playwright = sync_playwright().start()

    # Launch browser with more realistic settings
    browser = playwright.chromium.launch(
        headless=False,
        args=[
            "--disable-blink-features=AutomationControlled",
            "--disable-features=IsolateOrigins,site-per-process",
            "--disable-site-isolation-trials",
            "--disable-web-security",
            # "--disable-dev-shm-usage",
            # "--no-sandbox",
            # "--disable-gpu",
            # "--disable-infobars",
            # "--disable-extensions",
            # "--disable-notifications",
            # "--disable-background-networking",
        ],
    )

    # Create a context with realistic browser properties
    context = browser.new_context(
        user_agent=DEFAULT_USER_AGENT,
        viewport={"width": 1440, "height": 900},
        device_scale_factor=2.0,
        locale="en-US",
        timezone_id="America/Los_Angeles",
        has_touch=False,
        java_script_enabled=True,
        color_scheme="light",
        # Add more realistic browser properties
        bypass_csp=True,
        ignore_https_errors=True,
    )

    # Set additional headers to mimic a real browser
    context.set_extra_http_headers(
        {
            "Accept": DEFAULT_HEADERS["Accept"],
            "Accept-Language": DEFAULT_HEADERS["Accept-Language"],
            "Sec-Fetch-Dest": DEFAULT_HEADERS["Sec-Fetch-Dest"],
            "Sec-Fetch-Mode": DEFAULT_HEADERS["Sec-Fetch-Mode"],
            "Sec-Fetch-Site": DEFAULT_HEADERS["Sec-Fetch-Site"],
            "Sec-Fetch-User": DEFAULT_HEADERS["Sec-Fetch-User"],
            "Sec-CH-UA": DEFAULT_HEADERS["Sec-CH-UA"],
            "Sec-CH-UA-Mobile": DEFAULT_HEADERS["Sec-CH-UA-Mobile"],
            "Sec-CH-UA-Platform": DEFAULT_HEADERS["Sec-CH-UA-Platform"],
            "Cache-Control": "max-age=0",
            "DNT": "1",
        }
    )

    # Add a script to modify navigator properties to avoid detection
    context.add_init_script(
        """
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined
        });
        Object.defineProperty(navigator, 'plugins', {
            get: () => [1, 2, 3, 4, 5]
        });
        Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en']
        });
    """
    )

    return playwright, context


def _get_datetime_from_last_modified_header(last_modified: str) -> datetime | None:
    try:
        return datetime.strptime(last_modified, "%a, %d %b %Y %H:%M:%S %Z").replace(
            tzinfo=timezone.utc
        )
    except (ValueError, TypeError):
        return None


class WebConnector:
    MAX_RETRIES = 3

    def __init__(
        self,
        base_url: str,  # Can't change this without disrupting existing users
        scroll_before_scraping: bool = False,
    ) -> None:
        self.scroll_before_scraping = scroll_before_scraping
        self.to_visit_list = [base_url]
        self.visited_links = set()
        self.content_hashes = set()
        self.last_error = None
        self.mintlify_cleanup = True

        self.playwright, self.playwright_context = start_playwright()

    def load_credentials(self, credentials: dict[str, Any]) -> dict[str, Any] | None:
        if credentials:
            logger.warning("Unexpected credentials provided for Web Connector")
        return None

    def do_scrape(
        self,
        index: int,
        initial_url: str,
    ):
        """Returns a ScrapeResult object with a doc and retry flag."""

        if self.playwright is None:
            raise RuntimeError("scrape_context.playwright is None")

        if self.playwright_context is None:
            raise RuntimeError("scrape_context.playwright_context is None")

        result = {}

        # Handle cookies for the URL
        _handle_cookies(self.playwright_context, initial_url)

        # First do a HEAD request to check content type without downloading the entire content
        auth_cookies = set_auth_cookies()
        head_response = requests.head(
            initial_url,
            headers=DEFAULT_HEADERS,
            cookies=auth_cookies,
            allow_redirects=True,
        )
        if (
            eea_global_auth.get("login") is not None
            and "@@download/file" in initial_url
        ):
            head_response = requests.get(
                initial_url,
                headers=DEFAULT_HEADERS,
                cookies=auth_cookies,
                allow_redirects=True,
                stream=True,
            )

        is_pdf = is_pdf_content(head_response)

        if is_pdf or initial_url.lower().endswith(".pdf"):
            # PDF files are not checked for links
            response = requests.get(
                initial_url, headers=DEFAULT_HEADERS, cookies=auth_cookies
            )
            page_text, metadata, images = read_pdf_file(
                file=io.BytesIO(response.content)
            )
            last_modified = response.headers.get("Last-Modified")

            doc_updated_at = (
                _get_datetime_from_last_modified_header(last_modified)
                if last_modified
                else None
            )

            semantic_identifier = initial_url.split("/")[-1]
            id = initial_url

            logger.info("The document is a PDF")
            logger.info("Metadata:\n%r", metadata)
            logger.info("ID: %s", id)
            logger.info("Semantic identifier: %s", semantic_identifier)
            logger.info("DOC Updated at", doc_updated_at)
            logger.info("Text", page_text)

        page = self.playwright_context.new_page()
        try:
            # Can't use wait_until="networkidle" because it interferes with the scrolling behavior
            page_response = page.goto(
                initial_url,
                timeout=30000,  # 30 seconds
                wait_until="domcontentloaded",  # Wait for DOM to be ready
            )

            last_modified = (
                page_response.header_value(
                    "Last-Modified") if page_response else None
            )

            final_url = page.url
            if final_url != initial_url:
                protected_url_check(final_url)
                initial_url = final_url
                if initial_url in self.visited_links:
                    logger.info(
                        "%s: %S redirected to %s - already indexed",
                        index,
                        initial_url,
                        final_url,
                    )
                    page.close()
                    return result

                logger.info(f"""{index}: {initial_url}
                            redirected to {final_url}""")

                self.visited_links.add(initial_url)

            # If we got here, the request was successful
            if self.scroll_before_scraping:
                scroll_attempts = 0
                previous_height = page.evaluate("document.body.scrollHeight")
                while scroll_attempts < WEB_CONNECTOR_MAX_SCROLL_ATTEMPTS:
                    page.evaluate(
                        "window.scrollTo(0, document.body.scrollHeight)")
                    # wait for the content to load if we scrolled
                    page.wait_for_load_state("networkidle", timeout=30000)
                    time.sleep(0.5)  # let javascript run

                    new_height = page.evaluate("document.body.scrollHeight")
                    if new_height == previous_height:
                        break  # Stop scrolling when no more content is loaded
                    previous_height = new_height
                    scroll_attempts += 1

            content = page.content()
            import pdb

            pdb.set_trace()
            soup = BeautifulSoup(content, "html.parser")

            if page_response and str(page_response.status)[0] in ("4", "5"):
                self.last_error = f"""Skipped indexing {initial_url} due to HTTP {
                    page_response.status
                } response"""
                logger.info(self.last_error)
                # result.retry = True
                return result

            # after this point, we don't need the caller to retry
            parsed_html = web_html_cleanup(soup, self.mintlify_cleanup)

            """For websites containing iframes that need to be scraped,
            the code below can extract text from within these iframes.
            """
            logger.debug(
                f"""{index}: Length of cleaned text {len(parsed_html.cleaned_text)}"""
            )
            if JAVASCRIPT_DISABLED_MESSAGE in parsed_html.cleaned_text:
                iframe_count = page.frame_locator(
                    "iframe").locator("html").count()
                if iframe_count > 0:
                    iframe_texts = (
                        page.frame_locator("iframe").locator(
                            "html").all_inner_texts()
                    )
                    document_text = "\n".join(iframe_texts)
                    """ 700 is the threshold value for the length of the text extracted
                    from the iframe based on the issue faced """
                    if len(parsed_html.cleaned_text) < IFRAME_TEXT_LENGTH_THRESHOLD:
                        parsed_html.cleaned_text = document_text
                    else:
                        parsed_html.cleaned_text += "\n" + document_text

            # Sometimes pages with #! will serve duplicate content
            # There are also just other ways this can happen
            hashed_text = hash((parsed_html.title, parsed_html.cleaned_text))
            if hashed_text in self.content_hashes:
                logger.info(
                    f"""{index}: Skipping duplicate title + content for {initial_url}"""
                )
                return result

            self.content_hashes.add(hashed_text)
        finally:
            page.close()

        return result


if __name__ == "__main__":
    # parse command line arguments
    import argparse

    arg_parser = argparse.ArgumentParser(
        description="Web Connector Debug Tool")
    arg_parser.add_argument(
        "url",
        type=str,
        help="The URL to scrape using the Web Connector",
    )
    args = arg_parser.parse_args()
    url = args.url
    connector = WebConnector(base_url=url, scroll_before_scraping=True)
    connector.do_scrape(0, url)
