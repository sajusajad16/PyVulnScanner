import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl(url):
    visited = set()
    to_visit = [url]

    domain = urlparse(url).netloc

    while to_visit:
        current = to_visit.pop()

        if current in visited:
            continue

        try:
            response = requests.get(current, timeout=5)
            visited.add(current)

            soup = BeautifulSoup(response.text, "html.parser")

            for link in soup.find_all("a", href=True):
                full_url = urljoin(current, link["href"])

                # stay inside same domain
                if urlparse(full_url).netloc == domain:
                    if full_url not in visited:
                        to_visit.append(full_url)

        except:
            continue

    return visited
