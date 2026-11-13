"""Pull the readable text and the links out of an email, without rendering it."""
import re
from html.parser import HTMLParser

_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.I)


class _HtmlReader(HTMLParser):
    """Collects the visible text of an HTML part and every (href, link text) pair."""

    def __init__(self):
        super().__init__()
        self.text = []       # all visible text pieces
        self.links = []      # finished (href, link text) pairs
        self._href = None    # href of the <a> tag we are inside, if any
        self._label = []     # text seen so far inside that <a> tag

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._label = dict(attrs).get("href") or "", []

    def handle_data(self, data):
        self.text.append(data)
        if self._href is not None:
            self._label.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            if self._href.lower().startswith("http"):
                self.links.append((self._href, " ".join("".join(self._label).split())))
            self._href = None


def read_content(msg):
    """Return (text, links) for the non-attachment text parts of `msg`.

    `links` is a list of (url, link_text) pairs. URLs found in plain text have
    an empty link text because there the visible text is the URL itself.
    """
    texts, links = [], []
    for part in msg.walk():
        if part.get_content_maintype() != "text" or part.is_attachment():
            continue
        body = part.get_content()
        if part.get_content_subtype() == "html":
            reader = _HtmlReader()
            reader.feed(body)
            texts.append(" ".join(reader.text))
            links.extend(reader.links)
        else:
            texts.append(body)
            links.extend((url.rstrip(".,;"), "") for url in _URL.findall(body))
    unique = list(dict.fromkeys(links))  # drop duplicates, keep the order
    return " ".join(" ".join(texts).split()), unique
