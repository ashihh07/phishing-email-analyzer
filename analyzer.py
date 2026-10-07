#!/usr/bin/env python3
"""Phishing Email Analyzer - quick static triage of .eml files.

Parses headers, auth results (SPF/DKIM/DMARC), links and attachments,
then gives a rough risk score. Never fetches anything, fully offline.
"""
import argparse
import hashlib
import json
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"}
SUS_TLDS = {"xyz", "top", "click", "zip", "mov", "work", "gq", "tk", "ml",
            "cf", "ga", "country", "support", "loan", "icu"}
RISKY_EXT = {"exe", "scr", "js", "vbs", "bat", "cmd", "ps1", "jar", "lnk",
             "iso", "img", "hta", "docm", "xlsm", "pptm", "html", "htm"}
URGENCY = ["urgent", "immediately", "verify your account", "suspended",
           "within 24 hours", "action required", "confirm your password",
           "unusual activity", "final notice", "account will be closed"]

LEVELS = [(50, "HIGH"), (20, "MEDIUM"), (0, "LOW")]


class LinkParser(HTMLParser):
    """Collect <a href> with its visible text."""

    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), " ".join(self._text).strip()))
            self._href = None


def domain_of(addr):
    addr = parseaddr(str(addr or ""))[1].lower()
    return addr.split("@", 1)[1] if "@" in addr else ""


def defang(url):
    return re.sub(r"^http", "hxxp", url).replace(".", "[.]")


def check_url(url, text=""):
    flags = []
    p = urlparse(url)
    host = (p.hostname or "").lower()
    if not host:
        return flags
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        flags.append("IP address as host")
    if host in SHORTENERS:
        flags.append("URL shortener")
    if "xn--" in host:
        flags.append("punycode host (possible lookalike)")
    tld = host.rsplit(".", 1)[-1]
    if tld in SUS_TLDS:
        flags.append(f"suspicious TLD .{tld}")
    if "@" in p.netloc:
        flags.append("credentials trick (@ in URL)")
    if p.scheme == "http":
        flags.append("no HTTPS")
    if host.count(".") >= 4:
        flags.append("too many subdomains")
    m = re.search(r"((?:[a-z0-9-]+\.)+[a-z]{2,})", text.lower())
    if m:
        shown = m.group(1)
        if shown != host and not host.endswith("." + shown) and not shown.endswith("." + host):
            flags.append(f"link text shows {shown} but goes to {host}")
    return flags


def analyze(path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    r = {"file": path, "headers": {}, "auth": {}, "links": [],
         "attachments": [], "findings": [], "score": 0}

    def add(points, text):
        r["findings"].append({"points": points, "text": text})
        r["score"] += points

    # --- headers ---
    for h in ("From", "Reply-To", "Return-Path", "To", "Subject", "Date", "Message-ID"):
        r["headers"][h] = str(msg[h]) if msg[h] else ""
    r["headers"]["Received hops"] = len(msg.get_all("Received") or [])

    from_d = domain_of(r["headers"]["From"])
    reply_d = domain_of(r["headers"]["Reply-To"])
    path_d = domain_of(r["headers"]["Return-Path"])

    if reply_d and reply_d != from_d:
        add(15, f"Reply-To domain ({reply_d}) differs from From ({from_d})")
    if path_d and path_d != from_d:
        add(10, f"Return-Path domain ({path_d}) differs from From ({from_d})")

    name = parseaddr(r["headers"]["From"])[0].lower()
    m = re.search(r"([a-z0-9-]+\.)+[a-z]{2,}", name)
    if m and m.group(0) != from_d:
        add(15, f"display name contains a domain ({m.group(0)}) that isn't the sender's")

    # --- auth results ---
    auth_raw = " ".join(str(v) for v in (msg.get_all("Authentication-Results") or []))
    auth_raw += " " + str(msg["Received-SPF"] or "")
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}\s*=\s*(\w+)", auth_raw, re.I)
        if not m and mech == "spf":
            m = re.match(r"\s*(\w+)", str(msg["Received-SPF"] or ""))
        r["auth"][mech] = m.group(1).lower() if m else "none"
    for mech, res in r["auth"].items():
        if res in ("fail", "permerror", "temperror"):
            add(20, f"{mech.upper()} {res}")
        elif res in ("softfail", "neutral"):
            add(10, f"{mech.upper()} {res}")
    if all(v == "none" for v in r["auth"].values()):
        add(5, "no SPF/DKIM/DMARC results found in headers")

    # --- bodies, links, attachments ---
    body_text = ""
    raw_links = []
    for part in msg.walk():
        ctype = part.get_content_type()
        fname = part.get_filename()
        if fname:
            data = part.get_payload(decode=True) or b""
            r["attachments"].append({
                "name": fname, "type": ctype, "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest()})
        elif ctype == "text/plain":
            txt = part.get_content()
            body_text += " " + txt
            raw_links += [(u, "") for u in re.findall(r"https?://[^\s<>\"')]+", txt)]
        elif ctype == "text/html":
            html = part.get_content()
            body_text += " " + re.sub(r"<[^>]+>", " ", html)
            lp = LinkParser()
            lp.feed(html)
            raw_links += lp.links

    seen = set()
    link_points = 0
    for url, text in raw_links:
        if url in seen or not url.lower().startswith(("http://", "https://")):
            continue
        seen.add(url)
        flags = check_url(url, text)
        r["links"].append({"url": url, "text": text, "flags": flags})
        link_points += 8 * len(flags)
    if link_points:
        add(min(link_points, 40), "suspicious link traits (see links section)")

    hits = [w for w in URGENCY if w in body_text.lower()]
    if hits:
        add(min(5 * len(hits), 15), "urgency / pressure wording: " + ", ".join(hits))

    for a in r["attachments"]:
        parts = a["name"].lower().split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        if ext in RISKY_EXT:
            add(25, f"risky attachment type: {a['name']}")
        if len(parts) > 2 and ext in RISKY_EXT:
            add(20, f"double extension: {a['name']}")

    r["score"] = min(r["score"], 100)
    r["level"] = next(lbl for lim, lbl in LEVELS if r["score"] >= lim)
    return r


def show(r):
    colors = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[92m"}
    c = colors[r["level"]] if sys.stdout.isatty() else ""
    end = "\033[0m" if c else ""
    print(f"\n=== {r['file']} ===")
    for k, v in r["headers"].items():
        print(f"  {k:<15} {v}")
    print("\n  Auth:", ", ".join(f"{k.upper()}={v}" for k, v in r["auth"].items()))
    print(f"\n  Links ({len(r['links'])}):")
    for l in r["links"]:
        print(f"    - {defang(l['url'])}")
        for fl in l["flags"]:
            print(f"        ! {fl}")
    print(f"\n  Attachments ({len(r['attachments'])}):")
    for a in r["attachments"]:
        print(f"    - {a['name']} ({a['size']} bytes)\n      sha256 {a['sha256']}")
    print("\n  Findings:")
    for f in r["findings"]:
        print(f"    +{f['points']:<3} {f['text']}")
    print(f"\n  RISK: {c}{r['level']}{end} (score {r['score']})\n")


def main():
    ap = argparse.ArgumentParser(description="Static phishing triage for .eml files")
    ap.add_argument("files", nargs="+", help=".eml file(s) to analyze")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = ap.parse_args()

    results = [analyze(f) for f in args.files]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            show(r)


if __name__ == "__main__":
    main()
