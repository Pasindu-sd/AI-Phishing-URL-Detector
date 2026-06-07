import hashlib
import ipaddress
import math
import os
import re
import socket
from collections import Counter
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from functools import lru_cache
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


SUSPICIOUS_WORDS = ["login", "verify", "bank", "secure", "account", "password", "update"]
SHORTENERS = ["bit.ly", "tinyurl", "goo.gl", "t.co", "is.gd", "ow.ly", "buff.ly"]
WHOIS_SAMPLE_PERCENT = float(os.environ.get("URL_WHOIS_SAMPLE_PERCENT", "0.5"))
REDIRECT_SAMPLE_PERCENT = float(os.environ.get("URL_REDIRECT_SAMPLE_PERCENT", "0.25"))
WHOIS_TIMEOUT = float(os.environ.get("URL_WHOIS_TIMEOUT", "2.0"))
REDIRECT_TIMEOUT = float(os.environ.get("URL_REDIRECT_TIMEOUT", "2.0"))


def _normalize_url(url):
   candidate = (url or "").strip()
   if not candidate:
      return ""
   if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
      candidate = f"https://{candidate}"
   return candidate


def _hostname_from_url(url):
   parsed = urlsplit(_normalize_url(url))
   return (parsed.hostname or "").lower()


def _shannon_entropy(text):
   if not text:
      return 0.0

   counts = Counter(text)
   total = len(text)
   return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _is_ip_address(hostname):
   if not hostname:
      return False

   try:
      ipaddress.ip_address(hostname)
      return True
   except ValueError:
      return False


def _should_enrich(value, percent):
   if percent <= 0:
      return False

   digest = hashlib.md5((value or "").encode("utf-8")).hexdigest()
   score = int(digest[:8], 16) % 10000
   return score < int(percent * 100)


def _candidate_domains(hostname):
   parts = [part for part in hostname.split(".") if part]
   for index in range(len(parts) - 1):
      yield ".".join(parts[index:])


def _whois_query(server, query):
   with socket.create_connection((server, 43), timeout=WHOIS_TIMEOUT) as sock:
      sock.sendall(f"{query}\r\n".encode("utf-8"))
      chunks = []
      while True:
         data = sock.recv(4096)
         if not data:
            break
         chunks.append(data)

   return b"".join(chunks).decode("utf-8", errors="ignore")


def _parse_whois_datetime(raw_value):
   cleaned = raw_value.strip().split("#", 1)[0].split("(", 1)[0].strip()
   cleaned = cleaned.replace(" UTC", "+00:00").replace(" GMT", "+00:00").replace("Z", "+00:00")

   for date_format in (
      "%Y-%m-%dT%H:%M:%S%z",
      "%Y-%m-%d %H:%M:%S%z",
      "%Y-%m-%d",
      "%Y.%m.%d",
      "%d-%b-%Y",
      "%d-%b-%Y %H:%M:%S %Z",
      "%m/%d/%Y",
   ):
      try:
         parsed = datetime.strptime(cleaned, date_format)
         return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
      except ValueError:
         continue

   try:
      parsed = parsedate_to_datetime(cleaned)
      if parsed is not None:
         return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
   except (TypeError, ValueError, IndexError):
      return None

   return None


def _extract_whois_dates(whois_response):
   dates = []
   date_labels = (
      "creation date",
      "created on",
      "created",
      "registered on",
      "domain registration date",
      "domain create date",
      "record created on",
   )

   for line in whois_response.splitlines():
      normalized = line.strip().lower()
      if not any(label in normalized for label in date_labels):
         continue

      if ":" not in line:
         continue

      _, raw_value = line.split(":", 1)
      parsed = _parse_whois_datetime(raw_value)
      if parsed is not None:
         dates.append(parsed)

   return dates


def _whois_age_days(hostname):
   if not hostname or _is_ip_address(hostname):
      return 0.0

   for candidate in _candidate_domains(hostname):
      try:
         response = _whois_query("whois.iana.org", candidate)
         refer_match = re.search(r"(?im)^refer:\s*(\S+)", response)
         whois_server = refer_match.group(1).strip() if refer_match else None

         if whois_server:
            response = _whois_query(whois_server, candidate)

         dates = _extract_whois_dates(response)
         if dates:
            creation_date = min(dates)
            age = datetime.now(timezone.utc) - creation_date.astimezone(timezone.utc)
            return float(max(age.days, 0))
      except OSError:
         continue

   return 0.0


@lru_cache(maxsize=4096)
def _cached_whois_age_days(hostname):
   return _whois_age_days(hostname)


def _domain_age_days(url, force=False):
   hostname = _hostname_from_url(url)
   if not hostname:
      return 0.0

   if not force and not _should_enrich(hostname, WHOIS_SAMPLE_PERCENT):
      return 0.0

   return _cached_whois_age_days(hostname)


class _RedirectTracker(HTTPRedirectHandler):
   def __init__(self):
      super().__init__()
      self.hops = 0
      self.cross_domain_hops = 0
      self.loop_detected = False
      self._visited = set()

   def redirect_request(self, req, fp, code, msg, headers, newurl):
      resolved_url = urljoin(req.full_url, newurl)
      if resolved_url in self._visited:
         self.loop_detected = True
         return None

      previous_host = (urlsplit(req.full_url).hostname or "").lower()
      next_host = (urlsplit(resolved_url).hostname or "").lower()
      if previous_host and next_host and previous_host != next_host:
         self.cross_domain_hops += 1

      self._visited.add(resolved_url)
      self.hops += 1
      return super().redirect_request(req, fp, code, msg, headers, newurl)


def _redirect_features(url):
   normalized_url = _normalize_url(url)
   if not normalized_url:
      return 0.0, 0.0, 0.0

   tracker = _RedirectTracker()
   opener = build_opener(tracker)
   headers = {
      "User-Agent": "Mozilla/5.0 (URL feature extractor)",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
   }

   for method in ("HEAD", "GET"):
      request = Request(normalized_url, headers=headers, method=method)
      try:
         response = opener.open(request, timeout=REDIRECT_TIMEOUT)
         response.close()
         break
      except Exception:
         continue

   return float(tracker.hops), float(tracker.cross_domain_hops), float(1 if tracker.loop_detected else 0)


@lru_cache(maxsize=4096)
def _cached_redirect_features(url):
   return _redirect_features(url)


def extract_features(url, force_enrichment=False):
   normalized_url = _normalize_url(url)
   hostname = _hostname_from_url(url)
   feature_text = normalized_url or (url or "")

   entropy_value = _shannon_entropy(feature_text)
   domain_age = _domain_age_days(url, force=force_enrichment)
   redirect_hops = 0.0
   cross_domain_redirects = 0.0
   redirect_loop = 0.0

   should_probe_redirects = force_enrichment or _should_enrich(feature_text, REDIRECT_SAMPLE_PERCENT)
   if should_probe_redirects:
      redirect_hops, cross_domain_redirects, redirect_loop = _cached_redirect_features(feature_text)

   features = [
      len(feature_text),
      feature_text.count("."),
      feature_text.count("-"),
      feature_text.count("@"),
      1 if feature_text.startswith("https") else 0,
      1 if re.search(r"\d+\.\d+\.\d+\.\d+", feature_text) or _is_ip_address(hostname) else 0,
      1 if any(word in feature_text.lower() for word in SUSPICIOUS_WORDS) else 0,
      feature_text.count("?"),
      1 if any(shortener in feature_text.lower() for shortener in SHORTENERS) else 0,
      round(entropy_value, 6),
      round(domain_age, 2),
      redirect_hops,
      cross_domain_redirects,
      redirect_loop,
   ]

   return features
