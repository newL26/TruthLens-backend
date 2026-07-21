"""
agents/url_agent.py — Agent 2: URL & Website Risk Analyzer

Signal inventory (14 signals, each with a documented max contribution):
  1.  No HTTPS                      +20
  2.  IP address as host            +30
  3.  Suspicious TLD (weighted)     +10 – +25
  4.  Excessive subdomains (≥ 4)    +10
  5.  Brand impersonation           +35
  6.  Suspicious path keywords      up to +20
  7.  Cyrillic / homoglyph chars    +40
  8.  Very long URL (> 200 chars)   +5
  9.  Punycode / IDN domain         +20
 10.  Data-URI or javascript: scheme +50
 11.  Deep path (> 6 segments)      +8
 12.  Percent-encoding abuse        +15
 13.  Typosquatting heuristic       +25
 14.  Non-standard port             +10

Score is capped at 100.
Confidence is calibrated from the number and diversity of signals hit.
"""
from __future__ import annotations

import logging
import re
import urllib.parse
from typing import Optional

import requests
from django.conf import settings

from .base import BaseAgent, AgentResult

logger = logging.getLogger("agents.url_agent")

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

TRUSTED_BRANDS = [
    "google", "facebook", "paypal", "amazon", "microsoft", "apple",
    "instagram", "twitter", "whatsapp", "netflix", "dropbox", "linkedin",
    "wellsfargo", "chase", "bankofamerica", "citibank", "barclays",
    "crdb", "nmb", "kcb", "equity", "tigo", "vodacom", "airtel",
    "government", "nida", "tra", "ura", "kra", "nhif", "nssf", "zimra",
]

# Official second-level domains that should NOT be flagged as impersonation
_BRAND_WHITELIST_DOMAINS = {
    "google.com", "google.co.tz", "google.co.ke",
    "facebook.com", "fb.com",
    "paypal.com",
    "amazon.com", "amazon.co.uk",
    "microsoft.com", "live.com", "outlook.com",
    "apple.com",
    "instagram.com",
    "twitter.com", "x.com",
    "whatsapp.com",
    "netflix.com",
    "dropbox.com",
    "linkedin.com",
    "crdb.co.tz",
    "nmb.co.tz",
    "kcb.co.ke",
    "equitybank.co.ke",
    "airtel.co.tz", "airtel.co.ke",
    "vodacom.co.tz",
    "tra.go.tz",
    "nida.go.tz",
    "nhif.or.ke",
    "nssf.or.tz",
}

# TLD risk weights  (higher = riskier)
TLD_RISK: dict[str, int] = {
    ".xyz": 25, ".top": 22, ".click": 22, ".gq": 25, ".ml": 25,
    ".ga": 25, ".cf": 25, ".tk": 25, ".pw": 20, ".work": 18,
    ".loan": 22, ".win": 20, ".bid": 20, ".stream": 18, ".download": 20,
    ".party": 15, ".racing": 15, ".trade": 15, ".review": 12,
    ".date": 12, ".faith": 12, ".accountant": 12, ".cricket": 12,
}

# Keywords in paths that raise suspicion
SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "secure", "update",
    "account", "banking", "payment", "confirm", "validate", "wallet",
    "prize", "winner", "free", "bonus", "reward", "claim", "activate",
    "suspended", "locked", "unusual-activity", "billing",
]

# Regex helpers — compiled once at import time
_IP_HOST_RE = re.compile(r"^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
_EXCESS_SUBDOMAIN_RE = re.compile(r"([^./]+\.){4,}")     # 4+ dot-separated parts before TLD
_CYRILLIC_RE = re.compile(r"[\u0400-\u04FF]")             # Cyrillic lookalikes
_PUNYCODE_RE = re.compile(r"xn--", re.IGNORECASE)
_PERCENT_ENCODE_RE = re.compile(r"%[0-9a-fA-F]{2}")       # any percent-encoded character
_DANGEROUS_SCHEME_RE = re.compile(r"^(javascript|data|vbscript):", re.IGNORECASE)
_NON_STD_PORT_RE = re.compile(r":\d{4,5}$")              # port in netloc


class URLAnalysisAgent(BaseAgent):
    """
    Agent 2 — Analyzes a URL across 14 risk signals and produces a
    structured AgentResult with a risk score, per-signal findings, and
    metadata suitable for direct DB persistence.
    """
    agent_name = "url_analysis"

    def analyze(self, url: str = "", **kwargs) -> AgentResult:
        if not url or not url.strip():
            return AgentResult(
                success=False,
                agent_name=self.agent_name,
                error="No URL provided.",
            )

        url = url.strip()

        # Reject obviously dangerous schemes before any further processing
        if _DANGEROUS_SCHEME_RE.match(url):
            return AgentResult(
                success=True,
                agent_name=self.agent_name,
                score=100,
                confidence=95,
                provider="internal",
                findings=["Dangerous URI scheme detected (javascript:/data:/vbscript:)"],
                data={
                    "url": url,
                    "domain": "",
                    "uses_https": False,
                    "suspicious_patterns": ["dangerous_scheme"],
                    "is_brand_impersonation_suspected": False,
                    "is_typosquatting_suspected": False,
                    "redirect_count": 0,
                    "final_url": url,
                    "tld_risk": 0,
                    "path_depth": 0,
                    "encoding_issues": True,
                    "signal_count": 1,
                    "risk_label": "High Risk",
                    "signal_detail": {"dangerous_scheme": True},
                    "online_check": {"checked": False, "reachable": None},
                    "crosscheck_links": self._build_crosscheck_links(""),
                },
            )

        # Normalise — add scheme if missing
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            parsed = urllib.parse.urlparse(url)
        except Exception as exc:
            return AgentResult(
                success=False,
                agent_name=self.agent_name,
                error=f"URL parse error: {exc}",
            )

        domain = parsed.netloc.lower().strip()
        path = parsed.path.lower()
        query = parsed.query.lower()
        scheme = parsed.scheme.lower()
        uses_https = scheme == "https"

        findings: list[str] = []
        suspicious_patterns: list[str] = []
        signal_detail: dict[str, object] = {}
        score = 0

        # ------------------------------------------------------------------
        # Signal 1: No HTTPS
        # ------------------------------------------------------------------
        if not uses_https:
            score += 20
            findings.append("Does not use HTTPS — connection is unencrypted")
            suspicious_patterns.append("no_https")
            signal_detail["no_https"] = True

        # ------------------------------------------------------------------
        # Signal 2: IP address used as host
        # ------------------------------------------------------------------
        if _IP_HOST_RE.match(url):
            score += 30
            findings.append("URL uses a raw IP address instead of a domain name")
            suspicious_patterns.append("ip_address_as_host")
            signal_detail["ip_address_as_host"] = True

        # ------------------------------------------------------------------
        # Signal 3: Suspicious TLD (weighted by risk table)
        # ------------------------------------------------------------------
        tld_risk_score = 0
        matched_tld = ""
        for tld, weight in TLD_RISK.items():
            # Match at end of netloc, stripping optional port
            netloc_no_port = domain.split(":")[0]
            if netloc_no_port.endswith(tld):
                tld_risk_score = weight
                matched_tld = tld
                break
        if tld_risk_score:
            score += tld_risk_score
            findings.append(f"Domain uses a high-risk TLD: {matched_tld} (risk weight: {tld_risk_score})")
            suspicious_patterns.append(f"suspicious_tld:{matched_tld}")
            signal_detail["suspicious_tld"] = matched_tld

        # ------------------------------------------------------------------
        # Signal 4: Excessive subdomains
        # ------------------------------------------------------------------
        netloc_no_port = domain.split(":")[0]
        subdomain_count = netloc_no_port.count(".")
        if subdomain_count >= 3:
            score += 10
            findings.append(f"URL has {subdomain_count} subdomain levels — unusually deep")
            suspicious_patterns.append("excessive_subdomains")
            signal_detail["subdomain_depth"] = subdomain_count

        # ------------------------------------------------------------------
        # Signal 5: Brand impersonation
        # ------------------------------------------------------------------
        impersonated_brand = self._detect_brand_impersonation(domain)
        if impersonated_brand:
            score += 35
            findings.append(
                f"Possible brand impersonation: '{impersonated_brand}' appears in domain "
                f"but does not match the official domain"
            )
            suspicious_patterns.append("brand_impersonation")
            signal_detail["brand_impersonation_suspected"] = impersonated_brand

        # ------------------------------------------------------------------
        # Signal 6: Suspicious keywords in path / query
        # ------------------------------------------------------------------
        full_path_query = path + "?" + query if query else path
        kw_hits = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in full_path_query]
        if kw_hits:
            kw_score = min(20, len(kw_hits) * 5)
            score += kw_score
            findings.append(
                f"Suspicious keyword{'s' if len(kw_hits) > 1 else ''} in URL path: "
                f"{', '.join(kw_hits[:5])}"
            )
            suspicious_patterns.append("suspicious_path_keywords")
            signal_detail["path_keywords"] = kw_hits

        # ------------------------------------------------------------------
        # Signal 7: Cyrillic / homoglyph characters in domain
        # ------------------------------------------------------------------
        if _CYRILLIC_RE.search(domain):
            score += 40
            findings.append("Domain contains Cyrillic characters — possible homoglyph attack")
            suspicious_patterns.append("homoglyph_chars")
            signal_detail["homoglyph_chars"] = True

        # ------------------------------------------------------------------
        # Signal 8: Very long URL
        # ------------------------------------------------------------------
        if len(url) > 200:
            score += 5
            findings.append(f"Unusually long URL ({len(url)} characters)")
            suspicious_patterns.append("long_url")
            signal_detail["url_length"] = len(url)

        # ------------------------------------------------------------------
        # Signal 9: Punycode / Internationalised Domain Name
        # ------------------------------------------------------------------
        if _PUNYCODE_RE.search(domain):
            score += 20
            findings.append("Domain uses punycode (xn--) — may be a lookalike/IDN attack")
            suspicious_patterns.append("punycode_idn")
            signal_detail["punycode_idn"] = True

        # ------------------------------------------------------------------
        # Signal 10: Dangerous scheme (already handled above; skip)
        # ------------------------------------------------------------------

        # ------------------------------------------------------------------
        # Signal 11: Deep URL path (> 6 segments)
        # ------------------------------------------------------------------
        path_segments = [s for s in path.split("/") if s]
        path_depth = len(path_segments)
        if path_depth > 6:
            score += 8
            findings.append(f"Unusually deep URL path ({path_depth} segments)")
            suspicious_patterns.append("deep_path")
            signal_detail["path_depth"] = path_depth

        # ------------------------------------------------------------------
        # Signal 12: Excessive percent-encoding
        # ------------------------------------------------------------------
        encode_hits = _PERCENT_ENCODE_RE.findall(url)
        encoding_issues = len(encode_hits) > 5
        if encoding_issues:
            score += 15
            findings.append(
                f"URL contains {len(encode_hits)} percent-encoded characters — "
                "may be obfuscating malicious content"
            )
            suspicious_patterns.append("encoding_abuse")
            signal_detail["percent_encoded_count"] = len(encode_hits)

        # ------------------------------------------------------------------
        # Signal 13: Typosquatting heuristic
        # ------------------------------------------------------------------
        is_typosquatting = self._detect_typosquatting(netloc_no_port)
        if is_typosquatting:
            score += 25
            findings.append(
                "Domain closely resembles a well-known brand but is not the official domain — "
                "possible typosquatting"
            )
            suspicious_patterns.append("typosquatting_suspected")
            signal_detail["typosquatting_suspected"] = True

        # ------------------------------------------------------------------
        # Signal 14: Non-standard port
        # ------------------------------------------------------------------
        if parsed.port and parsed.port not in (80, 443, 8080, 8443):
            score += 10
            findings.append(f"URL uses a non-standard port: {parsed.port}")
            suspicious_patterns.append("non_standard_port")
            signal_detail["port"] = parsed.port

        # ------------------------------------------------------------------
        # Cap score and compute confidence
        # ------------------------------------------------------------------
        score = min(100, score)
        confidence = self._compute_confidence(
            signal_count=len(suspicious_patterns),
            has_https_signal=not uses_https or "ip_address_as_host" in suspicious_patterns,
            brand_hit=bool(impersonated_brand),
        )

        risk_label = self._score_to_label(score)

        # ------------------------------------------------------------------
        # Online cross-check: quick reachability probe + manual-verification
        # links, so users can independently confirm accuracy when a link
        # looks wrong or the heuristic score seems off.
        # ------------------------------------------------------------------
        online_check = self._quick_online_check(url)
        crosscheck_links = self._build_crosscheck_links(netloc_no_port)

        if online_check.get("checked") and online_check.get("reachable") is False:
            findings.append(
                "The link could not be reached online — it may be broken, taken down, "
                "or blocking automated checks."
            )
            suspicious_patterns.append("unreachable_online")
            signal_detail["unreachable_online"] = True

        final_url = online_check.get("final_url") or url
        redirect_count = online_check.get("redirect_count", 0)

        return AgentResult(
            success=True,
            agent_name=self.agent_name,
            score=score,
            confidence=confidence,
            provider="internal",
            findings=findings,
            data={
                "url": url,
                "domain": netloc_no_port,
                "uses_https": uses_https,
                "suspicious_patterns": suspicious_patterns,
                "is_brand_impersonation_suspected": bool(impersonated_brand),
                "is_typosquatting_suspected": is_typosquatting,
                # New fields
                "redirect_count": redirect_count,
                "final_url": final_url,
                "tld_risk": tld_risk_score,
                "path_depth": path_depth,
                "encoding_issues": encoding_issues,
                "signal_count": len(suspicious_patterns),
                "risk_label": risk_label,
                "signal_detail": signal_detail,
                # Online verification — lets the user quickly cross-check
                # accuracy themselves instead of relying on heuristics alone.
                "online_check": online_check,
                "crosscheck_links": crosscheck_links,
            },
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_brand_impersonation(domain: str) -> str:
        """
        Return the brand name if a known brand keyword appears in the domain
        but the domain-root is NOT on the official whitelist.

        Examples that should trigger:
          paypal-login.xyz       → "paypal"
          secure-paypal.com      → "paypal"
          paypal.secure.xyz      → "paypal"

        Examples that should NOT trigger:
          paypal.com             → ""   (official domain)
          paypal.co.uk           → ""   (official ccTLD variant — not in whitelist but
                                          root is 'paypal' with known ccTLD)
        """
        netloc = domain.split(":")[0]
        # Strip www.
        bare = netloc.replace("www.", "")
        # Extract SLD (second-level domain) — everything between first and last dot group
        parts = bare.split(".")
        sld = parts[0] if parts else bare

        for brand in TRUSTED_BRANDS:
            if brand not in bare:
                continue
            # Check whitelist
            if bare in _BRAND_WHITELIST_DOMAINS:
                return ""
            # Allow  <brand>.<known-ccTLD>  patterns (e.g. paypal.co.uk)
            if sld == brand:
                return ""
            # Brand appears somewhere else in the domain → impersonation
            return brand
        return ""

    @staticmethod
    def _detect_typosquatting(netloc: str) -> bool:
        """
        Simple edit-distance heuristic.  A domain is suspected of typosquatting
        if it is 1–2 characters away from a trusted brand name (Levenshtein ≤ 2)
        but does NOT exactly match that brand.
        """
        bare = netloc.replace("www.", "")
        # Take only the second-level part (e.g. "paypa1" from "paypa1.com")
        parts = bare.split(".")
        candidate = parts[0] if parts else bare

        for brand in TRUSTED_BRANDS:
            if candidate == brand:
                return False          # exact match — not a squatter
            if abs(len(candidate) - len(brand)) <= 2:
                dist = _levenshtein(candidate, brand)
                if 1 <= dist <= 2:
                    return True
        return False

    @staticmethod
    def _score_to_label(score: int) -> str:
        if score >= 70:
            return "High Risk"
        if score >= 50:
            return "Suspicious"
        if score >= 20:
            return "Needs Verification"
        return "Likely Safe"

    @staticmethod
    def _compute_confidence(
        signal_count: int,
        has_https_signal: bool,
        brand_hit: bool,
    ) -> int:
        """Confidence rises with more independent signals."""
        base = 50
        base += min(30, signal_count * 8)   # each additional signal adds certainty
        if brand_hit:
            base += 10
        if has_https_signal:
            base += 5
        return min(95, base)

    @staticmethod
    def _build_crosscheck_links(domain: str) -> dict:
        """
        Build ready-to-click links to independent, well-known online tools so
        a user can quickly cross-check whether a link/domain is accurate and
        safe, rather than relying solely on our internal heuristics (which
        can occasionally be wrong).
        """
        if not domain:
            return {}
        quoted_domain = urllib.parse.quote(domain, safe="")
        return {
            "google_safe_browsing": (
                "https://transparencyreport.google.com/safe-browsing/search?url="
                f"{quoted_domain}"
            ),
            "virustotal": f"https://www.virustotal.com/gui/domain/{quoted_domain}",
            "urlscan": f"https://urlscan.io/search/#{quoted_domain}",
            "whois": f"https://www.whois.com/whois/{quoted_domain}",
        }

    @staticmethod
    def _quick_online_check(url: str) -> dict:
        """
        Perform a fast, best-effort reachability check against the live URL so
        results reflect what's actually online right now (some links reported
        as risky/safe by static heuristics alone may be outdated or wrong).

        Designed to never slow down or break the pipeline:
          - Disabled entirely via settings.URL_ONLINE_CHECK_ENABLED (tests run
            with this off so CI stays fast and deterministic).
          - Uses a short timeout (settings.URL_ONLINE_CHECK_TIMEOUT_SEC).
          - Any network error is caught and reported, never raised.
        """
        if not getattr(settings, "URL_ONLINE_CHECK_ENABLED", True):
            return {"checked": False, "reachable": None}

        timeout = float(getattr(settings, "URL_ONLINE_CHECK_TIMEOUT_SEC", 3))

        try:
            resp = requests.head(
                url, allow_redirects=True, timeout=timeout,
                headers={"User-Agent": "TruthLensAI-URLCheck/1.0"},
            )
            # Some servers reject HEAD; fall back to a lightweight GET.
            if resp.status_code in (403, 405):
                resp = requests.get(
                    url, allow_redirects=True, timeout=timeout, stream=True,
                    headers={"User-Agent": "TruthLensAI-URLCheck/1.0"},
                )
            return {
                "checked": True,
                "reachable": resp.status_code < 400,
                "status_code": resp.status_code,
                "final_url": resp.url,
                "redirect_count": len(resp.history),
                "error": None,
            }
        except requests.RequestException as exc:
            return {
                "checked": True,
                "reachable": False,
                "status_code": None,
                "final_url": url,
                "redirect_count": 0,
                "error": str(exc),
            }


# ---------------------------------------------------------------------------
# Utility — fast Levenshtein (no external deps)
# ---------------------------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]
