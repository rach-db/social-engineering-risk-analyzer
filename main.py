"""
Social Engineering Risk Analyzer - Improved Version
"""

import re
import json
import logging
import argparse
from urllib.parse import urlparse
from datetime import datetime
from typing import Optional

# Optional WHOIS support
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ==============================
# KEYWORD DATABASES
# ==============================

IMPERSONATION_WORDS = ["official", "support", "admin", "customer care", "helpdesk"]
URGENCY_WORDS      = ["urgent", "act now", "limited", "offer", "immediate", "claim now"]
BRAND_WORDS        = ["amazon", "paypal", "instagram", "facebook", "google", "bank"]

SUSPICIOUS_DOMAIN_WORDS = ["verify", "secure", "login", "update", "claim"]
SUSPICIOUS_TLDS         = [".xyz", ".online", ".top", ".info"]

# Max possible score — derived from scoring logic for accurate percentage
MAX_SCORE = 155


# ==============================
# HELPERS
# ==============================

def _word_matches(word: str, text: str) -> bool:
    """Match whole words only (avoids 'banking' matching 'bank')."""
    pattern = r'\b' + re.escape(word) + r'\b'
    return bool(re.search(pattern, text, re.IGNORECASE))


def _match_any(word_list: list[str], text: str) -> list[str]:
    return [w for w in word_list if _word_matches(w, text)]


# ==============================
# ANALYSIS MODULES
# ==============================

def analyze_keywords(bio: str) -> tuple[list, list, list]:
    impersonation_hits = _match_any(IMPERSONATION_WORDS, bio)
    urgency_hits       = _match_any(URGENCY_WORDS, bio)
    brand_hits         = _match_any(BRAND_WORDS, bio)
    return impersonation_hits, urgency_hits, brand_hits


def analyze_username(username: str) -> tuple[bool, bool, bool]:
    imp_in_user   = any(_word_matches(w, username) for w in IMPERSONATION_WORDS)
    brand_in_user = any(_word_matches(w, username) for w in BRAND_WORDS)
    # Only flag digits if they appear right after an impersonation/brand word
    suspicious_digit_pattern = bool(
        re.search(r'(official|support|admin|amazon|paypal|google|facebook|instagram|bank)\d+',
                  username, re.IGNORECASE)
    )
    return imp_in_user, brand_in_user, suspicious_digit_pattern


def analyze_account_age(creation_date: Optional[str]) -> Optional[int]:
    if not creation_date:
        return None
    try:
        created = datetime.strptime(creation_date.strip(), "%Y-%m-%d")
        return (datetime.today() - created).days
    except ValueError as e:
        logger.warning("Could not parse account creation date '%s': %s", creation_date, e)
        return None


def analyze_domain(link: str) -> tuple[Optional[int], bool, list[str]]:
    """
    Returns (domain_age_days, tld_is_suspicious, suspicious_keyword_hits).
    All failures are logged rather than silently swallowed.
    """
    if not link:
        return None, False, []

    try:
        if not link.startswith("http"):
            link = "http://" + link

        parsed = urlparse(link)
        domain = parsed.netloc.lower().lstrip("www.")

        suspicious_word_hits = _match_any(SUSPICIOUS_DOMAIN_WORDS, domain)
        tld_flag = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)

        domain_age_days = _get_domain_age(domain)
        return domain_age_days, tld_flag, suspicious_word_hits

    except Exception as e:
        logger.warning("Domain analysis failed for '%s': %s", link, e)
        return None, False, []


def _get_domain_age(domain: str) -> Optional[int]:
    if not WHOIS_AVAILABLE:
        logger.warning("python-whois is not installed; skipping domain age check.")
        return None
    try:
        import socket
        socket.setdefaulttimeout(10)          # prevent indefinite hang
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            return (datetime.today() - creation_date).days
    except Exception as e:
        logger.warning("WHOIS lookup failed for '%s': %s", domain, e)
    return None


# ==============================
# SCORING ENGINE
# ==============================

def calculate_risk_score(
    username: str,
    impersonation_hits: list,
    urgency_hits: list,
    brand_hits: list,
    account_age_days: Optional[int],
    domain_age_days: Optional[int],
    tld_flag: bool,
    suspicious_domain_words: list,
    link: str,
) -> dict:

    score = 0
    reasons = []

    # --- Language Signals ---
    if impersonation_hits:
        score += min(len(impersonation_hits) * 10, 25)
        reasons.append(f"Impersonation language detected: {impersonation_hits}")

    if urgency_hits:
        score += min(len(urgency_hits) * 5, 15)
        reasons.append(f"Urgency language detected: {urgency_hits}")

    if brand_hits and impersonation_hits:
        score += 15
        reasons.append(f"Brand impersonation detected: {brand_hits}")

    if impersonation_hits and urgency_hits:
        score += 10
        reasons.append("Impersonation + urgency combination")

    # --- Username Pattern ---
    imp_user, brand_user, suspicious_digits = analyze_username(username)

    if imp_user and brand_user:
        score += 15
        reasons.append("Brand + impersonation keywords in username")

    if suspicious_digits:
        score += 10
        reasons.append("Suspicious digit pattern in username (e.g. 'support2024')")

    # --- Domain Signals ---
    if link:
        if suspicious_domain_words:
            score += 10
            reasons.append(f"Suspicious domain keywords: {suspicious_domain_words}")
        if tld_flag:
            score += 10
            reasons.append("Suspicious top-level domain (e.g. .xyz, .online)")

    if domain_age_days is not None:
        if domain_age_days < 30:
            score += 25
            reasons.append(f"Very new domain ({domain_age_days} days old)")
        elif domain_age_days < 180:
            score += 15
            reasons.append(f"New domain ({domain_age_days} days old)")

    # --- Account Age ---
    if account_age_days is not None:
        if account_age_days < 7:
            score += 20
            reasons.append(f"Very new account ({account_age_days} days old)")
        elif account_age_days < 30:
            score += 10
            reasons.append(f"New account ({account_age_days} days old)")

    # --- Old Account + New Domain Mismatch ---
    if account_age_days is not None and domain_age_days is not None:
        if account_age_days > 365 and domain_age_days < 30:
            score += 20
            reasons.append("Old account linked to newly registered domain — likely compromised or repurposed")

    # --- Derived Metrics ---
    risk_percentage = min((score / MAX_SCORE) * 100, 100)

    if score <= 25:
        level = "LOW"
    elif score <= 60:
        level = "MEDIUM"
    else:
        level = "HIGH"

    signal_count = len(reasons)
    confidence = "HIGH" if signal_count >= 5 else "MEDIUM" if signal_count >= 3 else "LOW"

    return {
        "score": score,
        "max_score": MAX_SCORE,
        "risk_percentage": round(risk_percentage, 2),
        "risk_level": level,
        "confidence": confidence,
        "indicators": reasons,
        "account_age_days": account_age_days,
        "domain_age_days": domain_age_days,
    }


# ==============================
# INPUT
# ==============================

def get_user_input() -> dict:
    print("===== SOCIAL ENGINEERING RISK ANALYZER =====")
    username      = input("Enter username: ").strip()
    bio           = input("Enter bio/description: ").strip()
    link          = input("Enter external link (or press Enter if none): ").strip()
    creation_date = input("Enter account creation date (YYYY-MM-DD) or press Enter if unknown: ").strip() or None
    return {"username": username, "bio": bio, "link": link, "creation_date": creation_date}


# ==============================
# REPORTING
# ==============================

def print_report(profile: dict, result: dict, as_json: bool = False) -> None:
    if as_json:
        output = {"username": profile["username"], **result}
        print(json.dumps(output, indent=2))
        return

    print("\n===== SOCIAL ENGINEERING RISK REPORT =====")
    print(f"Username:        {profile['username']}")
    print(f"Risk Score:      {result['score']} / {result['max_score']}")
    print(f"Risk Percentage: {result['risk_percentage']:.2f}%")
    print(f"Risk Level:      {result['risk_level']}")
    print(f"Confidence:      {result['confidence']}")
    print(f"Account Age:     {result['account_age_days']} days" if result['account_age_days'] is not None else "Account Age:     Unknown")
    print(f"Domain Age:      {result['domain_age_days']} days" if result['domain_age_days'] is not None else "Domain Age:      Unknown")

    print("\nTriggered Indicators:")
    if result["indicators"]:
        for r in result["indicators"]:
            print(f"  - {r}")
    else:
        print("  None")


# ==============================
# MAIN
# ==============================

def run(profile: dict, as_json: bool = False) -> dict:
    impersonation_hits, urgency_hits, brand_hits = analyze_keywords(profile["bio"])
    account_age_days = analyze_account_age(profile["creation_date"])
    domain_age_days, tld_flag, suspicious_domain_words = analyze_domain(profile["link"])

    result = calculate_risk_score(
        profile["username"], impersonation_hits, urgency_hits, brand_hits,
        account_age_days, domain_age_days, tld_flag, suspicious_domain_words, profile["link"]
    )

    print_report(profile, result, as_json=as_json)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Social Engineering Risk Analyzer")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    profile = get_user_input()
    run(profile, as_json=args.json)