import re
import urllib.parse

# Maps to the UCI phishing dataset (ARFF) column order.
# URL-derivable features are computed; page-analysis features default to neutral.
FEATURE_NAMES = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token",
    "Request_URL", "URL_of_Anchor", "Links_in_tags", "SFH",
    "Submitting_to_email", "Abnormal_URL", "Redirect", "on_mouseover",
    "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
    "DNSRecord", "web_traffic", "Page_Rank", "Google_Index",
    "Links_pointing_to_page", "Statistical_report",
]

FEATURE_LABELS = {
    "having_IP_Address": "IP Address in URL",
    "URL_Length": "URL Length",
    "Shortining_Service": "URL Shortener",
    "having_At_Symbol": "@ Symbol Present",
    "double_slash_redirecting": "Double Slash Redirect",
    "Prefix_Suffix": "Hyphen in Domain",
    "having_Sub_Domain": "Subdomain Count",
    "SSLfinal_State": "HTTPS / SSL",
    "Domain_registeration_length": "Domain Registration Length",
    "Favicon": "Favicon Source",
    "port": "Non-Standard Port",
    "HTTPS_token": "'HTTPS' in Domain Name",
    "Request_URL": "External Request URLs",
    "URL_of_Anchor": "Anchor Tag URLs",
    "Links_in_tags": "Links in Script/Meta Tags",
    "SFH": "Server Form Handler",
    "Submitting_to_email": "Form Submits to Email",
    "Abnormal_URL": "Abnormal URL Structure",
    "Redirect": "Page Redirects",
    "on_mouseover": "Mouseover Status Bar",
    "RightClick": "Right-Click Disabled",
    "popUpWidnow": "Popup Window",
    "Iframe": "iFrame Present",
    "age_of_domain": "Domain Age",
    "DNSRecord": "DNS Record",
    "web_traffic": "Site Traffic Rank",
    "Page_Rank": "PageRank",
    "Google_Index": "Google Indexed",
    "Links_pointing_to_page": "Inbound Links",
    "Statistical_report": "In Phishing Reports",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rb.gy", "cutt.ly", "short.io",
}


def extract_features(url: str) -> list:
    """
    Returns a 30-element feature vector matching the UCI ARFF column order.
    Encoding: 1 = legitimate signal, -1 = phishing signal, 0 = suspicious/neutral.
    Features that require page fetching or WHOIS default to 1 (neutral).
    """
    raw = url.lower().strip()
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw

    try:
        parsed = urllib.parse.urlparse(raw)
        scheme = parsed.scheme
        netloc = parsed.netloc.split(":")[0]
        path = parsed.path
        query = parsed.query
    except Exception:
        return [1] * 30

    # 1. IP address instead of domain
    ip_re = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    having_IP = -1 if ip_re.match(netloc) else 1

    # 2. URL length: <54 safe, 54–75 suspicious, >75 phishing
    url_len = len(url)
    URL_Length = 1 if url_len < 54 else (0 if url_len <= 75 else -1)

    # 3. URL shortener service
    Shortining_Service = -1 if any(s in raw for s in SHORTENERS) else 1

    # 4. @ symbol — browser ignores everything to its left
    having_At = -1 if "@" in url else 1

    # 5. Double slash in path (not counting the protocol's //)
    path_body = path + ("?" + query if query else "")
    double_slash = -1 if "//" in path_body else 1

    # 6. Hyphen in domain name (e.g. paypal-secure.com)
    Prefix_Suffix = -1 if "-" in netloc else 1

    # 7. Subdomain depth
    dots = netloc.replace("www.", "").count(".")
    having_Sub_Domain = 1 if dots == 1 else (0 if dots == 2 else -1)

    # 8. HTTPS
    SSLfinal_State = 1 if scheme == "https" else -1

    # 9–10. WHOIS / favicon require external lookup — default neutral
    Domain_reg_len = 1
    Favicon = 1

    # 11. Non-standard port in URL
    raw_netloc = urllib.parse.urlparse(raw).netloc
    port_val = -1 if re.search(r":\d{2,5}$", raw_netloc) else 1

    # 12. "https" token inside the domain name itself (e.g. https-paypal.com)
    HTTPS_token = -1 if "https" in netloc else 1

    # 13–16. Page content signals require fetching — default neutral
    Request_URL = 1
    URL_of_Anchor = 0
    Links_in_tags = 1
    SFH = 1

    # 17. mailto: in URL
    Submitting_to_email = -1 if "mailto:" in raw else 1

    # 18. Hostname absent from URL body
    # BUG FIX: strip www. from netloc before comparing so www.example.com
    # domains don't get a false phishing signal.
    bare_netloc = netloc.replace("www.", "")
    Abnormal_URL = -1 if bare_netloc and bare_netloc not in raw else 1

    # 19. Extra // beyond the protocol (redirect trick)
    # BUG FIX: was returning 1 (legit) when extra slashes found — should be -1.
    Redirect = -1 if raw.count("//") > 1 else 0

    # 20–30. Behavioral / external signals — default neutral
    on_mouseover = 1
    RightClick = 1
    popUpWidnow = 1
    Iframe = 1
    age_of_domain = 0
    DNSRecord = 0
    web_traffic = 0
    Page_Rank = -1
    Google_Index = 1
    Links_pointing = 0
    Statistical_report = 1

    return [
        having_IP, URL_Length, Shortining_Service, having_At,
        double_slash, Prefix_Suffix, having_Sub_Domain, SSLfinal_State,
        Domain_reg_len, Favicon, port_val, HTTPS_token,
        Request_URL, URL_of_Anchor, Links_in_tags, SFH,
        Submitting_to_email, Abnormal_URL, Redirect, on_mouseover,
        RightClick, popUpWidnow, Iframe, age_of_domain,
        DNSRecord, web_traffic, Page_Rank, Google_Index,
        Links_pointing, Statistical_report,
    ]


def get_feature_dict(url: str) -> dict:
    return dict(zip(FEATURE_NAMES, extract_features(url)))


def get_red_flags(url: str) -> list:
    f = get_feature_dict(url)
    flags = []
    if f["having_IP_Address"] == -1:
        flags.append("IP address used instead of a domain name")
    if f["having_At_Symbol"] == -1:
        flags.append("@ symbol present — browser ignores everything before it")
    if f["double_slash_redirecting"] == -1:
        flags.append("Double slash in path — possible redirect trick")
    if f["Prefix_Suffix"] == -1:
        flags.append("Hyphen in domain — common fake-domain pattern (e.g. paypal-secure.com)")
    if f["having_Sub_Domain"] == -1:
        flags.append("Excessive subdomains — obscures the real domain")
    if f["SSLfinal_State"] == -1:
        flags.append("No HTTPS")
    if f["Shortining_Service"] == -1:
        flags.append("URL shortener — true destination is hidden")
    if f["HTTPS_token"] == -1:
        flags.append("'https' in domain name itself — spoofing trust signals")
    if f["port"] == -1:
        flags.append("Non-standard port in URL")
    if f["Submitting_to_email"] == -1:
        flags.append("mailto: found in URL — data routes to an email address")
    if len(url) > 75:
        flags.append(f"URL is {len(url)} characters — long URLs bury malicious paths")
    return flags
