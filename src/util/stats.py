import matplotlib.pyplot as plt
import seaborn as sns

import logging

logger = logging.getLogger('util.stats')

def mapping_function(feature_name, value):
    mappings = {
        "having_ip_address": {
            -1: "Phishing (Domain has an IP address)",
            1: "Legitimate (Domain does not have an IP address)"
        },
        "url_length": {
            1: "Legitimate (URL length < 54)",
            0: "Suspicious (54 ≤ URL length ≤ 75)",
            -1: "Phishing (URL length > 75)"
        },
        "shortining_service": {
            1: "Legitimate (Does not use a shortening service)",
            -1: "Phishing (Uses a shortening service)"
        },
        "having_at_symbol": {
            1: "Phishing (URL contains '@' symbol)",
            -1: "Legitimate (URL does not contain '@' symbol)"
        },
        "double_slash_redirecting": {
            -1: "Phishing (Last occurrence of '//' > 7)",
            1: "Legitimate (Last occurrence of '//' ≤ 7)"
        },
        "prefix_suffix": {
            -1: "Phishing (URL starts/ends with hyphen/dot)",
            1: "Legitimate (URL does not start/end with hyphen/dot)"
        },
        "having_sub_domain": {
            -1: "Phishing (URL has more than one subdomain)",
            0: "Suspicious (URL has a single subdomain)",
            1: "Legitimate (URL has no subdomain)"
        },
        "sslfinal_state": {
            -1: "Phishing (SSL certificate is not valid or does not exist)",
            0: "Suspicious (SSL certificate is valid but not fully secured)",
            1: "Legitimate (SSL certificate is valid and fully secured)"
        },
        "domain_registration_length": {
            -1: "Phishing (Domain registration < 6 months)",
            1: "Legitimate (Domain registration ≥ 6 months)"
        },
        "favicon": {
            1: "Legitimate (Favicon exists and is legitimate)",
            -1: "Phishing (Favicon is missing or suspicious)"
        },
        "port": {
            1: "Legitimate (Uses standard ports like 80, 443)",
            -1: "Phishing (Uses non-standard ports)"
        },
        "https_token": {
            -1: "Phishing (No 'https' or mixed content)",
            1: "Legitimate (Contains 'https' and no mixed content)"
        },
        "request_url": {
            1: "Legitimate (Request URL is legitimate)",
            -1: "Phishing (Request URL is not legitimate)"
        },
        "url_of_anchor": {
            -1: "Phishing (Anchor text is misleading or no description)",
            0: "Suspicious (Anchor text is generic or neutral)",
            1: "Legitimate (Anchor text is descriptive)"
        },
        "links_in_tags": {
            1: "Legitimate (No links or links point to legitimate sites)",
            -1: "Phishing (Links point to suspicious sites)",
            0: "Suspicious (Links in tags are neutral)"
        },
        "sfh": {
            -1: "Phishing (Form action does not point to a legitimate site)",
            0: "Suspicious (Form action points to a generic form handler)",
            1: "Legitimate (Form action points to a legitimate site)"
        },
        "submitting_to_email": {
            -1: "Phishing (Form submits data to an email address)",
            1: "Legitimate (Form does not submit data to an email address)"
        },
        "abnormal_url": {
            -1: "Phishing (URL contains unusual characters or patterns)",
            1: "Legitimate (URL does not contain unusual characters or patterns)"
        },
        "redirect": {
            0: "Suspicious (URL performs redirection)",
            1: "Legitimate (URL does not perform redirection)"
        },
        "on_mouseover": {
            1: "Legitimate (Mouseover event is not suspicious)",
            -1: "Phishing (Mouseover event triggers suspicious behavior)"
        },
        "rightclick": {
            1: "Legitimate (Right-click is enabled)",
            -1: "Phishing (Right-click is disabled)"
        },
        "popupwindow": {
            1: "Legitimate (Pop-up windows require user action)",
            -1: "Phishing (Pop-up windows generated without user action)"
        },
        "iframe": {
            1: "Legitimate (Uses iframes from the same domain)",
            -1: "Phishing (Uses iframes from different domains)"
        },
        "age_of_domain": {
            -1: "Phishing (Domain is less than 6 months old)",
            1: "Legitimate (Domain is ≥ 6 months old)"
        },
        "dnsrecord": {
            -1: "Phishing (No DNS record or suspicious DNS record)",
            1: "Legitimate (Valid DNS record)"
        },
        "web_traffic": {
            -1: "Phishing (Low or no web traffic)",
            0: "Suspicious (Moderate web traffic)",
            1: "Legitimate (High web traffic)"
        },
        "page_rank": {
            -1: "Phishing (Low or no page rank)",
            1: "Legitimate (High page rank)"
        },
        "google_index": {
            1: "Legitimate (Indexed by Google)",
            -1: "Phishing (Not indexed by Google)"
        },
        "links_pointing_to_page": {
            1: "Legitimate (Many legitimate links pointing to the page)",
            0: "Suspicious (Few links pointing to the page)",
            -1: "Phishing (Few or no legitimate links pointing to the page)"
        },
        "statistical_report": {
            -1: "Phishing (Indicates malicious behavior)",
            1: "Legitimate (Indicates legitimate behavior)"
        },
        "result": {
            -1: "Phishing",
            1: "Legitimate"
        }
    }
    
    if feature_name in mappings:
        if value in mappings[feature_name]:
            return mappings[feature_name][value]
        else:
            return "Unknown value"
    else:
        return "Unknown feature"

IMAGES_DIR = "../../docs/images"

def draw_pie(data, feature, dimensions=(6, 6)):
    logger.info(f"Drawing pie chart for '{feature}'")
    data = data[feature].value_counts(normalize=True)
    labels = [f"{mapping_function(feature, value)}" for value, _ in data.items()]
    plt.figure(figsize=dimensions)
    plt.pie(data, labels=labels, autopct='%1.1f%%', colors=["#66c2a5", "#fc8d62", "#8da0cb"])
    plt.title(f"Distribution of '{feature}'")
    image_path = f"{IMAGES_DIR}/{feature}_distribution.png"
    plt.savefig(image_path)
    logger.info(f"Pie chart saved to '{image_path}'")