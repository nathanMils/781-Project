import pandas as pd

from enum import Enum

class Encoding(Enum):
    BINARY = 0
    TERNARY = 1

attributes_encoding = [
    {"attribute": "having_ip_address", "encoding": Encoding.BINARY},                            # { -1, 1 }
    {"attribute": "url_length", "encoding": Encoding.TERNARY},                                  # { 1, 0, -1 }
    {"attribute": "shortining_service", "encoding": Encoding.BINARY},                           # { 1, -1 }
    {"attribute": "having_at_symbol", "encoding": Encoding.BINARY},                             # { 1, -1 }
    {"attribute": "double_slash_redirecting", "encoding": Encoding.BINARY},                     # { -1, 1 }
    {"attribute": "prefix_suffix", "encoding": Encoding.BINARY},                                # { -1, 1 }
    {"attribute": "having_sub_domain", "encoding": Encoding.TERNARY},                           # { -1, 0, 1 }
    {"attribute": "sslfinal_state", "encoding": Encoding.TERNARY},                              # { -1, 1, 0 }
    {"attribute": "domain_registration_length", "encoding": Encoding.BINARY},                   # { -1, 1 }
    {"attribute": "favicon", "encoding": Encoding.BINARY},                                      # { 1, -1 }
    {"attribute": "port", "encoding": Encoding.BINARY},                                         # { 1, -1 }
    {"attribute": "https_token", "encoding": Encoding.BINARY},                                  # { -1, 1 }
    {"attribute": "request_url", "encoding": Encoding.BINARY},                                  # { 1, -1 }
    {"attribute": "url_of_anchor", "encoding": Encoding.TERNARY},                               # { -1, 0, 1 }
    {"attribute": "links_in_tags", "encoding": Encoding.TERNARY},                               # { 1, -1, 0 }
    {"attribute": "sfh", "encoding": Encoding.TERNARY},                                         # { -1, 1, 0 }
    {"attribute": "submitting_to_email", "encoding": Encoding.BINARY},                          # { -1, 1 }
    {"attribute": "abnormal_url", "encoding": Encoding.BINARY},                                 # { -1, 1 }
    {"attribute": "redirect", "encoding": Encoding.BINARY},                                     # { 0, 1 }
    {"attribute": "on_mouseover", "encoding": Encoding.BINARY},                                 # { 1, -1 }
    {"attribute": "rightclick", "encoding": Encoding.BINARY},                                   # { 1, -1 }
    {"attribute": "popupwindow", "encoding": Encoding.BINARY},                                  # { 1, -1 }
    {"attribute": "iframe", "encoding": Encoding.BINARY},                                       # { 1, -1 }
    {"attribute": "age_of_domain", "encoding": Encoding.BINARY},                                # { -1, 1 }
    {"attribute": "dnsrecord", "encoding": Encoding.BINARY},                                    # { -1, 1 }
    {"attribute": "web_traffic", "encoding": Encoding.TERNARY},                                 # { -1, 0, 1 }
    {"attribute": "page_rank", "encoding": Encoding.BINARY},                                    # { -1, 1 }
    {"attribute": "google_index", "encoding": Encoding.BINARY},                                 # { 1, -1 }
    {"attribute": "links_pointing_to_page", "encoding": Encoding.TERNARY},                      # { 1, 0, -1 }
    {"attribute": "statistical_report", "encoding": Encoding.BINARY},                           # { -1, 1 }
    {"attribute": "result", "encoding": Encoding.BINARY},                                       # { -1, 1 }
]

def encode_data(data: pd.DataFrame) -> pd.DataFrame:
    encoding_map = {attr['attribute']: attr['encoding'] for attr in attributes_encoding}

    encoded_data = []
    for col in data.columns:
        if col in encoding_map:
            encoding = encoding_map[col]
            if encoding == Encoding.BINARY:
                encoded_data.append(data[col].map({-1: 0, 1: 1, 0: 0}).rename(col))
            elif encoding == Encoding.TERNARY:
                encoded_data.append(data[col].map({-1: -1, 0: 0, 1: 1}).rename(col))
            else:
                raise ValueError(f"Unsupported encoding type for attribute '{col}': {encoding}")
        else:
            print(f"Warning: No encoding specified for '{col}'. Including as-is.")
            encoded_data.append(data[col])

    return pd.concat(encoded_data, axis=1)


def map_to_boolean(data: pd.DataFrame) -> pd.DataFrame:
    encoded_data = encode_data(data.copy())
    encoding_map = {attr['attribute']: attr['encoding'] for attr in attributes_encoding}
    mapped_data = []
    for col in encoded_data.columns:
        if col in encoding_map:
            encoding = encoding_map[col]
            if encoding == Encoding.BINARY:
                mapped_data.append(encoded_data[col].map({0: False, 1: True}).rename(col))
            elif encoding == Encoding.TERNARY:
                mapped_data.append(encoded_data[col].rename(col))
        else:
            print(f"Warning: No encoding specified for '{col}'. Including as-is.")
            mapped_data.append(encoded_data[col])

    return pd.concat(mapped_data, axis=1)
        