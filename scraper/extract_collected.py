import csv
import json

input_json_file = './data/collected/collected_phish_data.json'
output_csv_file = 'output.csv'

headers = [
    "id", "timestamp", "open_rank_domain", "page_rank_integer", "page_rank_decimal", 
    "website_url", "having_ip_address", "url_length", "shortining_service", "having_at_symbol", 
    "double_slash_redirecting", "prefix_suffix", "having_sub_domain", "sslfinal_state", 
    "domain_registration_length", "favicon", "port", "https_token", "request_url", 
    "url_of_anchor", "links_in_tags", "sfh", "submitting_to_email", "abnormal_url", "redirect", 
    "on_mouseover", "rightclick", "popupwindow", "iframe", "age_of_domain", "dnsrecord", "web_traffic", 
    "page_rank", "google_index", "links_pointing_to_page", "statistical_report", "result"
]

with open(input_json_file, 'r') as file:
    data = json.load(file)

with open(output_csv_file, mode='w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=headers)
    writer.writeheader()
    
    for entry in data:
        open_rank = entry['open_rank']['response'][0]
        
        data_features = entry['data']
        
        row = {
            "id": entry["id"],
            "timestamp": entry["timestamp"],
            "open_rank_domain": open_rank["domain"],
            "page_rank_integer": open_rank["page_rank_integer"],
            "page_rank_decimal": open_rank["page_rank_decimal"],
        }
        
        row.update(data_features)
        
        writer.writerow(row)

print(f"Data has been written to {output_csv_file}")
