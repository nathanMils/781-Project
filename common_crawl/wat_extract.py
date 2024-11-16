from warcio.archiveiterator import ArchiveIterator
import gzip
import csv

warc_file = './common_crawl/wat_data/CC-MAIN-20241003094020-20241003124020-00118.warc.wat.gz'
csv_file = './common_crawl/extracted_urls.csv'

with gzip.open(warc_file, 'rb') as warc, open(csv_file, mode='w', newline='', encoding='utf-8') as csvfile:
    csv_writer = csv.writer(csvfile)
    
    csv_writer.writerow(['url'])
    
    for record in ArchiveIterator(warc):
        if record.rec_type == 'metadata':
            target_uri = record.rec_headers.get_header('WARC-Target-URI')
            if target_uri:
                csv_writer.writerow([target_uri])

print(f"URLs have been successfully extracted and saved to {csv_file}.")
