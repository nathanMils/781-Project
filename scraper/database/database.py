import sqlite3
import csv

def create_database_from_csv(csv_file, db_file):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS domains (
            Rank INTEGER,
            Domain TEXT,
            OpenPageRank REAL
        )
    """)

    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            rank = row[0]
            domain = row[1]
            open_page_rank = row[2]
            cursor.execute("INSERT INTO domains (Rank, Domain, OpenPageRank) VALUES (?, ?, ?)", (rank, domain, open_page_rank))

    conn.commit()
    conn.close()

csv_file = './data/top_million/top10milliondomains.csv'
db_file = './scrapper/database/domains.db'
create_database_from_csv(csv_file, db_file)