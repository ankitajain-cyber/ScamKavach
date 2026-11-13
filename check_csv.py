import csv
from collections import Counter

with open("dataset.csv", newline="", encoding="utf-8-sig") as f:
    rows = list(csv.DictReader(f))

print("Columns:", list(rows[0].keys()))
print("Rows:", len(rows))
for col in rows[0].keys():
    values = Counter(r[col] for r in rows)
    if len(values) <= 15:
        print(f"\n{col!r} values:", dict(values))
print("\nFirst row:", rows[0])