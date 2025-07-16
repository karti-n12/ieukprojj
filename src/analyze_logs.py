#!/usr/bin/env python
import re
import argparse
import os
from collections import Counter
import pandas as pd

# Regex for Apache/Nginx‑style access log
LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s*-\s*(?P<country>\w+)\s*-\s*'
    r'\[(?P<timestamp>[^\]]+)\]\s*'
    r'"(?P<method>\w+)\s+(?P<url>\S+)\s+HTTP/[0-9.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s*'
    r'"(?P<user_agent>[^"]+)"'
)

def parse_log_file(filepath):
    ip_counts = Counter()
    url_counts = Counter()
    ua_counts = Counter()

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = LOG_PATTERN.search(line)
            if not m:
                continue
            ip_counts[m.group('ip')] += 1
            url_counts[m.group('url')] += 1
            ua_counts[m.group('user_agent')] += 1

    return ip_counts, url_counts, ua_counts

def main():
    p = argparse.ArgumentParser(description="Analyze web server access logs.")
    p.add_argument("logfile", help="Path to the access log file")
    args = p.parse_args()

    if not os.path.isfile(args.logfile):
        print(f"Error: file not found: {args.logfile}")
        return

    ips, urls, uas = parse_log_file(args.logfile)

    # Top‑10 DataFrames
    df_ips = pd.DataFrame(ips.most_common(10), columns=['IP Address', 'Request Count'])
    df_urls = pd.DataFrame(urls.most_common(10), columns=['URL', 'Hit Count'])
    df_uas = pd.DataFrame(uas.most_common(10), columns=['User-Agent', 'Count'])

    # Print to console
    print("\nTop 10 IP Addresses by Request Count:")
    print(df_ips.to_string(index=False))

    print("\nTop 10 Requested URLs:")
    print(df_urls.to_string(index=False))

    print("\nTop 10 User-Agent Strings:")
    print(df_uas.to_string(index=False))

    # Save CSVs
    df_ips.to_csv("top_ips.csv", index=False)
    df_urls.to_csv("top_urls.csv", index=False)
    df_uas.to_csv("top_user_agents.csv", index=False)
    print("\nResults saved to top_ips.csv, top_urls.csv, top_user_agents.csv")

if __name__ == "__main__":
    main()
