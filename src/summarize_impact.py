import re
import pandas as pd
from collections import Counter

LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?"\w+\s+(?P<url>\S+)\s+HTTP/.*?"\s+\d+\s+\d+\s+"(?P<ua>[^"]+)"'
)

def load_suspects():
    ips = pd.read_csv("suspect_ips.csv")["IP Address"].tolist()
    uas = pd.read_csv("suspect_user_agents.csv")["User-Agent"].tolist()
    return set(ips), set(uas)

def summarize(logfile):
    total = 0
    bot_reqs = 0
    bot_url_counts = Counter()

    suspect_ips, suspect_uas = load_suspects()

    with open(logfile, 'r', errors='ignore') as f:
        for line in f:
            m = LOG_PATTERN.search(line)
            if not m:
                continue
            total += 1
            ip, url, ua = m.group('ip'), m.group('url'), m.group('ua')
            if ip in suspect_ips or ua in suspect_uas:
                bot_reqs += 1
                bot_url_counts[url] += 1

    print(f"Total requests: {total}")
    print(f"Bot requests:   {bot_reqs} ({bot_reqs/total:.1%})\n")

    print("Top 10 URLs hit by bots:")
    for url, cnt in bot_url_counts.most_common(10):
        print(f"  {url:40s} {cnt}")

if __name__ == "__main__":
    summarize("logs/sample-log.log")
