#!/usr/bin/env python
import pandas as pd

def main():
    ips_df = pd.read_csv("top_ips.csv")
    uas_df = pd.read_csv("top_user_agents.csv")

    # Column discovery
    ip_col, ip_count_col = ips_df.columns
    ua_col, ua_count_col = uas_df.columns

    # 1) Suspect IPs: >75th percentile
    ip_threshold = ips_df[ip_count_col].quantile(0.75)
    suspect_ips = ips_df[ips_df[ip_count_col] > ip_threshold]

    # 2) Suspect UAs by keyword OR empty UA
    bot_keywords = ["bot", "crawl", "spider", "slurp", "archiver", "feedfetcher"]
    keyword_mask = uas_df[ua_col].str.lower().str.contains("|".join(bot_keywords), na=False)
    empty_mask   = uas_df[ua_col].fillna("").str.strip().isin(["", "-"])
    # 3) Suspect high-volume UA as well (optional)
    ua_threshold = uas_df[ua_count_col].quantile(0.75)
    volume_mask  = uas_df[ua_count_col] > ua_threshold

    suspect_uas = uas_df[keyword_mask | empty_mask | volume_mask]

    # Output
    print("=== Suspect IPs ===")
    print(suspect_ips.to_string(index=False))

    print("\n=== Suspect User‑Agents ===")
    print(suspect_uas.to_string(index=False))

    suspect_ips.to_csv("suspect_ips.csv", index=False)
    suspect_uas.to_csv("suspect_user_agents.csv", index=False)
    print("\nSaved suspect_ips.csv and suspect_user_agents.csv")

if __name__ == "__main__":
    main()
