import pandas as pd
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

# CSV 경로
CSV_PATH = os.path.join("..", "csv", "verified_online.csv")
SAVE_PATH = os.path.join("..", "csv", "alive_phishing_urls.csv")

def is_url_alive(row):
    url = row['url']
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        if response.status_code < 400:
            print(f"[ALIVE] {url}")
            return row
    except Exception:
        pass
    print(f"[DEAD] {url}")
    return None

def main():
    df = pd.read_csv(CSV_PATH)
    print(f"✅ 총 URL 수: {len(df)}개")

    alive_rows = []
    max_threads = 20

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(is_url_alive, row) for _, row in df.iterrows()]
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                alive_rows.append(result)

    # URL과 제출 시간만 저장
    alive_df = pd.DataFrame(alive_rows)
    alive_df[['url', 'submission_time']].to_csv(SAVE_PATH, index=False)
    print(f"\n✅ 살아있는 URL: {len(alive_df)}개 저장 완료!")
    print(f"📁 저장 위치: {SAVE_PATH}")

if __name__ == "__main__":
    main()