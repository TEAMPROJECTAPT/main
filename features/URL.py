import pandas as pd
import requests
from tqdm import tqdm

def to_valid_url(domain):
    headers = {"User-Agent": "Mozilla/5.0"}
    for scheme in ["https://", "http://"]:
        try:
            res = requests.get(scheme + domain, timeout=5)
            if res.status_code < 400:
                return scheme + domain
        except:
            continue
    return None

# 1. CSV 파일 불러오기
df = pd.read_csv("top1.csv", header=None)
df.columns = ["Rank", "Domain"]

# 2. 상위 N개만 테스트
N = 15000  
df = df.head(N)

# 3. 유효한 URL만 저장
valid_data = []
for domain in tqdm(df["Domain"], desc="Checking URLs"):
    valid_url = to_valid_url(domain)
    if valid_url:
        valid_data.append([valid_url, 1])  # label = 1

# 4. DataFrame 저장
result_df = pd.DataFrame(valid_data, columns=["URL", "label"])
result_df.to_csv("valid.csv", index=False)

print(f"\n 저장 완료: 총 {len(valid_data)}개 유효 URL")