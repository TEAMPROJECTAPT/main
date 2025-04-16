#로컬 환경에서 돌리기 위한 코드
#수정 필요함 

import pandas as pd
from tqdm import tqdm
import concurrent.futures
import os
from features import FeatureExtraction  
from concurrent.futures import ThreadPoolExecutor  

# 병렬 함수
def extract_features_safe(url):
    try:
        extractor = FeatureExtraction(url)
        return extractor.getFeaturesList()
    except:
        return [0] * 27

def parallel_feature_extraction(url_list, max_workers=16):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:  
        for features in tqdm(executor.map(extract_features_safe, url_list), total=len(url_list)):
            results.append(features)
    return results


if __name__ == "__main__":
    input_path = r""
    output_path = r""

    df = pd.read_csv(input_path, encoding="cp949")
    url_list = df["URL"].tolist()
    labels = df["label"].reset_index(drop=True)

    features_list = parallel_feature_extraction(url_list)

    columns = [
        "Index", "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//", "PrefixSuffix-", "SubDomains",
        "HTTPS", "Favicon", "NonStdPort", "HTTPSDomainURL", "RequestURL", "AnchorURL", "LinksInScriptTags",
        "ServerFormHandler", "InfoEmail", "AbnormalURL", "WebsiteForwarding", "StatusBarCust",
        "DisableRightClick", "UsingPopupWindow", "IframeRedirection", "WebsiteTraffic", "PageRank",
        "GoogleIndex", "LinksPointingToPage", "StatsReport", "label"
    ]

    feature_df = pd.DataFrame(features_list, columns=columns[1:-1])
    feature_df.insert(0, "Index", range(1, len(feature_df) + 1))
    feature_df["label"] = labels
    feature_df.to_csv(output_path, index=False, encoding="utf-8-sig")

    print("전처리 완료", output_path)
