import pandas as pd
import joblib
import os
import warnings
import sys


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tqdm import tqdm
from features.extract_features_1_22 import FeatureExtraction
from features.extract_features_23_26 import (
    extract_domain,
    google_safe_browsing_check,
    detect_bitdefender,
    whois_registered,
    download_latest_tranco,
    tranco_rank
)

# ─────────── 경고 제거 ───────────
warnings.filterwarnings("ignore")

# ────────────────── 경로 설정 ──────────────────
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

MODEL_PATH = os.path.join(BASE_DIR, "train_models", "vc_model.pkl")
PREPROCESSOR_PATH = os.path.join(BASE_DIR, "train_models", "vc_preprocessor.pkl")

# ───────────── 모델 및 전처리 로드 ─────────────
model = joblib.load(MODEL_PATH)
preprocessor = joblib.load(PREPROCESSOR_PATH)

# ───────────── 정적 특징 진행률 ─────────────
STATIC_FEATURE_NAMES = [
    "uses_ip_address", "is_url_too_long", "uses_shortening_service", "has_at_symbol",
    "has_prefix_suffix_in_domain", "has_many_subdomains", "has_https_in_scheme",
    "has_external_favicon", "check_external_resource_ratio", "check_anchor_tag_safety",
    "check_script_link_ratio", "check_form_handler", "has_email_submission",
    "check_website_forwarding", "uses_popup_window", "has_iframe_redirection",
    "check_links_pointing_to_page", "has_suspicious_words_in_url", "count_digits_in_url",
    "meta_refresh_exists", "has_password_input", "external_script_ratio"
]

def extract_static_features_with_tqdm(url):
    extractor = FeatureExtraction(url)
    features = []
    pbar = tqdm(total=len(STATIC_FEATURE_NAMES), desc="📘 정적 특징 추출 진행", ncols=100)
    for name in STATIC_FEATURE_NAMES:
        features.append(getattr(extractor, name)())
        pbar.update(1)
    pbar.close()
    return features

# ───────────── 외부 서비스 특징 진행률 ─────────────
def get_external_features_with_cache(url):
    domain = extract_domain(url)
    steps = [
        "Google Safe Browsing",
        "Bitdefender TrafficLight",
        "WHOIS 등록 여부",
        "Tranco Rank"
    ]
    pbar = tqdm(total=len(steps), desc="🌐 외부 특징 추출 진행", ncols=100)

    gsb = google_safe_browsing_check(url)
    pbar.update(1)
    bd = detect_bitdefender(domain)[1]
    pbar.update(1)
    whois_r = whois_registered(domain)
    pbar.update(1)

    tranco_dict = download_latest_tranco()
    tranco_r = tranco_rank(domain, tranco_dict)
    pbar.update(1)
    pbar.close()

    return [gsb, tranco_r, bd, whois_r]

# ───────────── 예측 함수 ─────────────
def predict_url_phishing(url):
    print(f"\n🔍 입력된 URL: {url}")
    static_features = extract_static_features_with_tqdm(url)
    external_features = get_external_features_with_cache(url)
    full_features = static_features + external_features

    df_input = pd.DataFrame([full_features], columns=preprocessor.feature_names_in_)
    scaled_features = preprocessor.transform(df_input)
    df_scaled = pd.DataFrame(scaled_features, columns=preprocessor.feature_names_in_)

    prediction = model.predict(df_scaled)[0]
    return "🔴 피싱 사이트" if prediction == -1 else "🟢 정상 사이트"

# ──────────────── 사용자 입력 기반 실행 ────────────────
if __name__ == "__main__":
    url = input("🔎 검사할 URL을 입력하세요: ").strip()
    if url:
        result = predict_url_phishing(url)
        print(f"\n[결과] {url} → {result}")
    else:
        print("❗ URL을 입력하지 않았습니다.")
