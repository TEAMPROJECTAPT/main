import pandas as pd
import requests
import whois
import time
import socket
from urllib.parse import urlparse
from multiprocessing import Manager, Process, Value
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
import os
import logging
import subprocess

# ──────────── 설정 ────────────
logging.getLogger("whois").setLevel(logging.CRITICAL)
socket.setdefaulttimeout(10)

GOOGLE_API_KEY = "Your API KEY"
API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

# ──────────── 도메인 추출 ────────────
def extract_domain(url):
    try:
        domain = urlparse(url).netloc.lower()
        return domain.replace("www.", "") if domain.startswith("www.") else domain
    except:
        return ""

# ──────────── Bitdefender (1:정상 / -1:악성 / 0:오류) ────────────
def detect_bitdefender(domain):
    try:
        url = f"https://trafficlight.bitdefender.com/info/?url=https%3A%2F%2F{domain}"
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--log-level=3")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--remote-debugging-pipe")
        
        options.add_experimental_option("excludeSwitches", ["enable-logging"])

        service = Service(log_path=os.devnull)
        service.creation_flags = subprocess.CREATE_NO_WINDOW  
        driver = webdriver.Chrome(options=options, service=service)
        driver.get(url)
        time.sleep(4)
        result = 0
        if driver.find_element(By.ID, "card-danger").get_attribute("class") != "d-none":
            result = -1
        elif driver.find_element(By.ID, "card-success").get_attribute("class") != "d-none":
            result = 1
        driver.quit()
        return domain, result
    except:
        return domain, 0

def run_bitdefender(domains, results, progress):
    def worker(domain):
        d, r = detect_bitdefender(domain)
        results[d] = r
        with progress.get_lock():
            progress.value += 1
    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(worker, domains)

# ──────────── WHOIS (1:등록됨 / -1:미등록 / 0:오류) ────────────
def whois_registered(domain):
    try:
        data = whois.whois(domain)
        return 1 if data.domain_name else -1
    except:
        return 0

def run_whois(domains, results, progress):
    for d in domains:
        results[d] = whois_registered(d)
        with progress.get_lock():
            progress.value += 1

# ──────────── Google Safe Browsing (1:정상 / -1:악성 / 0:오류) ────────────
def google_safe_browsing_check(url):
    try:
        body = {
            "client": {"clientId": "yourcompanyname", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        headers = {"Content-Type": "application/json"}
        res = requests.post(API_URL, json=body, headers=headers, timeout=5)
        return -1 if res.status_code == 200 and "matches" in res.json() else 1
    except:
        return 0

def run_google_safe_browsing(urls, results, progress):
    for url in urls:
        results[url] = google_safe_browsing_check(url)
        with progress.get_lock():
            progress.value += 1

# ──────────── Tranco Rank (-1:없음 / 정수:랭크) ────────────
def download_latest_tranco():
    url = "https://tranco-list.eu/top-1m.csv.zip"
    zip_path = "tranco_top1m.zip"
    csv_path = "top-1m.csv"
    res = requests.get(url)
    with open(zip_path, "wb") as f:
        f.write(res.content)
    import zipfile
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(".")
    os.remove(zip_path)
    df = pd.read_csv(csv_path, names=["rank", "domain"])
    return dict(zip(df["domain"], df["rank"]))

def tranco_rank(domain, tranco_dict):
    return tranco_dict.get(domain, -1)

def run_tranco(domains, tranco_dict, results, progress):
    for domain in domains:
        results[domain] = tranco_rank(domain, tranco_dict)
        with progress.get_lock():
            progress.value += 1

# ──────────── 메인 ────────────
if __name__ == "__main__":
    df = pd.read_csv("merged_dataset_30000.csv")        # 데이터셋 경로
    urls = df["URL"].dropna().unique().tolist()[:1000]  # 전체 사용 시 [:1000] 제거
    domains = [extract_domain(url) for url in urls]

    tranco_dict = download_latest_tranco()

    manager = Manager()
    bd_result = manager.dict()
    whois_result = manager.dict()
    gsb_result = manager.dict()
    tranco_result = manager.dict()
    bd_prog = Value("i", 0)
    whois_prog = Value("i", 0)
    gsb_prog = Value("i", 0)
    tranco_prog = Value("i", 0)

    # 동시 실행
    p1 = Process(target=run_bitdefender, args=(domains, bd_result, bd_prog))
    p2 = Process(target=run_whois, args=(domains, whois_result, whois_prog))
    p3 = Process(target=run_google_safe_browsing, args=(urls, gsb_result, gsb_prog))
    p4 = Process(target=run_tranco, args=(domains, tranco_dict, tranco_result, tranco_prog))

    p1.start(); p2.start(); p3.start(); p4.start()

    with tqdm(total=len(domains), desc="Bitdefender", position=0) as bar1, \
         tqdm(total=len(domains), desc="WHOIS", position=1) as bar2, \
         tqdm(total=len(urls), desc="Google Safe Browsing", position=2) as bar3, \
         tqdm(total=len(domains), desc="Tranco Rank", position=3) as bar4:

        while p1.is_alive() or p2.is_alive() or p3.is_alive() or p4.is_alive():
            bar1.n = bd_prog.value
            bar2.n = whois_prog.value
            bar3.n = gsb_prog.value
            bar4.n = tranco_prog.value
            bar1.refresh(); bar2.refresh(); bar3.refresh(); bar4.refresh()
            time.sleep(1)

    p1.join(); p2.join(); p3.join(); p4.join()
    bar1.close(); bar2.close(); bar3.close(); bar4.close()

    # 결과 병합 및 저장
    records = []
    for url, domain in zip(urls, domains):
        records.append({
            "url": url,
            "google_safe_browsing": gsb_result.get(url, 0),          # 1:정상 / -1:위험 / 0:오류
            "tranco_rank": tranco_result.get(domain, -1),            # 정수:순위 / -1:없음
            "bitdefender_trafficLight": bd_result.get(domain, 0),    # 1:정상 / -1:위험 / 0:오류
            "whois_registered": whois_result.get(domain, 0)          # 1:등록됨 / -1:없음 / 0:오류
        })

    pd.DataFrame(records).to_csv("external_service_features.csv", index=False)
    print("✅ 저장 완료: external_service_features.csv")
