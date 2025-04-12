import urllib.request              # 외부 URL 요청 (ex. Alexa 순위)
from urllib.parse import urlparse # URL 구조 분석 (scheme, netloc 등)
import requests                    # HTTP 요청 (웹 페이지 HTML 받기)

from bs4 import BeautifulSoup      # HTML 파싱

import re                          # 정규표현식 처리

import ipaddress                   # 문자열이 IP주소인지 판별
import socket                      # 도메인 → IP 변환
import whois                       # 도메인 등록 정보 (생성일, 만료일 등)

from datetime import date, datetime     # 날짜/시간 객체
import time                             # 시간 지연 (현재 코드에서는 사용 X)
from dateutil.parser import parse as date_parse # 문자열 → 날짜 객체

from googlesearch import search         # Google 검색 결과 확인

import pandas as pd                     # (현재 사용 X) 피처 결과 저장/로딩용
# from google.colab import drive          # Colab에서 Google Drive 마운트
# drive.mount('/content/gdrive', force_remount=True)
# filepath = '/content/gdrive/My Drive/' + '/csv/'

class FeatureExtraction:
    features = []
    def __init__(self,url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        self.features.append(self.uses_ip_address())
        self.features.append(self.is_url_too_long())
        self.features.append(self.uses_shortening_service())
        self.features.append(self.has_at_symbol())
        self.features.append(self.has_double_slash_redirect())
        self.features.append(self.has_prefix_suffix_in_domain())
        self.features.append(self.has_many_subdomains())
        self.features.append(self.uses_https())
        self.features.append(self.is_domain_registration_short())
        self.features.append(self.has_external_favicon())

    # 1. IP 주소 사용 여부 확인 (도메인 대신 IP면 피싱 의심)
    def uses_ip_address(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    # 2. URL 길이가 너무 긴 경우 (짧으면 정상, 너무 길면 피싱 의심)
    def is_url_too_long(self):
        if len(self.url) < 54:
            return 1
        if 54 <= len(self.url) <= 75:
            return 0
        return -1

    # 3. 단축 URL 서비스 사용 여부 (bit.ly, tinyurl 등 → 피싱 가능성↑)
    def uses_shortening_service(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',
                          self.url)
        if match:
            return -1
        return 1

    # 4. @ 기호 포함 여부 (@ 이후 주소를 가려서 피싱 시도 가능)
    def has_at_symbol(self):
        if re.findall("@", self.url):
            return -1
        return 1

    # 5. URL 내 // 위치로 리디렉션 가능성 판단
    def has_double_slash_redirect(self):
        if self.url.rfind('//') > 6:
            return -1
        return 1

    # 6. 도메인에 하이픈(-)이 포함된 경우 (피싱 도메인 특징 중 하나)
    def has_prefix_suffix_in_domain(self):
        try:
            match = re.findall('-', self.domain)
            if match:
                return -1
            return 1
        except:
            return -1

    # 7. 서브도메인의 개수가 많은 경우 (피싱 사이트에서 자주 보임)
    def has_many_subdomains(self):
        dot_count = len(re.findall("\.", self.url))
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8. HTTPS 사용 여부 (보안 접속이면 정상 가능성↑)
    def uses_https(self):
        try:
            https = self.urlparse.scheme
            if 'https' in https:
                return 1
            return -1
        except:
            return 1

    # 9. 도메인 등록 기간이 짧은 경우 (신뢰도 낮음)
    def is_domain_registration_short(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            try:
                if len(expiration_date):
                    expiration_date = expiration_date[0]
            except:
                pass
            try:
                if len(creation_date):
                    creation_date = creation_date[0]
            except:
                pass

            age = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
            if age >= 12:
                return 1
            return -1
        except:
            return -1

    # 10. 파비콘(favicon)이 외부 도메인에서 로드되는지 여부
    def has_external_favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for head.link in self.soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if self.url in head.link['href'] or len(dots) == 1 or self.domain in head.link['href']:
                        return 1
            return -1
        except:
            return -1
