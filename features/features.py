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

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())

     # 1.UsingIp
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    # 2.longUrl
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        return -1

