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
