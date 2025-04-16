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
#from google.colab import drive          # Colab에서 Google Drive 마운트
#drive.mount('/content/gdrive', force_remount=True)
#filepath = '/content/gdrive/My Drive/' + '/csv/'

# AbnormalURL -1
# WebsiteTraffic -1
# PageRank -1
# GoogleIndex 1
# 해당 피쳐 수정 필요
# 현재 특징 추출에서 정적인 부분, 동적인 부분 총 30개의 특징을 추출하는데 수정 필요. 동적인 부분에서의 시간 소요가 너무 큼
# url 당 요청 - 응답시 시간이 오래걸림. url 문자열에서 특징 추출해도 탐지율 높음.

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
            self.response = requests.get(url, timeout=3)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        # WHOIS는 현재 사용하지 않으므로 None 고정
        self.whois_response = None

        self.features.append(self.uses_ip_address())
        self.features.append(self.is_url_too_long())
        self.features.append(self.uses_shortening_service())
        self.features.append(self.has_at_symbol())
        self.features.append(self.has_double_slash_redirect())
        self.features.append(self.has_prefix_suffix_in_domain())
        self.features.append(self.has_many_subdomains())
        self.features.append(self.uses_https())
        #self.features.append(self.is_domain_registration_short())
        self.features.append(self.has_external_favicon())

        self.features.append(self.uses_non_standard_port())
        self.features.append(self.has_https_in_domain())
        self.features.append(self.check_external_resource_ratio())
        self.features.append(self.check_anchor_tag_safety())
        self.features.append(self.check_script_link_ratio())
        self.features.append(self.check_form_handler())
        self.features.append(self.has_email_submission())
        self.features.append(self.is_url_structure_abnormal())
        self.features.append(self.check_website_forwarding())
        self.features.append(self.has_status_bar_script())

        self.features.append(self.has_disabled_right_click())
        self.features.append(self.uses_popup_window())
        self.features.append(self.has_iframe_redirection())
        #self.features.append(self.is_domain_old_enough())
        #self.features.append(self.has_dns_record())
        self.features.append(self.has_high_traffic_rank())
        self.features.append(self.check_page_rank())
        self.features.append(self.is_google_indexed())
        self.features.append(self.check_links_pointing_to_page())
        self.features.append(self.check_blacklist_status())

    # 1. IP 주소 사용 여부 확인
    def uses_ip_address(self):
        try:
            hostname = urlparse(self.url).hostname      #hostname==url(포트 삭제)
            ipaddress.ip_address(hostname)
            return -1
        except:
            return 1

    # 2. URL 길이가 너무 긴 경우
    def is_url_too_long(self):
        if len(self.url) < 54:
            return 1
        if 54 <= len(self.url) <= 75:
            return 0
        return -1

    # 3. 단축 URL 서비스 사용 여부
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

    # 4. @ 기호 포함 여부
    def has_at_symbol(self):
        if re.findall("@", self.url):
            return -1
        return 1

    # 5. URL 내 // 위치로 리디렉션 가능성 판단
    def has_double_slash_redirect(self):
        if self.url.rfind('//') > 6:
            return -1
        return 1

    # 6. 도메인에 하이픈(-)이 포함된 경우
    def has_prefix_suffix_in_domain(self):
        try:
            match = re.findall('-', self.domain)
            if match:
                return -1
            return 1
        except:
            return -1

    # 7. 서브도메인의 개수가 많은 경우
    def has_many_subdomains(self):
        dot_count = len(re.findall("\.", self.url))
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8. HTTPS 사용 여부
    def uses_https(self):
        try:
            https = self.urlparse.scheme
            if 'https' in https:
                return 1
            return -1
        except:
            return 1

   # 9. 도메인 등록 기간이 짧은 경우
    def is_domain_registration_short(self):
        try:
            if not self.whois_response:
                return -1
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date

            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

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
        
    # 11. 비표준 포트 사용 여부 
    def uses_non_standard_port(self):
        try:
            port = self.domain.split(":")
            if len(port) > 1:
                return -1
            return 1
        except:
            return -1

    # 12. 도메인명에 'https' 문자열 포함 여부 
    def has_https_in_domain(self):
        try:
            if 'https' in self.domain:
                return -1
            return 1
        except:
            return -1

    # 13. 외부 객체 요청 URL 비율 
    def check_external_resource_ratio(self):
        try:
            success = 0
            i = 0
            for tag in ['img', 'audio', 'embed', 'iframe']:
                for res in self.soup.find_all(tag, src=True):
                    dots = [x.start(0) for x in re.finditer('\.', res['src'])]
                    if self.url in res['src'] or self.domain in res['src'] or len(dots) == 1:
                        success += 1
                    i += 1

            try:
                percentage = success / float(i) * 100
                if percentage < 22.0:
                    return 1
                elif 22.0 <= percentage < 61.0:
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1

    # 14. <a> 태그 링크의 안전성 판단
    def check_anchor_tag_safety(self):
        try:
            i, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (self.url in a['href'] or self.domain in a['href']):
                    unsafe += 1
                i += 1

            try:
                percentage = unsafe / float(i) * 100
                if percentage < 31.0:
                    return 1
                elif 31.0 <= percentage < 67.0:
                    return 0
                else:
                    return -1
            except:
                return -1
        except:
            return -1

    # 15. <script>, <link> 태그 내 외부 리소스 비율
    def check_script_link_ratio(self):
        try:
            i, success = 0, 0

            for tag in ['link', 'script']:
                attr = 'href' if tag == 'link' else 'src'
                for res in self.soup.find_all(tag, **{attr: True}):
                    dots = [x.start(0) for x in re.finditer('\.', res[attr])]
                    if self.url in res[attr] or self.domain in res[attr] or len(dots) == 1:
                        success += 1
                    i += 1

            try:
                percentage = success / float(i) * 100
                if percentage < 17.0:
                    return 1
                elif 17.0 <= percentage < 81.0:
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1

    # 16. <form> 태그의 action 속성 분석
    def check_form_handler(self):
        try:
            forms = self.soup.find_all('form', action=True)
            if len(forms) == 0:
                return 1
            for form in forms:
                action = form['action']
                if action == "" or action == "about:blank":
                    return -1
                elif self.url not in action and self.domain not in action:
                    return 0
                else:
                    return 1
        except:
            return -1

    # 17. 페이지 내 이메일 주소 수집 시도
    def has_email_submission(self):
        try:
            if re.findall(r"[mail\(\)|mailto:?]", self.soup.text):
                return -1
            return 1
        except:
            return -1

    # 18. WHOIS 정보와 HTML 응답이 동일한지
    def is_url_structure_abnormal(self):
        try:
            if not self.whois_response or not self.response:
                return -1 # 정상
            # WHOIS 정보에 HTML 구조가 포함되면 이상하다고 판단     
            whois_lower = self.whois_response.lower()   #html 태그 대소문자 구분 없음==> lower()
            if "<html" in whois_lower or "<!doctype html" in whois_lower:
                return 1  # 비정상
            return -1
        except:
            return -1

    # 19. 리디렉션 횟수 기반 의심 판단
    def check_website_forwarding(self):
        try:
            history_len = len(self.response.history)
            if history_len <= 1:
                return 1
            elif history_len <= 4:
                return 0
            else:
                return -1
        except:
            return -1

    # 20. 마우스 오버로 상태 표시줄을 조작하는 스크립트 존재 여부
    def has_status_bar_script(self):
        try:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                return 1
            return -1
        except:
            return -1
        
          # 21. 오른쪽 클릭 금지 스크립트 존재 여부
    def has_disabled_right_click(self):
        try:
            if re.findall(r"event.button ?== ?2", self.response.text):
                return 1
            return -1
        except:
            return -1

    # 22. 팝업(alert) 창 사용 여부
    def uses_popup_window(self):
        try:
            if re.findall(r"alert\(", self.response.text):
                return 1
            return -1
        except:
            return -1

    # 23. iframe 또는 frameBorder 태그 존재 여부
    def has_iframe_redirection(self):
        try:
            if re.findall(r"[<iframe>|<frameBorder>]", self.response.text):
                return 1
            return -1
        except:
            return -1

    # 24. 도메인 나이가 6개월 이상인지 확인
    def is_domain_old_enough(self):
        try:
            if not self.whois_response:
                return -1
            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            today = date.today()
            age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            if age >= 6:
                return 1
            return -1
        except:
            return -1

    # 25. DNS 레코드 기록 존재 여부
    def has_dns_record(self):
        try:
            if not self.whois_response:
                return -1
            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            today = date.today()
            age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            if age >= 6:
                return 1
            return -1
        except:
            return -1

    # 26. SimilarWeb 웹사이트 트래픽 순위 확인      #Alexa 사이트 폐쇄
    class TrafficChecker:
        def __init__(self, url, api_key):
            self.url = url
            self.api_key = api_key

    def has_high_traffic_rank(self):
        try:
            # SimilarWeb API를 사용하여 트래픽 정보 가져오기
            api_url = f"https://api.similarweb.com/v1/website/{self.url}/traffic"
            headers = {
                "Authorization": f"Bearer {self.api_key}"
            }
            response = requests.get(api_url, headers=headers)
            data = response.json()

            # 트래픽 순위 가져오기
            rank = data.get("rank", None)
            if rank and rank < 100000:
                return 1
            return 0
        except:
            return -1

    # 27. PageRank 순위가 낮은지 확인   # html request.post 요청 5초가 안전, global_rank=100만으로 변경
    def check_page_rank(self):
        try:
            if not self.domain:
                return -1
            prank_checker_response = requests.post(
                "https://www.checkpagerank.net/index.php",
                {"name": self.domain},
                timeout=5
            )
            
            match = re.findall(r"Global Rank: ([0-9]+)", prank_checker_response.text)
            if match:
                global_rank = int(match[0])
                if 0 < global_rank < 1000000:
                    return 1
            return -1
        except:
            -1

    # 28. 구글 검색 결과에 인덱싱 되어 있는지 확인
    def is_google_indexed(self):
        try:
            results = list(search(self.url, num=5))
            return 1 if results else -1
        except Exception as e:
            return 0  # 에러 발생 시 미정 처리

    # 29. 페이지 내 링크 개수 확인
    def check_links_pointing_to_page(self):
        try:
            number_of_links = len(re.findall(r"<a href=", self.response.text))
            if number_of_links == 0:
                return 1
            elif number_of_links <= 2:
                return 0
            else:
                return -1
        except:
            return -1

    # 30. URL 또는 IP가 블랙리스트에 포함되는지 확인
    def check_blacklist_status(self):
        try:
            # 1. 블랙리스트 URL 패턴 (도메인 내 포함 여부)
            url_blacklist_pattern = (
                r"at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|"
                r"sweddy\.com|myjino\.ru|96\.lt|ow\.ly"
            )
            url_match = re.search(url_blacklist_pattern, self.url)

            # 2. 블랙리스트 IP 패턴 (도메인 IP 변환 후 일치 확인)
            try:
                ip_address = socket.gethostbyname(self.domain)
                ip_blacklist_pattern = (
                    r"146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|"
                    r"181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|"
                    r"107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|"
                    r"107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|"
                    r"118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|"
                    r"141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|"
                    r"216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|"
                    r"213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|"
                    r"34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|"
                    r"198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|"
                    r"209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|54\.86\.225\.156|"
                    r"54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42"
                )
                ip_match = re.search(ip_blacklist_pattern, ip_address)
            except:
                ip_match = False  # IP 변환 실패 시 IP 블랙리스트 검사 생략

            # 3. 둘 중 하나라도 매치되면 피싱으로 간주
            if url_match or ip_match:
                return -1
            return 1
        except:
            return 0  # 판단 불가한 경우는 중립값 반환
        
    def getFeaturesList(self):
            return self.features