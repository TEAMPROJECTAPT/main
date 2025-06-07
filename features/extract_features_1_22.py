import re
import ipaddress
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import requests

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.urlparse = urlparse(url)
        self.domain = self.urlparse.netloc
        self.features = []

        try:
            self.response = requests.get(url, timeout=3)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            self.response = None
            self.soup = None

        self.features = self.extract_all_features()

    def extract_all_features(self):
        features = [
            self.uses_ip_address(),               # 1
            self.is_url_too_long(),               # 2
            self.uses_shortening_service(),       # 3
            self.has_at_symbol(),                 # 4
            self.has_prefix_suffix_in_domain(),   # 5
            self.has_many_subdomains(),           # 6
            self.has_https_in_scheme(),           # 7
            self.has_external_favicon(),          # 8
            self.check_external_resource_ratio(), # 9
            self.check_anchor_tag_safety(),       #10
            self.check_script_link_ratio(),       #11
            self.check_form_handler(),            #12
            self.has_email_submission(),          #13
            self.check_website_forwarding(),      #14
            self.uses_popup_window(),             #15
            self.has_iframe_redirection(),        #16
            self.check_links_pointing_to_page(),  #17
            self.has_suspicious_words_in_url(),   #18
            self.count_digits_in_url(),           #19
            self.meta_refresh_exists(),           #20
            self.has_password_input(),            #21
            self.external_script_ratio()          #22
        ]
        return features

    def uses_ip_address(self):
        try:
            ipaddress.ip_address(self.domain)
            return -1
        except:
            return 1

    def is_url_too_long(self):
        length = len(self.url)
        return 1 if length < 54 else 0 if length <= 75 else -1

    def uses_shortening_service(self):
        pattern = r"(bit\.ly|tinyurl\.com|goo\.gl|ow\.ly|t\.co|is\.gd|buff\.ly|adf\.ly|bitly\.com)"
        return -1 if re.search(pattern, self.url) else 1

    def has_at_symbol(self):
        return -1 if "@" in self.url else 1

    def has_prefix_suffix_in_domain(self):
        return -1 if "-" in self.domain else 1

    def has_many_subdomains(self):
        dots = self.domain.split(".")
        return 1 if len(dots) == 2 else 0 if len(dots) == 3 else -1

    def has_https_in_scheme(self):
        return 1 if self.urlparse.scheme == "https" else -1

    def has_external_favicon(self):
        try:
            links = self.soup.find_all("link", href=True)
            for link in links:
                href = link["href"]
                if self.domain in href or self.url in href:
                    return 1
            return -1
        except:
            return -1

    def check_external_resource_ratio(self):
        try:
            total, local = 0, 0
            for tag in ['img', 'audio', 'embed', 'iframe']:
                for res in self.soup.find_all(tag, src=True):
                    total += 1
                    if self.domain in res["src"]:
                        local += 1
            if total == 0:
                return 0
            ratio = local / total * 100
            return 1 if ratio < 22 else 0 if ratio < 61 else -1
        except:
            return -1

    def check_anchor_tag_safety(self):
        try:
            total, unsafe = 0, 0
            for a in self.soup.find_all("a", href=True):
                href = a["href"]
                if any(x in href.lower() for x in ["#", "javascript", "mailto"]) or self.domain not in href:
                    unsafe += 1
                total += 1
            if total == 0:
                return 0
            ratio = unsafe / total * 100
            return 1 if ratio < 31 else 0 if ratio < 67 else -1
        except:
            return -1

    def check_script_link_ratio(self):
        try:
            total, local = 0, 0
            for tag in ['script', 'link']:
                attr = 'src' if tag == 'script' else 'href'
                for res in self.soup.find_all(tag, **{attr: True}):
                    total += 1
                    if self.domain in res[attr]:
                        local += 1
            if total == 0:
                return 0
            ratio = local / total * 100
            return 1 if ratio < 17 else 0 if ratio < 81 else -1
        except:
            return -1

    def check_form_handler(self):
        try:
            forms = self.soup.find_all("form", action=True)
            if not forms:
                return 1
            for form in forms:
                action = form["action"]
                if action in ["", "about:blank"]:
                    return -1
                if self.domain not in action:
                    return 0
            return 1
        except:
            return -1

    def has_email_submission(self):
        try:
            return -1 if re.search(r"mailto:", self.soup.text.lower()) else 1
        except:
            return -1

    def check_website_forwarding(self):
        try:
            return 1 if len(self.response.history) <= 1 else 0 if len(self.response.history) <= 4 else -1
        except:
            return -1

    def uses_popup_window(self):
        try:
            return 1 if "alert(" in self.response.text else -1
        except:
            return -1

    def has_iframe_redirection(self):
        try:
            return 1 if "<iframe" in self.response.text.lower() else -1
        except:
            return -1

    def check_links_pointing_to_page(self):
        try:
            num_links = self.response.text.lower().count("<a href=")
            return 1 if num_links == 0 else 0 if num_links <= 2 else -1
        except:
            return -1

    def has_suspicious_words_in_url(self):
        suspicious_keywords = ['login', 'secure', 'verify', 'account', 'update', 'bank', 'free', 'password', 'win', 'confirm']
        return -1 if any(word in self.url.lower() for word in suspicious_keywords) else 1

    def count_digits_in_url(self):
        digits = sum(c.isdigit() for c in self.url)
        return -1 if digits > 10 else 1

    def meta_refresh_exists(self):
        try:
            return -1 if self.soup.find("meta", {"http-equiv": "refresh"}) else 1
        except:
            return -1

    def has_password_input(self):
        try:
            return -1 if self.soup.find("input", {"type": "password"}) else 1
        except:
            return -1

    def external_script_ratio(self):
        try:
            total, local = 0, 0
            for tag in self.soup.find_all("script", src=True):
                total += 1
                if self.domain in tag["src"]:
                    local += 1
            if total == 0:
                return 0
            ratio = local / total * 100
            return 1 if ratio >= 80 else 0 if ratio >= 40 else -1
        except:
            return -1

    def getFeaturesList(self):
        return self.features
