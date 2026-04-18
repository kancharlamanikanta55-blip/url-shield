import re
from urllib.parse import urlparse
from tld import get_tld

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
    return 1 if match else 0
def abnormal_url(url):
    try:
        hostname = str(urlparse(url).hostname)
        if hostname and hostname in url:
            return 1
        return 0
    except:
        return 0

def count_dot(url):       return url.count('.')
def count_www(url):       return url.count('www')
def count_atrate(url):    return url.count('@')
def count_https(url):     return url.count('https')
def count_http(url):      return url.count('http')
def count_per(url):       return url.count('%')
def count_ques(url):      return url.count('?')
def count_hyphen(url):    return url.count('-')
def count_equal(url):     return url.count('=')
def url_length(url):
    try:    return len(str(url))
    except: return 0

def hostname_length(url):
    try:    return len(urlparse(url).netloc)
    except: return 0

def no_of_dir(url):
    try:
        return urlparse(url).path.count('/')
    except:
        return 0

def no_of_embed(url):
    try:
        return urlparse(url).path.count('//')
    except:
        return 0

def shortening_service(url):
    match = re.search(
        'bit\\.ly|goo\\.gl|shorte\\.st|go2l\\.ink|x\\.co|ow\\.ly|t\\.co|tinyurl|'
        'tr\\.im|is\\.gd|cli\\.gs|yfrog\\.com|migre\\.me|ff\\.im|tiny\\.cc|'
        'url4\\.eu|twit\\.ac|su\\.pr|bitly\\.com|db\\.tt|qr\\.ae|adf\\.ly|'
        'cur\\.lv|tinyurl\\.com|lnkd\\.in', url)
    return 1 if match else 0

def suspicious_words(url):
    match = re.search(
        'PayPal|login|signin|bank|account|update|free|lucky|service|bonus|webscr', url)
    return 1 if match else 0

def digit_count(url):
    return sum(1 for c in url if c.isnumeric())

def letter_count(url):
    return sum(1 for c in url if c.isalpha())

def fd_length(url):
    try:
        return len(urlparse(url).path.split('/')[1])
    except:
        return 0


def tld_length(tld):
    try:    return len(tld)
    except: return -1

import math

def url_entropy(url):
    try:
        prob = [float(url.count(c)) / len(url) for c in set(url)]
        return -sum(p * math.log(p, 2) for p in prob)
    except:
        return 0

def special_char_count(url):
    return sum(1 for c in url if c in '~_*[]{}|\\^`<>')

def subdomain_count(url):
    try:
        hostname = urlparse(url).hostname
        if hostname:
            return len(hostname.split('.')) - 2
        return 0
    except:
        return 0

def path_length(url):
    try:
        return len(urlparse(url).path)
    except:
        return 0

def main(url):
    status = []
    status.append(having_ip_address(url))
    status.append(abnormal_url(url))
    status.append(count_dot(url))
    status.append(count_www(url))
    status.append(count_atrate(url))
    status.append(no_of_dir(url))
    status.append(no_of_embed(url))
    status.append(shortening_service(url))
    status.append(count_https(url))
    status.append(count_http(url))
    status.append(count_per(url))
    status.append(count_ques(url))
    status.append(count_hyphen(url))
    status.append(count_equal(url))
    status.append(url_length(url))
    status.append(hostname_length(url))
    status.append(suspicious_words(url))
    status.append(digit_count(url))
    status.append(letter_count(url))
    status.append(fd_length(url))
    tld = get_tld(url, fail_silently=True)
    status.append(tld_length(tld))
    status.append(url_entropy(url))
    status.append(special_char_count(url))
    status.append(subdomain_count(url))
    status.append(path_length(url))
    return status