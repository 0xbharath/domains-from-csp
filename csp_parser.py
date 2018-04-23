from __future__ import print_function
import sys
import requests

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
    )

logger = logging.getLogger('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def get_csp_header(url):
    try:
        logger.info("[+] Fetching headers for {}".format(url))
        r = requests.get(url)
    except requests.exceptions.RequestException as e:
        print(e)
        sys.exit(1)

    if 'Content-Security-Policy' in r.headers:
        csp_header = r.headers['Content-Security-Policy']
        return csp_header
    else:
        logger.info("[+] {} doesn't support CSP header".format(url))
        sys.exit(1)
def get_domains(csp_header):
    domains = []
    csp_header_values = csp_header.split(" ")
    for line in csp_header_values:
        if "." in line:
            line = line.replace(";","")
            domains.append(line)
        else:
            pass
    return domains

def get_url():
    if len(sys.argv) <= 1:
        print("Usage: python domain_enum_csp.py <target_url>\nURL format - http(s)://example.com")
        sys.exit(1)
    else:
        return sys.argv[1]

def main():
    url = get_url() 
    csp_header = get_csp_header(url)
    domains = get_domains(csp_header)
    for domain in set(domains):
        print(domain)
if __name__ == '__main__':
    main()