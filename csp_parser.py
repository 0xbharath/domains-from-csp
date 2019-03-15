from __future__ import print_function

from requests import get, exceptions
import click
from socket import gethostbyname, gaierror
from sys import version_info, exit

if version_info[0] == 2:
    from urlparse import urlparse
elif version_info[0] == 3:
    import urllib.parse.urlsplit as urlparse

import logging
import tldextract

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
)

logger = logging.getLogger('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

__author__ = "Bharath(github.com/yamakira)"
__version__ = "0.0.1"
__purpose__ = '''Parse and print domain names from Content Security Policy(CSP) header'''


def clean_domains(domains):
    clean_domains_set = set()
    for domain in set(domains):
        ext = tldextract.extract(str(domain))
        # If subdomain is wildcard or empty
        if ext[0] in ['*', '']:
            clean_domains_set.add('.'.join(ext[1:]))
        else:
            clean_domains_set.add('.'.join(ext))
    return clean_domains_set


def get_csp_header(url):
    try:
        logger.info("[+] Fetching headers for {}".format(url))
        r = get(url)
    except exceptions.RequestException as e:
        print(e)
        exit(1)

    if 'Content-Security-Policy' in r.headers:
        csp_header = r.headers['Content-Security-Policy']
        return csp_header
    else:
        logger.info("[+] {} doesn't support CSP header".format(url))
        exit(1)


def get_domains(csp_header, clean=False):
    domains = []
    csp_header_values = csp_header.split(" ")
    for line in csp_header_values:
        if "." in line:
            line = line.replace(";", "")
            domains.append(line)
        else:
            pass
    if clean:
        return clean_domains(domains)
    else:
        return domains


def resolve_domains(domains):
    for domain in clean_domains(domains):
        try:
            ip_address = gethostbyname(domain)
            print("\033[92m{0:<30} - {1:20}\033[1;m".format(domain, ip_address.rstrip("\n\r")))
        except gaierror as e:
            print("\033[93m{0:<30} - {1:20}\033[1;m".format(domain, "No A record exists"), end=''),
            print(e.message)
    pass


@click.command()
@click.option('--url', '-u', required=True,
              help='Url to retrieve the CSP header from.')
@click.option('--clean/--dirty', '-c', default=False,
              help='Return domains "cleaned" (without schema and wildcards)')
@click.option('--resolve/--no-resolve', '-r', default=False,
              help='Enable/Disable DNS resolution')
def main(url, resolve, clean):
    csp_header = get_csp_header(url)
    if clean:
        domains = get_domains(csp_header, clean=True)
    else:
        domains = get_domains(csp_header)
    if resolve:
        resolve_domains(domains)
    else:
        for domain in set(domains):
            print(domain)


if __name__ == '__main__':
    main()
