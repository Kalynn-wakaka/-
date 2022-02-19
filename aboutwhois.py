import requests

def check_whois(domain):
    proxies = {'http': 'http://localhost:1081', 'https': 'http://localhost:1080'}
    url = "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_2rzwsiFqo6YYaLiokezLQsiTF88WO&domainName=" + domain + "&outputFormat=JSON"
    res = requests.get(url, proxies=proxies)

    with open("whois.txt","w") as f:
        f.write(res.text)
    
    return res.text