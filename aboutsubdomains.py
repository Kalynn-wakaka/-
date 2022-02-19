import requests, json

def check_subdomains(ipaddr):
    proxies = {'http': 'http://localhost:1081', 'https': 'http://localhost:1080'}
    url = "https://subdomains.whoisxmlapi.com/api/v1?apiKey=at_2rzwsiFqo6YYaLiokezLQsiTF88WO&domainName=" + ipaddr + "&outputFormat=JSON"

    res = requests.get(url, proxies=proxies)

    with open("subdomains.txt","w") as f:
        f.write(res.text)
    res_js = json.loads(res.text)
    num = res_js['result']['count']
    lis = [ipaddr, num]
    str1 = ""
    for i in res_js['result']['records']:
        str1.append(i['domain'])
    lis.append(str1)
    print(lis)
    return lis
    
      
