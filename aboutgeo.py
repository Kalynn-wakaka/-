import requests, json

def check_geo(ipaddr):
    proxies = {'http': 'http://localhost:1081', 'https': 'http://localhost:1080'}
    url = "https://ip-geolocation.whoisxmlapi.com/api/v1?apiKey=at_2rzwsiFqo6YYaLiokezLQsiTF88WO&ipAddress=" + ipaddr
    res = requests.get(url, proxies=proxies)

    with open("geo.txt","w") as f:
        f.write(res.text)
    lis = []
    textjs = json.loads(res.text)
    lis.append(textjs['location']['country'])
    lis.append(textjs['location']['region'])
    lis.append(textjs['location']['city'])
    lis.append(textjs['location']['lat'])
    lis.append(textjs['location']['lng'])
    lis.append(textjs['location']['timezone'])
    lis.append(textjs['as']['asn'])
    lis.append(textjs['as']['name'])
    print(lis)
    return lis

# check_geo('47.119.119.150')