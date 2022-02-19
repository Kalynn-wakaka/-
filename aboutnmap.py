import nmap
from aboutwhois import check_whois

def run_nmap(ip, ports='1-8888'):
    nmap_dict = {}
    nm = nmap.PortScanner()
    nm.scan(hosts=ip, arguments='-O')
    a = nm[ip]['osmatch'][0]['name'].split(' ')[0]
    print(a)
    nmap_dict['os'] = a

    nm.scan(hosts=ip, ports=ports)
    print(nm[ip]['tcp'])
    nmap_dict['tcp'] = nm[ip]['tcp']

    domain = None
    for k in nm[ip]['tcp'].keys():
        if 'http' in nm[ip]['tcp'][k]:
            domain = ip + ':' + k
            check_whois(domain)
            print(domain)
        elif 'https' in nm[ip]['tcp'][k]:
            domain = ip + ':' + k
            check_whois(domain)
            print(domain)
    nmap_dict['domain'] = domain
    return nmap_dict
        

# print(run_nmap('47.119.119.150'))