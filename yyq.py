import requests
import csv
from aboutnessus import *
from mymysql import *
from aboutwhois import check_whois
from aboutnmap import run_nmap 
from aboutgeo import check_geo
from aboutsubdomains import check_subdomains
import pymysql
import json
import getopt
import sys
from prettytable import PrettyTable

IP = ''
scan = [False for i in range(5)]
show = False
data = ''

def add_to_nesss():
    with open('./test.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['Port'] != '':
                id = row['Plugin ID']
                cve = row['CVE']
                cvss = row['CVSS']
                risk = row['Risk']
                host = row['Host']
                port = row['Port']
                protocol = row['Protocol']
                name = row['Name']
                synopsis = row['Synopsis']
                info = row['Description']
                solution = row['Solution']
                plugin_output = row['Plugin Output']
                lis = [id, cve, cvss, risk, host, port, protocol, name, synopsis, info, solution, plugin_output]
                add_to_ness(lis)
                print("[+] Add port info tabel successful")

def usage():
    print("\n\nWelcome to YYQ's toolkit!")
    p = r'''
 /$$     /$$/$$     /$$/$$$$$$          /$$                         /$$ /$$       /$$   /$$    
|  $$   /$$/  $$   /$$/$$__  $$        | $$                        | $$| $$      |__/  | $$    
 \  $$ /$$/ \  $$ /$$/ $$  \ $$       /$$$$$$    /$$$$$$   /$$$$$$ | $$| $$   /$$ /$$ /$$$$$$  
  \  $$$$/   \  $$$$/| $$  | $$      |_  $$_/   /$$__  $$ /$$__  $$| $$| $$  /$$/| $$|_  $$_/  
   \  $$/     \  $$/ | $$  | $$        | $$    | $$  \ $$| $$  \ $$| $$| $$$$$$/ | $$  | $$    
    | $$       | $$  | $$/$$ $$        | $$ /$$| $$  | $$| $$  | $$| $$| $$_  $$ | $$  | $$ /$$
    | $$       | $$  |  $$$$$$/        |  $$$$/|  $$$$$$/|  $$$$$$/| $$| $$ \  $$| $$  |  $$$$/
    |__/       |__/   \____ $$$         \___/   \______/  \______/ |__/|__/  \__/|__/   \___/  
                           \__/                                                                
                                                                                               
                                                                                                                                                                                         
    '''
    print(p)
    print("\nUsage: python yyq.py -p target_ip -a")
    print("-p --IP              - the host IP to listen rebound shell")
    print("-a --all             - run all of the scan")
    print("-w --whois           - run whois scan and save in database")
    print("-s --subdomain       - run subdomain scan and save in database")
    print("-n --nmap            - run nmap scan and save in database")
    print("-g --geography       - run geography scan and save in database, it need nmap")
    print("-e --nessus          - run nessus scan and save with csv report")
    print("-l --show            - look or show the database list")
    print("-d --data            - look or show the data which in database list, most 5 columns")
    print("-q --quit            - exit the system")
    print("\n")
    print("Examples:")
    print("python yyq.py -p 192.168.0.3 -a")
    print("python yyq.py -p 47.119.119.150 -wng")
    print("python yyq.py -p 192.168.0.88 -s -e --nmap")
    print("python yyq.py -l -d whois\n")
    sys.exit(0)

def main():
    global IP
    global scan
    global show
    global data

    if not len(sys.argv[1:]):
        usage()
    
    # get command option
    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:awsngeld:q", ["IP", "all", "whois", "subdomain", "nmap", "geography", "nessus", "show", "data", "quit"])
    except getopt.GetoptError as err:
        print(err)
    for o,a in opts:
        if o in ('-p', '--IP'):
            IP = a
        elif o in ('-a', '--all'):
            scan = [True for i in range(5)]
        elif o in ('-w', '--whois'):
            scan[0] = True
        elif o in ('-s', '--subdomain'):
            scan[1] = True
        elif o in ('-n', '--nmap'):
            scan[2] = True
        elif o in ('-g', '--geography'):
            scan[2] = True
            scan[3] = True
        elif o in ('-e', '--nessus'):
            scan[4] = True
        elif o in ('-l', '--show'):
            show = True
        elif o in ('-d', '--data'):
            show = True
            data = a
        elif o in ('-q', '--quit'):
            print("[-] Quit the system...Bye!")
            sys.exit()
        else:
            usage()
            assert False, "Unknow Option"
    
    # run the option
    if IP and scan[0]:
        whois_dict = json.loads(check_whois(IP))['WhoisRecord']
        add_to_whois([IP, str(whois_dict['audit']), str(whois_dict['contactEmail']), str(whois_dict['domainName']), whois_dict['estimatedDomainAge'], whois_dict['parseCode'], str(whois_dict['registrarIANAID']), str(whois_dict['registrarName']), str(whois_dict['registryData'])])
    if IP and scan[1]:
        subdomains_list = check_subdomains(IP)
        add_to_subdomains(subdomains_list)
    if IP and scan[2]:
        nmap_dict = run_nmap(IP)
        for k,v in nmap_dict['tcp'].items():
            add_to_port([IP, k, v['state'], v['name']])
    if IP and scan[3]:
        geo_list = check_geo(IP)
        add_to_info([IP, nmap_dict['os'], geo_list[0], geo_list[2], geo_list[3], geo_list[4], geo_list[5], geo_list[6], geo_list[7]])
    if IP and scan[4]:
        run_nessus(IP)
        add_to_nesss()
    if show:
        if data:
            print(get_a_table(data))

        else:
            print(get_sql_list())


if __name__ == "__main__":
    # test_ip = '64.13.192.189'
    # create database
    create_nxq_database()
    create_ness_table()
    create_info_table()
    create_port_table()
    create_whois_table()
    create_subdomains_table()

    main()

    

    

    