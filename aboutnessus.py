import requests
import json
from pprint import pprint

proxies = {'http': 'http://localhost:1081', 'https': 'http://localhost:1080'}
accessKey = "aeb93ccadf0f9298c2e74965cfe6d3f7a7f762743481170fad67c8c4ffb2af66" 
secretKey = "b20ac9eb6d8b73bfa9d89874c40045b863e3a4245def2ec0b56c4e3ecb4f55ff" 
ip = '127.0.0.1'                                                               
port = 8834                                                                    
username = 'nessus'                                                            
password = 'nessus'                                                            

header = {
        "X-ApiKeys": "accessKey={accesskey};secretKey={secretkey}".format(accesskey=accessKey, secretkey=secretKey),
        "Content-Type": "application/json",
        "Accept": "text/plain"
    }

# 返回token，用于判断登录是否成功
def get_token():
    url = "https://{0}:{1}/session".format(ip, port)
    post_data = {
        'username': username,
        'password': password
    }
    proxies = {'http': 'http://localhost:1081', 'https': 'http://localhost:1080'}
    response = requests.post(url, data=post_data, verify=False, proxies = proxies)
    if response.status_code == 200:
        data = json.loads(response.text)
        return data["token"]

# 返回扫描列表，内含文件列表和扫描列表
def get_scan_list():
    url = "https://{ip}:{port}/scans".format(ip=ip, port=port)
    token = get_token()
    if token:
        proxies = {'http': 'http://localhost:1081', 'https': 'http://localhost:1080'}
        response = requests.get(url, headers=header, verify=False, proxies = proxies)
        if response.status_code == 200:
            result = json.loads(response.text)
            return result

# 获取指定模板的uuid，默认为用的最广的advanced策略
def get_nessus_template_uuid(template_name = "advanced"):
    api = "https://{ip}:{port}/editor/scan/templates".format(ip=ip, port=port)
    response = requests.get(api, headers=header, verify=False, proxies = proxies)
    templates = json.loads(response.text)['templates']
    for template in templates:
        if template['name'] == template_name:
            return template['uuid']
    return None

# 创建扫描策略，返回策略id
# def create_template(template_name, **kwargs): # kwargs 作为可选参数，用来配置settings和其他项
#     # settings里面的各小项必须得带上，否则会创建不成功
#     settings = {
#         "name": template_name,
#         "watchguard_offline_configs": "",
#         "unixfileanalysis_disable_xdev": "no",
#         "unixfileanalysis_include_paths": "",
#         "unixfileanalysis_exclude_paths": "",
#         "unixfileanalysis_file_extensions": "",
#         "unixfileanalysis_max_size": "",
#         "unixfileanalysis_max_cumulative_size": "",
#         "unixfileanalysis_max_depth": "",
#         "unix_docker_scan_scope": "host",
#         "sonicos_offline_configs": "",
#         "netapp_offline_configs": "",
#         "junos_offline_configs": "",
#         "huawei_offline_configs": "",
#         "procurve_offline_configs": "",
#         "procurve_config_to_audit": "Saved/(show config)",
#         "fortios_offline_configs": "",
#         "fireeye_offline_configs": "",
#         "extremeos_offline_configs": "",
#         "dell_f10_offline_configs": "",
#         "cisco_offline_configs": "",
#         "cisco_config_to_audit": "Saved/(show config)",
#         "checkpoint_gaia_offline_configs": "",
#         "brocade_offline_configs": "",
#         "bluecoat_proxysg_offline_configs": "",
#         "arista_offline_configs": "",
#         "alcatel_timos_offline_configs": "",
#         "adtran_aos_offline_configs": "",
#         "patch_audit_over_telnet": "no",
#         "patch_audit_over_rsh": "no",
#         "patch_audit_over_rexec": "no",
#         "snmp_port": "161",
#         "additional_snmp_port1": "161",
#         "additional_snmp_port2": "161",
#         "additional_snmp_port3": "161",
#         "http_login_method": "POST",
#         "http_reauth_delay": "",
#         "http_login_max_redir": "0",
#         "http_login_invert_auth_regex": "no",
#         "http_login_auth_regex_on_headers": "no",
#         "http_login_auth_regex_nocase": "no",
#         "never_send_win_creds_in_the_clear": "yes",
#         "dont_use_ntlmv1": "yes",
#         "start_remote_registry": "yes",
#         "enable_admin_shares": "yes",
#         "ssh_known_hosts": "",
#         "ssh_port": "",
#         "ssh_client_banner": "OpenSSH_5.0",
#         "attempt_least_privilege": "no",
#         "region_dfw_pref_name": "yes",
#         "region_ord_pref_name": "yes",
#         "region_iad_pref_name": "yes",
#         "region_lon_pref_name": "yes",
#         "region_syd_pref_name": "yes",
#         "region_hkg_pref_name": "yes",
#         "microsoft_azure_subscriptions_ids": "",
#         "aws_ui_region_type": "Rest of the World",
#         "aws_us_east_1": "",
#         "aws_us_east_2": "",
#         "aws_us_west_1": "",
#         "aws_us_west_2": "",
#         "aws_ca_central_1": "",
#         "aws_eu_west_1": "",
#         "aws_eu_west_2": "",
#         "aws_eu_west_3": "",
#         "aws_eu_central_1": "",
#         "aws_eu_north_1": "",
#         "aws_ap_east_1": "",
#         "aws_ap_northeast_1": "",
#         "aws_ap_northeast_2": "",
#         "aws_ap_northeast_3": "",
#         "aws_ap_southeast_1": "",
#         "aws_ap_southeast_2": "",
#         "aws_ap_south_1": "",
#         "aws_me_south_1": "",
#         "aws_sa_east_1": "",
#         "aws_use_https": "yes",
#         "aws_verify_ssl": "yes",
#         "log_whole_attack": "no",
#         "enable_plugin_debugging": "no",
#         "audit_trail": "use_scanner_default",
#         "include_kb": "use_scanner_default",
#         "enable_plugin_list": "no",
#         "custom_find_filepath_exclusions": "",
#         "custom_find_filesystem_exclusions": "",
#         "reduce_connections_on_congestion": "no",
#         "network_receive_timeout": "5",
#         "max_checks_per_host": "5",
#         "max_hosts_per_scan": "100",
#         "max_simult_tcp_sessions_per_host": "",
#         "max_simult_tcp_sessions_per_scan": "",
#         "safe_checks": "yes",
#         "stop_scan_on_disconnect": "no",
#         "slice_network_addresses": "no",
#         "allow_post_scan_editing": "yes",
#         "reverse_lookup": "no",
#         "log_live_hosts": "no",
#         "display_unreachable_hosts": "no",
#         "report_verbosity": "Normal",
#         "report_superseded_patches": "yes",
#         "silent_dependencies": "yes",
#         "scan_malware": "no",
#         "samr_enumeration": "yes",
#         "adsi_query": "yes",
#         "wmi_query": "yes",
#         "rid_brute_forcing": "no",
#         "request_windows_domain_info": "no",
#         "scan_webapps": "no",
#         "start_cotp_tsap": "8",
#         "stop_cotp_tsap": "8",
#         "modbus_start_reg": "0",
#         "modbus_end_reg": "16",
#         "hydra_always_enable": "yes",
#         "hydra_logins_file": "", # 弱口令文件需要事先上传，后面会提到上传文件接口
#         "hydra_passwords_file": "",
#         "hydra_parallel_tasks": "16",
#         "hydra_timeout": "30",
#         "hydra_empty_passwords": "yes",
#         "hydra_login_as_pw": "yes",
#         "hydra_exit_on_success": "no",
#         "hydra_add_other_accounts": "yes",
#         "hydra_postgresql_db_name": "",
#         "hydra_client_id": "",
#         "hydra_win_account_type": "Local accounts",
#         "hydra_win_pw_as_hash": "no",
#         "hydra_cisco_logon_pw": "",
#         "hydra_web_page": "",
#         "hydra_proxy_test_site": "",
#         "hydra_ldap_dn": "",
#         "test_default_oracle_accounts": "no",
#         "provided_creds_only": "yes",
#         "smtp_domain": "example.com",
#         "smtp_from": "nobody@example.com",
#         "smtp_to": "postmaster@[AUTO_REPLACED_IP]",
#         "av_grace_period": "0",
#         "report_paranoia": "Normal",
#         "thorough_tests": "no",
#         "detect_ssl": "yes",
#         "tcp_scanner": "no",
#         "tcp_firewall_detection": "Automatic (normal)",
#         "syn_scanner": "yes",
#         "syn_firewall_detection": "Automatic (normal)",
#         "wol_mac_addresses": "",
#         "wol_wait_time": "5",
#         "scan_network_printers": "no",
#         "scan_netware_hosts": "no",
#         "scan_ot_devices": "no",
#         "ping_the_remote_host": "yes",
#         "tcp_ping": "yes",
#         "icmp_unreach_means_host_down": "no",
#         "test_local_nessus_host": "yes",
#         "fast_network_discovery": "no",

#         "arp_ping": "yes",
#         "tcp_ping_dest_ports":"",
#         "icmp_ping": "yes",
#         "icmp_ping_retries":"",
#         "udp_ping": "yes",
#         "unscanned_closed": "yes",
#         "portscan_range":"",
#         "ssh_netstat_scanner": "yes",
#         "wmi_netstat_scanner": "yes",
#         "snmp_scanner": "yes",
#         "only_portscan_if_enum_failed": "yes",
#         "verify_open_ports": "yes",
#         "udp_scanner": "yes",
#         "svc_detection_on_all_ports": "yes",
#         "ssl_prob_ports": "Known SSL ports",
#         "cert_expiry_warning_days":"",
#         "enumerate_all_ciphers": "yes",
#         "check_crl": "yes",
#     }
#     credentials = {
#                 "add": {
#                     "Host": {
#                         "SSH": [],
#                         "SNMPv3": [],
#                         "Windows": [],
#                     },
#                     "Plaintext Authentication": {
#                         "telnet/rsh/rexec": []
#                     }
#                 }
#             }
#     policys = {}
#     data = {
#             "uuid": get_nessus_template_uuid("advanced"),
#             "settings": settings,
#             "plugins": policys,
#             "credentials": credentials
#         }
    
#     api = "https://{0}:{1}/policies".format(ip, port)
#     response = requests.post(api, headers=header, data=json.dumps(data, ensure_ascii=False).encode("utf-8"), verify=False)# 这里做一个转码防止在nessus端发生中文乱码
#     if response.status_code == 200:
#         data = json.loads(response.text)
#         return data["policy_id"] # 返回策略模板的id，后续可以在创建任务时使用
#     else:
#         return None

# 创建任务，并返回任务id
def create_task(task_name, hosts): # host 是一个列表，存放的是需要扫描的多台主机
    uuid = get_nessus_template_uuid() # custom为获取自定义策略的uuid,默认为系统自带advanced策略
    if uuid is None:
        return False
    data = {"uuid": uuid, "settings": {
        "name": task_name,
        # "policy_id": policy_id,
        "enabled": True,
        "text_targets": hosts,
        "agent_group_id": []
    }}
    pprint(data)
    api = "https://{ip}:{port}/scans".format(ip=ip, port=port)
    response = requests.post(api, headers=header, data=json.dumps(data).encode("utf-8"), verify=False, proxies = proxies)
    if response.status_code == 200:
        data = json.loads(response.text)
        scan = data["scan"]
        if data["scan"] is not None:
            # 新增任务扩展信息记录
            return scan["id"] # 返回任务id


# 开始任务
def start_task(task_id):
    api = "https://{ip}:{port}/scans/{scan_id}/launch".format(ip=ip, port=port, scan_id=task_id)
    response = requests.post(api, verify=False, headers=header, proxies = proxies)
    if response.status_code != 200:
        return False
    else:
        return True

# 结束任务
def stop_task(task_id):
    api = "https://{ip}:{port}/scans/{scan_id}/stop".format(ip=ip, port=port, scan_id=task_id)
    response = requests.post(api, headers=header, verify=False, proxies = proxies)
    if response.status_code == 200 or response.status_code == 409: # 根据nessus api文档可以知道409 表示任务已结束
        return True
    return False    

# 获取任务状态
def get_task_status(task_id):
    api = "https://{ip}:{port}/scans/{task_id}".format(ip=ip, port=port, task_id=task_id)
    response = requests.get(api, headers=header, verify=False, proxies = proxies)
    if response.status_code != 200:
        return 2, "Data Error"

    data = json.loads(response.text)
    # hosts = data["hosts"]
    # for host in hosts:
    #     get_host_vulnerabilities(scan_id, host["host_id"]) # 按主机获取漏洞信息

    if data["info"]["status"] == "completed" or data["info"]["status"] =='canceled':
        # 已完成,此时更新本地任务状态
        return 1, "OK"
    else:
        return 0, "Running"
        
# def get_host_vulnerabilities(scan_id, host_id):
#     scan_history = ScanHistory.objects.get(id=scan_id)
#     api = "https://{ip}:{port}/scans/{task_id}/hosts/{host_id}".format(ip=ip, port=port, task_id=scan_id, host_id=host_id)
#     response = requests.get(api, headers=header, verify=False, proxies = proxies)
#     if response.status_code != 200:
#         return 2, "Data Error"

#     data = json.loads(response.text)
#     vulns = data["vulnerabilities"]
#     for vuln in vulns:
#         vuln_name = vuln["plugin_name"]
#         plugin_id = vuln["plugin_id"] #插件id，可以获取更详细信息，包括插件自身信息和扫描到漏洞的解决方案等信息
#         #保存漏洞信息



def get_file_id(scan_id, file_type):
    api = "https://{ip}:{port}/scans/{scan_id}/export".format(ip=ip, port=port, scan_id=scan_id)
    data = {
        'scan_id' : scan_id,
        'format' : file_type, # Nessus, HTML, PDF, CSV, or DB
    }
    response = requests.post(api, headers=header, data=json.dumps(data).encode("utf-8"), verify=False, proxies = proxies)
    data = json.loads(response.text)
    return data['file']

def download_file(scan_id, file_id, file_name, file_type):
    api = "https://{ip}:{port}/scans/{scan_id}/export/{file_id}/download".format(ip=ip, port=port, scan_id=scan_id, file_id=file_id)
    response = requests.get(api, headers=header, verify=False, proxies = proxies)
    f = open('./'+file_name+'.'+file_type, 'w', encoding="utf-8")
    f.write(response.text)
    f.close()
    return 
    # data = json.loads(response.text)

def download_file_status(scan_id, file_id):
    api = "https://{ip}:{port}/scans/{scan_id}/export/{file_id}/status".format(ip=ip, port=port, scan_id=scan_id, file_id=file_id)
    response = requests.get(api, headers=header, verify=False, proxies = proxies)
    data = json.loads(response.text)
    return data['status']

def run_nessus(ip):
    # 获取指定扫描的uuid
    for scan in get_scan_list()['scans']:
        if scan['name'] == 'test':
            scan_uuid = scan['uuid']
            taskid = scan['id']
            break
    print('test uuid：' + scan_uuid + "______________________________")
    print('task id：' + str(taskid) + "______________________________")
    # pprint(get_nessus_template_uuid())
    # print(create_task('test','64.13.192.189'))

    # import time
    task_file_name = 'test'
    file_type = 'csv' # Nessus, HTML, PDF, CSV, or DB
    target_ip = ip

    # with open 
    # taskid = create_task(task_file_name, target_ip)
    # start_task(taskid)

    while True:
        status = get_task_status(taskid)
        if status[0] == 0:
            print("[+] now task is " + status[1])
            time.sleep(3)
            continue
        else:
            print("[+] now task is " + status[1])
            break
    # download 
    file_id = get_file_id(taskid, file_type) # Nessus, HTML, PDF, CSV, or DB

    while True:
        status = download_file_status(taskid, file_id)
        print("[+] now report status is " + status)
        if status == 'loading':
            time.sleep(3)
        elif status == 'ready':
            break
        else:
            print('status warnings!!')
    download_file(taskid, file_id, task_file_name, file_type)
    print("done")

    
