def 基于证书子域名查询(子域名参数):
    with 以爬虫的形式打开('https://crt.sh/?q=' + 子域名参数) as f:
        for 证书, 子域名 in 正则查找全部('<tr>(?:\s|\S)*?href="\?id=([0-9]+?)"(?:\s|\S)*?<td>([*_a-zA-Z0-9.-]+?\.' + re.escape(domains) + ')</td>(?:\s|\S)*?</tr>', code, re.IGNORECASE):
            子域名 = 子域名.split('@')[-1]
            with 打开一个被追加的保存结果的文件 as f:
                f.write(子域名)

def check_subdomains(ipaddr):
    根据文档构造url
    res = requests.get(url, 正确设置代理的参数)
    #以下假设返回结果以json形式显示
    res_js = 以json形式加载(返回结果res)
    num = 取出返回结果数
    lis = 取出返回的子域名并存储成列表
    return lis