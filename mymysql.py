import pymysql
from prettytable import PrettyTable

def create_nxq_database():
    db = get_db()
    cursor = db.cursor()
    create_db = "create database if not exists nxq;"
    cursor.execute(create_db)
    # print("Create database nxq successfully.")
    db.close()
    # print("database closed.")

def create_ness_table():
    db = get_db()
    cursor = db.cursor()
    create_tb = '''
        CREATE TABLE if not exists `ness`( 
            `uid` int NOT NULL auto_increment primary key,
            `id` int ,
            `cve` tinytext,
            `cvss` float,
            `risk` tinytext,
            `host` tinytext,
            `port` int,
            `protocol` tinytext,
            `name` tinytext,
            `synopsis` text,
            `info` text,
            `solution` text,
            `plugin_output` text
            ); 
    '''
    cursor.execute(create_tb)
    db.close()

def create_info_table():
    db = get_db()
    cursor = db.cursor()
    create_tb = '''
        CREATE TABLE if not exists `info`( 
            `ip` char(20) primary key,
            `system` tinytext,
            `country` tinytext,
            `city` tinytext,
            `lat` float,
            `lng` float,
            `timezone` tinytext,
            `asn_id` int,
            `asn_name` tinytext
            ); 
    '''
    cursor.execute(create_tb)
    db.close()

def create_port_table():
    db = get_db()
    cursor = db.cursor()
    create_tb = '''
        CREATE TABLE if not exists `port`( 
            `ip` char(20) ,
            `port` int,
            `state` tinytext,
            `service` tinytext,
            primary key(`ip`, `port`)
            ); 
    '''
    cursor.execute(create_tb)
    db.close()

def create_whois_table():
    db = get_db()
    cursor = db.cursor()
    create_tb = '''
        CREATE TABLE if not exists `whois`( 
            `ip` char(20) primary key,
            `audit` tinytext,
            `contactEmail` tinytext,
            `domainName` tinytext,
            `estimatedDomainAge` int,
            `parseCode` int,
            `registrarIANAID` tinytext,
            `registrarName` tinytext,
            `registryData` text
            ); 
    '''
    cursor.execute(create_tb)
    db.close()

def create_subdomains_table():
    db = get_db()
    cursor = db.cursor()
    create_tb = '''
        CREATE TABLE if not exists `subdomains`( 
            `ip` char(20) primary key,
            `count` int,
            `domains` tinytext
            ); 
    '''
    cursor.execute(create_tb)
    db.close()

def get_db():
    return pymysql.connect(host="localhost",user="root", password="yanpengfei",  database="nxq")

def add_to_ness(lis):
    if lis[2] == '':
        lis[2] = 0.0

    lit = lis[0:8]
    lis2 = lis + lit
    tup = tuple(lis)
    tup2 = tuple(lis2)

    db = get_db()
    cursor = db.cursor()

    sentence2 = '''
        INSERT INTO `ness`(
            `id`,
            `cve`,
            `cvss`,
            `risk`,
            `host`,
            `port`,
            `protocol`,
            `name`,
            `synopsis`,
            `info`,
            `solution`,
            `plugin_output`
        ) SELECT 
            %s,%s,%s,%s,%s,
            %s,%s,%s,%s,%s,
            %s,%s
        FROM DUAL WHERE NOT EXISTS(
            SELECT `id`,
            `cve`,
            `cvss`,
            `risk`,
            `host`,
            `port`,
            `protocol`,
            `name`,
            `synopsis`,
            `info`,
            `solution`,
            `plugin_output` 
            FROM `ness` WHERE 
                    `id`=%s AND
                    `cve`=%s AND
                    `cvss`=%s AND
                    `risk`=%s AND
                    `host`=%s AND
                    `port`=%s AND
                    `protocol`=%s AND
                    `name`=%s
        );
    '''
    cursor.execute(sentence2, tup2)
    db.commit()
    print("insert into ness table successfully.")
    cursor.close()
    db.close()
    print("database closed.")

def add_to_info(lis):
    db = get_db()
    cursor = db.cursor()

    lis.append(lis[0])
    tup2 = tuple(lis)
    sentence2 = '''
        INSERT INTO `info`(
            `ip`,
            `system`,
            `country`,
            `city`,
            `lat`,
            `lng`,
            `timezone`,
            `asn_id`,
            `asn_name`
        ) SELECT 
            %s,%s,%s,%s,%s,
            %s,%s,%s,%s
        FROM DUAL WHERE NOT EXISTS(
            SELECT `ip`
            FROM `info` WHERE 
                    `ip`=%s
        );
    '''
    cursor.execute(sentence2, tup2)
    db.commit()
    print("insert into info table successfully.")
    cursor.close()
    db.close()
    print("database closed.")

def add_to_port(lis):
    db = get_db()
    cursor = db.cursor()

    lis.append(lis[0])
    lis.append(lis[1])
    tup2 = tuple(lis)
    sentence2 = '''
        INSERT INTO `port`(
            `ip`,
            `port`,
            `state`,
            `service`
        ) SELECT 
            %s,%s,%s,%s
        FROM DUAL WHERE NOT EXISTS(
            SELECT `ip`
            FROM `port` WHERE 
                `ip`= %s AND
                `port` = %s
        );
    '''
    cursor.execute(sentence2, tup2)
    db.commit()
    print("insert into port table successfully.")
    cursor.close()
    db.close()
    print("database closed.")

def add_to_whois(lis):
    db = get_db()
    cursor = db.cursor()
    lis.append(lis[0])
    tup2 = tuple(lis)
    sentence2 = '''
        INSERT INTO `whois`(
            `ip`,
            `audit`,
            `contactEmail`,
            `domainName`,
            `estimatedDomainAge`,
            `parseCode`,
            `registrarIANAID`,
            `registrarName`,
            `registryData`
        ) SELECT 
            %s,%s,%s,%s,%s,
            %s,%s,%s,%s
        FROM DUAL WHERE NOT EXISTS(
            SELECT `ip`
            FROM `whois` WHERE 
                `ip`=%s
        );
    '''
    cursor.execute(sentence2, tup2)
    db.commit()
    print("insert into info table successfully.")
    cursor.close()
    db.close()
    print("database closed.")

def add_to_subdomains(lis):
    db = get_db()
    cursor = db.cursor()
    lis.append(lis[0])
    tup2 = tuple(lis)
    sentence2 = '''
        INSERT INTO `subdomains`(
            `ip`,
            `count`,
            `domains`
        ) SELECT 
            %s,%s,%s
        FROM DUAL WHERE NOT EXISTS(
            SELECT `ip`
            FROM `subdomains` WHERE 
                `ip`=%s
        );
    '''
    cursor.execute(sentence2, tup2)
    db.commit()
    print("insert into info table successfully.")
    cursor.close()
    db.close()
    print("database closed.")

    # select all the tables in my database 
def get_sql_list():
    db = get_db()
    cursor = db.cursor()
    query = '''
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema='nxq';
    '''
    result = cursor.execute(query)
    db.close()
    tb = PrettyTable()
    tb.field_names = ["TABLE_NAME"]
    for i in cursor.fetchall():
        temp = []
        temp.append(i[0])
        tb.add_row(temp)
    tb.align = "l"
    return tb

def get_a_table(data):
    db = get_db()
    cursor = db.cursor()
    query = '''
        select column_name 
        from information_schema.columns 
        where table_schema='nxq' and table_name=%s;
    '''
    result = cursor.execute(query, data)
    name = cursor.fetchall()
    tb = PrettyTable()
    for i in range(5 if len(name)>4 else len(name)):
        query = '''select '''+ name[i][0] +''' from ''' + data +''';'''
        cursor.execute(query)
        tb.add_column(name[i][0], [j[0] for j in cursor.fetchall()])
    db.close()
    tb.align = "l"
    return tb
