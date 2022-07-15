#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author   : R0A1NG
# @link     : https://www.roaing.com/
# @File     : main.py
# @Time     : 2022/4/25 10:59
from gevent import monkey
import gevent.pool
monkey.patch_all()
from urllib3.contrib import pyopenssl
import tldextract
import json
import requests
import urllib3
urllib3.disable_warnings()
from IPy import IP
from func_timeout import func_set_timeout, FunctionTimedOut

ip_all = []


def get_key1(dct, value):           # 根据证书找
    return list(filter(lambda k: value in dct[k], dct))


def get_key2(dct, value):           # 根据网段找
    for key in dct.keys():
        for ipd in dct[key]:
            if ipd and value in IP(ipd):
                return key
    return None


def pd_key(ip):
    global CdnToKey
    try:
        try:
            res = requests.get('http://' + ip, verify=False, timeout=5)
        except:
            res = requests.get('https://' + ip, verify=False, timeout=5)
        print(res.text)
        for name in CdnToKey:
            for key in CdnToKey[name]:
                if ('text:' in key and key.split('text:')[1] in res.text) or ('header:' in key and key.split('header:')[1] in str(res.headers)):
                    print(ip, name)
                    f = open('iscdn.txt', 'a+', encoding='utf-8')
                    f.write(ip + ',' + name + '\n')
                    return name
    except:
        pass
    return None


CdnToDom = json.load(open('public/CdnToDom.json', 'r', encoding='utf-8'))
CdnToNet = json.load(open('public/CdnToNet.json', 'r', encoding='utf-8'))
CdnToKey = json.load(open('public/CdnToKey.json', 'r', encoding='utf-8'))


def ippd(ip):
    global ip_all, rmip
    ipif = get_key2(CdnToNet, ip)
    if ipif:
        print(ip, ipif)
        f = open('iscdn.txt', 'a+', encoding='utf-8')
        f.write(ip + ',' + ipif + '\n')
        rmip.append(ip)


@func_set_timeout(5)
def conne(ip):
    conn = pyopenssl.ssl.create_connection((ip, 443))
    return conn


def get_expire(ip):
    global rmip, CdnToKey
    try:
        conn = conne(ip)
        sock = pyopenssl.ssl.SSLContext(pyopenssl.ssl.PROTOCOL_SSLv23).wrap_socket(conn)
        cert = pyopenssl.ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
        data = pyopenssl.OpenSSL.crypto.load_certificate(pyopenssl.OpenSSL.crypto.FILETYPE_PEM, cert)
        domain = data.get_subject().get_components()[-1][1].decode()  # 获取证书颁发域名信息
        vul = tldextract.extract(domain)  # 提取url里的域名结构
        pdomain = "{0}.{1}".format(vul.domain, vul.suffix)
        cdnfirm = get_key1(CdnToDom, pdomain)
        if cdnfirm:
            print(ip, cdnfirm[0])
            f = open('iscdn.txt', 'a+', encoding='utf-8')
            f.write(ip + ',' + cdnfirm[0] + '\n')
    except:
        pdomain = None
    if pdomain:
        if not pd_key(ip):
            print(ip, pdomain)
            f = open('isssl.txt', 'a+', encoding='utf-8')
            f.write(ip + ',' + pdomain + '\n')
        rmip.append(ip)
    else:
        if pd_key(ip):
            rmip.append(ip)


if __name__ == '__main__':
    ip_all = open('ip.txt', 'r').read().splitlines()
    open('iscdn.txt', 'w')
    open('isssl.txt', 'w')
    g = gevent.pool.Pool(100)

    # 先判断是否在已有IP段内
    rmip = []
    run_list = []
    for ip in ip_all:
        run_list.append(g.spawn(ippd, ip))
    gevent.joinall(run_list)

    for ip in rmip:
        ip_all.remove(ip)

    # 根据证书识别
    rmip = []
    run_list = []
    for ip in ip_all:
        run_list.append(g.spawn(get_expire, ip))
    gevent.joinall(run_list)

    for ip in rmip:
        ip_all.remove(ip)

    ip_all = '\n'.join(ip_all)
    f = open('unknown.txt', 'w').write(ip_all)
    print('确认为CDNIP的已保存至[iscdn.txt]')
    print('有ssl但不在本CDNIP库的已保存至[isssl.txt]')
    print('未确认的IP已保存至[unknown.txt]')