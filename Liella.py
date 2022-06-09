#! /usr/bin/env python
# coding=utf8
import socket
import argparse
import sys
import os
import re
import requests
from rich.console import Console
from rich.table import Table
import urllib3
urllib3.disable_warnings()


def main(host,port):
    try:
        s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
    except socket.error as e:
        print('Error create socket %s'.format(e))
        return

    try:
        s.connect((host,port))
    except Exception as e:
        print('Fist connect %s error'.format(e))
        return
#检测1
    try:
        s.sendall(('OPTIONS HTTP/1.1\r\n\r\n').encode())
    except socket.error as e:
        print('Send %s'.format(e))
        return
    while True:
        try:
            buf = s.recv(2048)
            #print("buf")
            #print(buf)
            if (b"200 OK" in buf) or (b"\x15\x03\x03\x00\x02\x02" in buf):
                print(host + ":" + str(port) + " is likely to be Cobalt Strike!")
            break
        except socket.error as e:
            print(e)
            break
#检测2
    try:
        s.sendall(('CURL /jquery-3.3.2.slim.min.js HTTP/1.1\r\n\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko\r\n\r\n').encode())
    except socket.error as e:
        print('Send %s'.format(e))
        return
    while True:
        try:
            buf = s.recv(2048)
            #print("buf")
            #print(buf)
            if (b"404 Not Found" in buf) and (b'nginx' not in buf):
                print(host + ":" + str(port) + " is likely to be Cobalt Strike!")
            break
        except socket.error as e:
            print(e)
            break

console = Console()
def Weibu(ip):  # 微步威胁情报查询
    ThreatBook_api = ""
    if ThreatBook_api == "":
        console.log('[red][EROR] 未检测到微步 API')
        return ('N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A')
    else:
        url = 'https://api.threatbook.cn/v3/scene/ip_reputation'
        query = {
            "apikey": "%s" % ThreatBook_api,
            "resource": "%s" % ip,
            "lang": "zh"
        }
        try:
            r = requests.request("GET", url, params=query, verify=False, proxies={'http': None, 'https': None})
            r_json = r.json()
            if r_json['response_code'] != 0:
                console.log('[red][EROR] 微步 API 调用失败，错误信息：%s' % r_json['verbose_msg'])
                return ('N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A')
            else:
                confidence_level = r_json['data']['%s' % ip]['confidence_level']  # 情报可信度
                if r_json['data']['%s' % ip]['is_malicious'] == False:  # 是否为恶意 IP
                    is_malicious = '否'
                else:
                    is_malicious = '是'
                severity = r_json['data']['%s' % ip]['severity']  # 危害程度
                judgments = ",".join(r_json['data']['%s' % ip]['judgments'])  # 威胁类型
                tags_classes = r_json['data']['%s' % ip]['tags_classes']  # 标签类别
                tags = []  # 标签
                tags_type = []  # 标签类型
                for i in tags_classes:
                    tags.append(",".join(i['tags']))
                    tags_type.append(i['tags_type'])
                tags = ','.join(tags)
                tags_type = ','.join(tags_type)
                scene = r_json['data']['%s' % ip]['scene']  # 场景
                carrier = r_json['data']['%s' % ip]['basic']['carrier']  # IP 基本信息
                location = r_json['data']['%s' % ip]['basic']['location']
                ip_location = location['country'] + ' ' + location['province'] + ' ' + location['city']  # IP 地理位置
                table = Table()
                table.add_column('是否为恶意IP', justify="center")
                table.add_column('危害程度', justify="center")
                table.add_column('威胁类型', justify="center")
                table.add_column('标签', justify="center")
                table.add_column('标签类型', justify="center")
                table.add_column('场景', justify="center")
                table.add_column('IP基本信息', justify="center")
                table.add_column('IP地理位置', justify="center")
                table.add_column('情报可信度', justify="center")
                table.add_row(is_malicious, severity, judgments, tags, tags_type, scene, carrier, ip_location,
                              confidence_level)
                console.log('[green][SUCC] %s 微步威胁情报信息：' % ip)
                console.print(table)
                return (
                    is_malicious, severity, judgments, tags, tags_type, scene, carrier, ip_location, confidence_level)
        except Exception as e:
            console.log('[red][EROR] 查询 %s 的微步信息发生错误，错误信息：%s' % (ip, repr(e)))
            return ('N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A')

def danger_port():
    danger_port = ['12221','3389','445','3306','1433','1521','21','27017','11211','5432','23','25','465','110','995','143','993','5900','6379']
    result = os.popen('netstat -ano')
    res = result.read()
    for line in res.splitlines():
        if "0.0.0.0:" in line:
            try:
                line2 = (re.findall(r'(0.0.0.0.+\d\s)', line))[0]
                port = (re.findall(r':(..+?)\D', line2))[0]
                if port in danger_port:
                    print("port " + port + " is open which means potencial danger")
            except:
                continue
        if (("ESTABLISHED" in line) & ("127.0.0.1" not in line)):
                #print(line+" in")
                line2 = re.findall(r'(\d{1,3}\W\d{1,3}\W\d{1,3}\W\d{1,3}\D\d{1,5})', line)[1]
                print(line2)
                host = re.findall(r'(.+?):',line2)[0]
                port = re.findall(r':(\d{1,5})',line2)[0]
                #print(host)
                #print(port)
                main(host,int(port))
                Weibu(host)
        continue

if __name__ == "__main__":
   danger_port()
