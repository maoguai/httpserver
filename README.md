# httpserver
一个简单的http服务器

 ## 要求
• 支持HTTP Post/Get方法，可以上传或下载文件     
• 支持HTTP分块传输，支持HTTP持久连接和管道   
• 使用openssl库，支持HTTPS   
• 使用libevent支持多路并发    

## 编译

gcc -o https_server https_server.c -levent -lssl -lcrypto -levent_openssl -lm -lpthread.         

  ## curl

上传：curl -k https://172.16.176.14:8081/post?file=a.txt -F "file=@/home/dzh/a.txt" -#

下载：curl -k http://172.16.176.14.:8081/get?file=IMG_0782.jpg -# -o s.jpg

