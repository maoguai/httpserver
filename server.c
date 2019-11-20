/*--------------------------头文件--------------------------*/
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <errno.h>
//
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
/*-------------------------全局变量--------------------------*/
#define PORT 6666
#define BUFFER_SIZE 4096
#define MAX_QUE_CONN_NM 5
#define FILE_NAME_MAX 512
#define SOCKADDR sockaddr_in
#define S_FAMILY sin_family
#define SERVER_AF AF_INET
#define MAX_HEADER_LENGTH 1024
#define MAXLINE  8192 

int method;                  /*用于获取http请求行的方法，GET或POST*/
char request_uri[MAX_HEADER_LENGTH + 1];/*用于获取客户端请求的uri*/
char *http_version;          /*获取http版本，未分配内存，是静态变量*/
int fd;                                               /*socket*/
extern char **environ;                      
int PARSE_HEAD_OPTION = 0;/*解析http头选项的标志位，为1表示可以解析了*/
fd_set block_read_fdset;
int max_fd;
#define BOA_FD_SET(fd, where) { FD_SET(fd, where); \
    if (fd > max_fd) max_fd = fd; \
    }
/*------------------------ http头状态机状态------------------*/
#define READ_HEADER             0                 /*读取状态*/
#define ONE_CR                  1                  /*/r状态*/
#define ONE_LF                  2           /*/r/n即解析状态*/
#define TWO_CR                  3     /*/r/n/r即即将空行状态*/
#define BODY_READ               4             /*请求正文状态*/
#define BODY_WRITE              5
#define WRITE                   6
#define PIPE_READ               7
#define PIPE_WRITE              8
#define DONE                    9
#define DEAD                   10
/*------------------------ http请求头---------------------*/
#define M_GET       1
#define M_HEAD      2
#define M_PUT       3
#define M_POST      4
#define M_DELETE    5
#define M_LINK      6
#define M_UNLINK    7
/*------------------------ http请求头部参数----------------*/
char *if_modified_since;            /* If-Modified-Since */
char *content_type;
char *content_length;
char *keepalive;
char *header_referer;
char *header_user_agent;
char *transfer_encoding;                           /*chunked*/
/*-------------------------函数申明--------------------------*/
void select_loop(int server_s);               /*处理客户端请求*/
int process_requests(int server_s);                /*报文解析*/

int header_parse(char *buff, int len);           /*解析http头*/
int http_head_parse(char *buff);             /*解析http请求行*/
int http_option_parse(char *buff);         /*解析http请求头部*/
char *to_upper(char *str);                       /*字符串大写*/
int body_read_parse(char *buff);               /*http请求处理*/
void serve_static(int fd, char *filename, int filesize);
                                               /*静态请求处理*/
int parse_uri(char *uri, char *filename, char *cgiargs);
void serve_dynamic(int fd, char *filename, char *cgiargs);
                                               /*动态请求处理*/
void *Mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
                                                  /*内存映射*/
void Munmap(void *start, size_t length);          /*内存释放*/
ssize_t rio_writen(int fd, void *usrbuf, size_t n);/*文件发送*/ 
ssize_t rio_readn(int fd, void *usrbuf, size_t n);/*文件读取*/ 
void get_filetype(char *filename, char *filetype);/*文件类型*/
void linux_error(char *msg);                      /*错误警告*/
void serve_post(char *post_buff, char *filename, char *cgiargs);
                                                  /*post请求*/
int de_chunked(unsigned char *data,int data_length,unsigned char *dest,int *dest_length);
                                          /*对chunked信息合块*/
int _find_key(unsigned char *data,int data_length,unsigned char *key,int key_length,int *position);
                             /*查找关键数据串在长数据中出现的位置*/
int htoi(unsigned char *s);                 /*进制转换十六转十*/
/*------------------------进制转换十六转十--------------------*/                                                  
int htoi(unsigned char *s) 
{ 
    int i; 
    int n = 0; 
    if (s[0] == '0' && (s[1]=='x' || s[1]=='X')) //判断是否有前导0x或者0X
    { 
        i = 2; 
    } 
    else 
    { 
        i = 0; 
    } 
    for (; (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >='A' && s[i] <= 'Z');++i) 
    {   
        if (tolower(s[i]) > '9') 
        { 
            n = 16 * n + (10 + tolower(s[i]) - 'a'); 
        } 
        else 
        { 
            n = 16 * n + (tolower(s[i]) - '0'); 
        } 
    } 
    return n; 
} 
/*----------------查找关键数据串在长数据中出现的位置-------------*/                               
int _find_key(unsigned char *data,int data_length,unsigned char *key,int key_length,int *position)
{
    int i = *position;
    if(key == NULL || i<0)
    {
        return 0;
    }
    for(; i <= data_length-key_length; i++)
    {
        if( memcmp(data+i, key, key_length) == 0 )
        {
            *position = i;
            return 1;
        }
    }
    return 0;
}
/*----------------------对chunked信息合块--------------------*/                                                  
int de_chunked(unsigned char *data,int data_length,unsigned char *dest,int *dest_length)
{
    char    chunked_hex[CHUNKED_MAX_LEN + 1];    // 十六进制的块长度
    int        chunked_len;                        // 块长度
    int        ret;
    int        begin = 0;
    int        end = 0;
    int        i = 0;
    int        index = 0;
    ret = _find_key(data,data_length,"0\r\n\r\n",5,&end);
    if (ret == 0)    //信息不完整
        return 0;

    ret = _find_key(data,data_length,"\r\n\r\n",4,&begin);
    begin = begin + 4;    //移动到数据起点

    while(memcmp(data+begin,"0\r\n\r\n",5) != 0)
    {
        //获得当前块长度
        ret = _find_key(data+begin,CHUNKED_MAX_LEN,"\r\n",2,&i);
        if (ret == 0)    //信息不完整
            return 0;
        memcpy(chunked_hex,data+begin,i);
        chunked_hex[i] = '\0';
        chunked_len = htoi(chunked_hex);
        //移动到当前块数据段
        begin = begin + i + 2;
        //获得当前块数据
        if (memcmp(data+begin+chunked_len,"\r\n",2) != 0)
            return 0;    //信息有误
        memcpy(dest+index,data+begin,chunked_len);
        index = index + chunked_len;
        //移动到下一块块长度
        begin = begin + chunked_len + 2;
        i = begin;
        if(begin > end)    //结构错误
            return -1;
    }
    *dest_length = index;
    return 1;
}
/*-------------------------post请求-------------------------*/                                                  
void serve_post(char *post_buff, char *filename, char *cgiargs) 
{
    printf("this is serve_post\n");

    int pipes[2] ,post_data_fd ,reda_num;
    char buf[MAXLINE], *emptylist[] = { NULL };
    printf("1\n");

    // Return first part of HTTP response 
    sprintf(buf, "HTTP/1.1 200 OK\r\n"); 
    if (rio_writen(fd, buf, strlen(buf)) != strlen(buf))
        linux_error("rio_writen");

    sprintf(buf, "Server: Tiny Web Server\r\n");
    if (rio_writen(fd, buf, strlen(buf)) != strlen(buf))
        linux_error("rio_writen");

    char template[] = "post-temp.XXXXXX";
    post_data_fd = mkstemp(template);//创建临时文件，用于存放post请求的body数据
    if (post_data_fd == -1) {
        linux_error("mkstemp");
    }
    int len = atoi(content_length);//从头部解析出的post请求数据长度
    if(len <= 0)
        linux_error("content_length");
    char len_buf[32] = {0};
    sprintf(len_buf, "CONTENT_LENGTH=%d",len);
    putenv(len_buf);//设置环境变量，方便cgi程序获取
    printf("content_length len = %d\n",len);
    //把post请求数据写入boa-temp.XXXXXX临时文件
    if (rio_writen(post_data_fd, post_buff, len) != len)
        linux_error("rio_writen");

    if (pipe(pipes) == -1) {//创建管道
        linux_error("pipe");
    }
    int pid = fork();
    if (pid == 0)// child
    {
        //把子进程的标准输出重定向到写管道，也就是CGI向终端输出的数据会写进管道，然后父进程读取管道的数据，最后最发送给客户端。
        if (dup2(pipes[1], STDOUT_FILENO) == -1) {
            close(pipes[1]);
            linux_error("dup2");
        }
        close(pipes[1]);//此时，pipes[1]和STDOUT_FILENO同时指向同一个地方，pipes[1]没用就关掉。

        lseek(post_data_fd, SEEK_SET, 0);
        dup2(post_data_fd, STDIN_FILENO);//将标准输入重定向到post_data_fd，也就是说post_data_fd指向的文件内容会作为标准输入
        close(post_data_fd);

        if (execve(filename, emptylist, environ) < 0)
            linux_error("Execve error");
    }
    else if (pid < 0)  //fork错误
    {
        close(pipes[0]);
        close(pipes[1]);
        linux_error("fork");
    }
    else //父进程
    {
        //读pipes[0] 管道的内容到buff中，这里可能还要对读取的cgi进行解析，然后发送给远端fd,明天调试
        close(post_data_fd); 
        post_data_fd = 0;
        close(pipes[1]);
        while ((reda_num = rio_readn(pipes[0], buf, 1024) )> 0) //从读管道读取cgi脚本的终端打印到buf中
        {
            if (rio_writen(fd, buf, reda_num) != reda_num)
                linux_error("rio_writen");
        }
    }
}
/*-------------------------错误警告-------------------------*/
void linux_error(char *msg) /* linux style error */
{
    perror(msg);
    exit(0);
}
/*-------------------------内存映射-------------------------*/
void *Mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) 
{
    void *ptr;
    if ((ptr = mmap(addr, len, prot, flags, fd, offset)) == ((void *) -1))
    {
        perror("mmap error");
        exit(0);
    }
    return(ptr);
}
/*-------------------------内存释放-------------------------*/
void Munmap(void *start, size_t length) 
{
    if (munmap(start, length) < 0)
    {
        perror("munmap error");
        exit(0);
    }
}
/*-------------------------文件读取-------------------------*/
ssize_t rio_readn(int fd, void *usrbuf, size_t n) 
{
    size_t nleft = n; //剩下未读字符数
    ssize_t nread;
    char *bufp = usrbuf;

    while (nleft > 0) {
    if ((nread = read(fd, bufp, nleft)) < 0) {
        if (errno == EINTR)  //被信号处理函数中断
        nread = 0;      //本次读到0个字符，再次读取
        else
        return -1;      //出错，errno由read设置
    } 
    else if (nread == 0) //读取到EOF
        break;              
    nleft -= nread; //剩下的字符数减去本次读到的字符数
    bufp += nread;  //缓冲区指针向右移动
    }
    //返回实际读取的字符数
    return (n - nleft);         /* return >= 0 */
}
/*-------------------------文件发送-------------------------*/
ssize_t rio_writen(int fd, void *usrbuf, size_t n) 
{
    size_t nleft = n;
    ssize_t nwritten;
    char *bufp = usrbuf;

    while (nleft > 0) {
    if ((nwritten = write(fd, bufp, nleft)) <= 0) {
        if (errno == EINTR)  /* interrupted by sig handler return */
        nwritten = 0;    /* and call write() again */
        else
        return -1;       /* errno set by write() */
    }
    nleft -= nwritten;
    bufp += nwritten;
    }
    return n;
}
/*-------------------------文件类型-------------------------*/
void get_filetype(char *filename, char *filetype) 
{
    if (strstr(filename, ".html"))
    strcpy(filetype, "text/html");
    else if (strstr(filename, ".gif"))
    strcpy(filetype, "image/gif");
    else if (strstr(filename, ".jpg"))
    strcpy(filetype, "image/jpeg");
    else
    strcpy(filetype, "text/plain");
}  
/*-------------------------动态处理-------------------------*/
void serve_dynamic(int fd, char *filename, char *cgiargs) 
{
    printf("this is serve_dynamic\n");
    char buf[MAXLINE], *emptylist[] = { NULL };
    // 发送响应头第一行 
    sprintf(buf, "HTTP/1.1 200 OK\r\n"); 
    if (rio_writen(fd, buf, strlen(buf)) != strlen(buf))
        linux_error("rio_writen");
    //发送响应头选项
    sprintf(buf, "Server: Tiny Web Server\r\n");
    if (rio_writen(fd, buf, strlen(buf)) != strlen(buf))
        linux_error("rio_writen");

    printf("filename=%s\n",filename);
    //fork出子进程用于发送请求的数据
    int pid = fork();
    if (pid == 0)// 子进程
    {
        //setenv("QUERY_STRING", cgiargs, 1);
        if( dup2(fd, STDOUT_FILENO) < 0)       //重定向标准输出到socket fd
            linux_error("dup2");

        if (execve(filename, emptylist, environ) < 0)//执行CGI可执行程序，新的程序将替代掉子进程
            linux_error("Execve error");
    }
    else if (pid < 0)  //fork错误
        linux_error("fork");
    else //父进程
    {
        if (wait(NULL) < 0) //父进程等待子进程执行完成  
            linux_error("wait"); 
    }
}
/*-------------------------静态处理-------------------------*/
void serve_static(int fd, char *filename, int filesize) 
{
    printf("静态处理\n");
    int srcfd;
    char *srcp, filetype[MAXLINE], buf[MAXLINE];

    //发送响应头给客户端
    get_filetype(filename, filetype);
    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    sprintf(buf, "%sServer: Tiny Web Server\r\n", buf);
    sprintf(buf, "%sContent-length: %d\r\n", buf, filesize);
    sprintf(buf, "%sContent-type: %s\r\n\r\n", buf, filetype);

    if (rio_writen(fd, buf, strlen(buf)) != strlen(buf))      
        linux_error("rio_writen");

    //发送响应体给客户端
    if((srcfd = open(filename, O_RDONLY, 0)) < 0)
        linux_error("open");
    //将文件内容映射到虚拟内存中，提高文件的读写效率
    srcp = Mmap(0, filesize, PROT_READ, MAP_PRIVATE, srcfd, 0);
    close(srcfd);   
    //将请求的内容发送给浏览器
    if (rio_writen(fd, srcp, filesize) != filesize)
        linux_error("rio_writen");
    //解除映射
    Munmap(srcp, filesize); 
    close(fd);
}
/*-------------------------uri解析----------------------------*/
int parse_uri(char *uri, char *filename, char *cgiargs) 
{
    char *ptr;

    if (!strstr(uri, "cgi-bin")) 
    {  
        strcpy(cgiargs, "");                             
        strcpy(filename, ".");                           
        strcat(filename, uri);                          
        if (uri[strlen(uri)-1] == '/')           
            strcat(filename, "home.html");              
        return 1;
    }
    else 
    {               
        ptr = index(uri, '?');                         
        if (ptr) 
        {
            strcpy(cgiargs, ptr+1);
            *ptr = '\0';
        }
        else 
            strcpy(cgiargs, "");                        
        strcpy(filename, ".");                           
        strcat(filename, uri);                          
        return 0;
    }
}
/*-------------------------http请求处理----------------------*/
int body_read_parse(char *buff)
{
    int is_static;
    struct stat sbuf;
    char buf[MAXLINE], uri[MAXLINE], version[MAXLINE];
    char filename[MAXLINE], cgiargs[MAXLINE];
    if (method != M_GET && method != M_POST) 
    {
        perror("does not implement this method");
        //501响应
        return;
    }
    is_static = parse_uri(request_uri, filename, cgiargs); 
    if (stat(filename, &sbuf) < 0) 
    {
        perror("couldn't find this file");
        return;
    }                                                    
    if (method == M_POST) {
        serve_post(buff, filename, cgiargs);
        return(0);
    }
    if (is_static) 
    { //对静态请求处理    
        if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) 
        { 
            perror("couldn't read the file");
            return;
        }
        serve_static(fd, filename, sbuf.st_size);        
    }
    else 
    { //对动态请求处理
        if (!(S_ISREG(sbuf.st_mode)) || !(S_IXUSR & sbuf.st_mode)) 
        { 
            perror("couldn't run the CGI program");
            return;
        }
        serve_dynamic(fd, filename, cgiargs);           
    }
    return 0;
}
/*------------------格式化字符串为大写字母---------------------*/
char *to_upper(char *str)
{
    char *buff = str;
    while (*str) {
        if (*str == '-')
            *str = '_';
        else
            *str = toupper(*str);
        str++;
    }
    return buff;
}
/*----------------------解析http请求头部----———---------------*/
int http_option_parse(char *buff) 
{
	char *check = buff;
	char key[64];
	char *value;
	int len_key = 0;
	value = strchr(check, ':');
	if (value == NULL)
        return 0;//表示解析结束
    len_key = value - check;
    *value++ = '\0';
    while (*value == ' ' || *value == '\t')
        value++;
    memcpy(key,check,len_key);
    key[len_key] = '\0';
    memcpy(key,to_upper(key),len_key);
    if (!memcmp(key, "IF_MODIFIED_SINCE", 17)){
        if_modified_since = value;
        printf("%s:%s\n",key,if_modified_since);
    }
    else if (!memcmp(key, "CONTENT_TYPE", 12)){
        content_type = value;
        printf("%s:%s\n",key,content_type);
    }
    else if (!memcmp(key, "CONTENT_LENGTH", 14)){
        content_length = value;
        printf("%s:%s\n",key,content_length);
    }
    else if (!memcmp(key, "CONNECTION", 10) ) {         
        keepalive = value;
        printf("%s:%s\n",key,keepalive);
    }
    else if (!memcmp(key, "REFERER", 7)) {
        header_referer = value;
        printf("%s:%s\n",key,header_referer);
    } 
    else if (!memcmp(key, "USER_AGENT", 10)) {
        header_user_agent = value;
        printf("%s:%s\n",key,header_user_agent);
    }
    return 0;
}

/*------------------------解析http请求行----------------------*/
int http_head_parse(char *buff)
{
	char *check = buff;
	char *check_uri;
	int len_uri = 0;
	int p,q;
	if (!memcmp(check, "GET", 3))
    {
        method = M_GET;
        printf("http请求方法 method = GET\n");
        check = check + 3;
    }
    else if (!memcmp(check, "POST", 4))
    {
        method = M_POST;
        printf("http请求方法 method = POST\n");
        check = check + 4;
    }
    else {
        perror("错误的请求\n");
        return -1;
    }
    PARSE_HEAD_OPTION = 1;//设置解析http头选项的标志位
    while (*(++check) == ' ');
    check_uri = check;
    while(*(++check_uri) != ' ');
    len_uri = check_uri - check;
    if( len_uri > MAX_HEADER_LENGTH)
    {
    	perror("URI过长");
    	return -1;
    }
    memset(request_uri,'\0',sizeof(request_uri));
    memcpy(request_uri, check, len_uri);
    request_uri[len_uri] = '\0';
    printf("http链接 uri = %s\n",request_uri);
    if(*check_uri = " ")
    {
    	while (*(++check_uri) == ' ');
    	if(sscanf(check_uri,"HTTP/%u.%u",&p,&q) == 2)
    	{
    		if (p == 1 && (q == 0 || q == 1)) 
            {
                http_version = check_uri;
                printf("http协议版本 version = %s\n",http_version);
            } 
            else if (p > 1 || (p != 0 && q > 1)) 
            {
                perror("bogus HTTP version");
    			return -1;
            }
    	}
    	else
    	{
    		perror("bogus HTTP version");
    		return -1;
    	}
    }
}
/*------------------------解析http头-------------------------*/
int header_parse(char *buff, int len)
{
	char *check = buff;
	int status = READ_HEADER;
	int check_num = 0;
	char *begin,*end;
	while(check < (buff + len))
	{
		switch (status) 
        {
        	case READ_HEADER:
            	if (*check == '\r') 
            	{
                	status = ONE_CR;
                	end = check;
            	} 
            	else if (*check == '\n') 
            	{
                	status = ONE_LF;
                	end = check;
            	}
            	break;

        	case ONE_CR:
            	if (*check == '\n')
                 	status = ONE_LF;
            	else if (*check != '\r')
                 	status = READ_HEADER;
            	break;

        	case ONE_LF:
            	if (*check == '\r')
                	status = TWO_CR;
            	else if (*check == '\n')
                	status = BODY_READ;
            	else
                	status = READ_HEADER;
            	break;

        	case TWO_CR:
            	if (*check == '\n')
                	status = BODY_READ;
            	else if (*check != '\r')
                	status = READ_HEADER;
            	break;

        	default:
            	break;
		}
		check++;
		check_num ++;
		if(status == ONE_LF)
		{
			*end = '\0';//截断
			/*解析http头选项，由key:value键值对组成*/
			if(PARSE_HEAD_OPTION == 1)
			{
				if(http_option_parse(begin) == -1)
				{
					perror("解析http请求头部失败");
					return  -1;
				}
			}
			/*解析http请求行，method uri version*/
			else
			{
				if (http_head_parse(buff) == -1)
                {
                    perror("解析http请求行失败");
                    return -1;
                }
			}
			begin = check;
		}
		else if(status == BODY_READ)
		{
			PARSE_HEAD_OPTION = 0;   //解析完请求头部之后置0，为下一个客户端做好准备。
            printf("解析请求数据!\n");
            body_read_parse(check);
            return 0;
		}

	}
}
/*----------------------处理客户端请求------------------------*/

void select_loop(int server_s)
{
    FD_ZERO(&block_read_fdset);
    max_fd = server_s+1;
    while (1) {
        BOA_FD_SET(server_s, &block_read_fdset); 
        //没有可读的文件描述符，就阻塞。
        if (select(max_fd + 1, &block_read_fdset,NULL, NULL,NULL) == -1) {
            if (errno == EINTR)
                continue;                     /* while(1) */
            else if (errno != EBADF) {
                perror("select");
            }
        }
        /*判断set集合中描述符fd是否准备好*/
        if (FD_ISSET(server_s, &block_read_fdset))
            process_requests(server_s);
    }
}

/*--------------------------报文解析-------------------------*/

int process_requests(int server_s)
{
    int fd;                                  /* socket */
    struct SOCKADDR remote_addr;             /* address */
    int remote_addrlen = sizeof (struct SOCKADDR);
    size_t len;
    char buff[BUFFER_SIZE];
    bzero(buff,BUFFER_SIZE);
    fd = accept(server_s, (struct sockaddr *) &remote_addr,
                &remote_addrlen);

    if (fd == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            /* abnormal error */
            perror("accept");
        return -1;
    }

    int bytes = read(fd, buff, BUFFER_SIZE);
    if (bytes < 0) {
        if (errno == EINTR)
            bytes = 0;
        else
            return -1;
    }
    printf("recv %d bytes from client:%s\n",bytes,buff);
    header_parse(buff,bytes);
    return 0;
}

/*--------------------------主函数--------------------------*/
/*-------------------socket套接字创建TCP连接-----------------*/
int main(int argc,char* argv[])
{
    int sockfd;
    int sin_size = sizeof(struct sockaddr);
    struct sockaddr_in server_sockaddr, client_sockaddr;
    int i = 1;/* 使得重复使用本地地址与套接字进行绑定 */

    /*建立socket连接*/
    if ((sockfd = socket(AF_INET,SOCK_STREAM,0))== -1)
    {
        perror("socket");
        exit(1);
    }
    printf("Socket id = %d\n",sockfd);

    /*设置sockaddr_in 结构体中相关参数*/
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_port = htons(PORT);
    server_sockaddr.sin_addr.s_addr = INADDR_ANY;
    bzero(&(server_sockaddr.sin_zero), 8);

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));

    /*绑定函数bind*/
    if (bind(sockfd, (struct sockaddr *)&server_sockaddr, sizeof(struct sockaddr))== -1)
    {
        perror("bind");
        exit(1);
    }
    printf("Bind success!\n");

    /*调用listen函数*/
    if (listen(sockfd, MAX_QUE_CONN_NM) == -1)
    {
        perror("listen");
        exit(1);
    }
    printf("Listening....\n");
    select_loop(sockfd);
    return 0;
}





