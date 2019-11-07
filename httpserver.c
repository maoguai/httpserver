//httpserver.c
//q
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
/*-------------------------全局变量--------------------------*/
#define PORT 6666
#define BUFFER_SIZE 4096
#define MAX_QUE_CONN_NM 5
#define FILE_NAME_MAX 512
#define SOCKADDR sockaddr_in
#define S_FAMILY sin_family
#define SERVER_AF AF_INET
#define MAX_HEADER_LENGTH           1024
int PARSE_HEAD_OPTION = 0;//解析http头选项的标志位，为1表示可以解析了
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

/*-------------------------函数申明--------------------------*/
void select_loop(int server_s);               /*处理客户端请求*/
int process_requests(int server_s);                /*报文解析*/

int header_parse(char *buff, int len);           /*解析http头*/
int http_head_parse(char *buff);             /*解析http请求行*/
int http_option_parse(char *buff);         /*解析http请求头部*/
char *to_upper(char *str);                       /*字符串大写*/
/*------------------------解析http头-------------------------*/

int header_parse(char *buff, int len)
{
	char *check = buff;
    int status = READ_HEADER;
    char *line_end;//用于标记，改成指针
    char *header_line;//记录http头选项每一行开始的位置
    int parse_pos = 0;
    while (check < (buff + len)) {
        switch (status) {
        case READ_HEADER:
            if (*check == '\r') {
                status = ONE_CR;
                line_end = check;
            } else if (*check == '\n') {
                status = ONE_LF;
                line_end = check;
            }
            break;

        case ONE_CR:
            if (*check == '\n')
                 status = ONE_LF;
            else if (*check != '\r')
                 status = READ_HEADER;
            break;

        case ONE_LF:
            /* if here, we've found the end (for sure) of a header */
            if (*check == '\r') /* could be end o headers */
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

        parse_pos++;       /* update parse position */
        check++;
        //解析到每一行末后进入
        if (status == ONE_LF) {
            *line_end = '\0';

            

            if (PARSE_HEAD_OPTION) {//解析http头选项，由key:value键值对组成
                if (http_option_parse(header_line) == -1) {
                    perror("解析http请求头部失败");
                    return -1;
                }
            } else {//解析http头请求行
                if (http_head_parse(buff) == -1){
                    perror("解析http请求行失败");
                    return -1;
                }
            }

            header_line = check;               //记录http头选项每一行开始的位置
        } else if (status == BODY_READ){
            PARSE_HEAD_OPTION = 0;   //解析完请求头部之后置0，为下一个客户端做好准备。
            printf("begin parse body!\n");
            return 0;
        }
    } 
    return 0;
}

/*----------------------解析http请求行----————---------------*/
int http_head_parse(char *buff)
{
    static char *SIMPLE_HTTP_VERSION = "HTTP/0.9";
    int method;//用于获取http请求行的方法，GET或HEAD或POST
    char request_uri[MAX_HEADER_LENGTH + 1]; // 用于获取客户端请求的uri
    char *http_version = SIMPLE_HTTP_VERSION;//获取http版本，未分配内存，是静态变量，注意一下，可能会出错

    char *stop, *stop2;
    char *logline = buff;
    if (!memcmp(logline, "GET ", 4))
    {
        method = M_GET;
        printf("http method = GET\n");
    }
    else if (!memcmp(logline, "HEAD ", 5))
    {
        /* head is just get w/no body */
        method = M_HEAD;
        printf("http method = HEAD\n");
    }
    else if (!memcmp(logline, "POST ", 5))
    {
        method = M_POST;
        printf("http method = POST\n");
    }
    else {
        //log_error_time();
        //fprintf(stderr, "malformed request: \"%s\"\n", req->logline);
        //send_r_not_implemented(req);
        perror("malformed request\n");
        return -1;
    }
    PARSE_HEAD_OPTION = 1;//设置解析http头选项的标志位

    /* Guaranteed to find ' ' since we matched a method above */
    stop = logline + 3;
    if (*stop != ' ')
        ++stop;

    /* scan to start of non-whitespace */
    while (*(++stop) == ' ');

    stop2 = stop;

    /* scan to end of non-whitespace */
    while (*stop2 != '\0' && *stop2 != ' ')
        ++stop2;

    if (stop2 - stop > MAX_HEADER_LENGTH) {
        //log_error_time();
        //fprintf(stderr, "URI too long %d: \"%s\"\n", MAX_HEADER_LENGTH,
        //        req->logline);
        //send_r_bad_request(req);
        perror("URI too long");
        return -1;
    }
    memcpy(request_uri, stop, stop2 - stop);
    request_uri[stop2 - stop] = '\0';
    printf("request uri = %s\n",request_uri);
    if (*stop2 == ' ') 
    {
        /* if found, we should get an HTTP/x.x */
        unsigned int p1, p2;

        /* scan to end of whitespace */
        ++stop2;
        while (*stop2 == ' ' && *stop2 != '\0')
            ++stop2;

        /* scan in HTTP/major.minor */
        if (sscanf(stop2, "HTTP/%u.%u", &p1, &p2) == 2) 
        {
            /* HTTP/{0.9,1.0,1.1} */
            if (p1 == 1 && (p2 == 0 || p2 == 1)) 
            {
                http_version = stop2;
                printf("http version = %s\n",http_version);
            } 
            else if (p1 > 1 || (p1 != 0 && p2 > 1)) 
            {
                goto BAD_VERSION;
            }
        } 
        else {
            goto BAD_VERSION;
        }
    }

    return 0;

    BAD_VERSION:
    //log_error_time();
    //fprintf(stderr, "bogus HTTP version: \"%s\"\n", stop2);
    //send_r_bad_request(req);
    perror("bogus HTTP version");
    return -1;
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
    char *if_modified_since;    /* If-Modified-Since */
    char *content_type;
    char *content_length;
    char *keepalive;
    char *header_referer;
    char *header_user_agent;

    char c, *value, *line = buff;

    value = strchr(line, ':');
    if (value == NULL)
        return 0;//表示解析结束
    *value++ = '\0';            /* overwrite the : */
    to_upper(line);             /* header types are case-insensitive */
    while ((c = *value) && (c == ' ' || c == '\t'))
        value++;

    if (!memcmp(line, "IF_MODIFIED_SINCE", 17)){
        if_modified_since = value;
        printf("IF_MODIFIED_SINCE:%s\n",if_modified_since);
    }
    else if (!memcmp(line, "CONTENT_TYPE", 12)){
        content_type = value;
        printf("CONTENT_TYPE:%s\n",content_type);
    }
    else if (!memcmp(line, "CONTENT_LENGTH", 14)){
        content_length = value;
        printf("CONTENT_LENGTH:%s\n",content_length);
    }
    else if (!memcmp(line, "CONNECTION", 10) ) {         
        keepalive = value;
        printf("CONNECTION:%s\n",keepalive);
    }
    else if (!memcmp(line, "REFERER", 7)) {
        header_referer = value;
        printf("REFERER:%s\n",header_referer);
    } 
    else if (!memcmp(line, "USER_AGENT", 10)) {
        header_user_agent = value;
        printf("USER_AGENT:%s\n",header_user_agent);
    }
    return 0;
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



