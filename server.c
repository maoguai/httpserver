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

/*-------------------------函数申明--------------------------*/
void select_loop(int server_s);               /*处理客户端请求*/
int process_requests(int server_s);                /*报文解析*/

int header_parse(char *buff, int len);           /*解析http头*/
int http_head_parse(char *buff);             /*解析http请求行*/
int http_option_parse(char *buff);         /*解析http请求头部*/
char *to_upper(char *str);                       /*字符串大写*/
int body_read_parse();                         /*http请求处理*/
void serve_static(int fd, char *filename, int filesize);
                                               /*静态请求处理*/
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
            //body_read_parse();
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





