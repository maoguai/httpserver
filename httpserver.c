//httpserver.c

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

/*-------------------------全局变量--------------------------*/
#define PORT 6666
#define BUFFER_SIZE 4096
#define MAX_QUE_CONN_NM 5
#define FILE_NAME_MAX 512
#define SOCKADDR sockaddr_in
#define S_FAMILY sin_family
#define SERVER_AF AF_INET
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
int http_head_parse(char *buff)              /*解析http请求行*/


/*------------------------解析http头-------------------------*/
int header_parse(char *buff, int len)
{
	char *parse_buff = buff;              /*等待解析的http文件*/
	int status = READ_HEADER;          /*设置启始状态为读取状态*/
	int parse_num = 0;                      /*解析过的字符串数*/
	while(parse_buff < (buff + len))
	{
		switch (status) {
        case READ_HEADER:
            if (*parse_buff == '\r') {
                status = ONE_CR;
            } else if (*parse_buff == '\n') {
                status = ONE_LF;
            }
            break;

        case ONE_CR:
            if (*parse_buff == '\n')
                 status = ONE_LF;
            else if (*parse_buff != '\r')
                 status = READ_HEADER;
            break;

        case ONE_LF:
            if (*parse_buff == '\r') 
                status = TWO_CR;
            else if (*parse_buff == '\n')
                status = BODY_READ;
            else
                status = READ_HEADER;
            break;

        case TWO_CR:
            if (*parse_buff == '\n')
                status = BODY_READ;
            else if (*parse_buff != '\r')
                status = READ_HEADER;
            break;

        default:
            break;
        }

        parse_buff++;                       /*更新等待解析http*/
        parse_num++;                        /*更新解析http字数*/

        if(status == ONE_LF)             /*请求方法或者请求头部*/
        {
              
        }
        else if(status == BODY_READ)				  /*正文*/
        {

        }

	}
}

/*----------------------解析http请求行----————---------------*/
int http_head_parse(char *buff)
{
    int method;                   /*请求http方法，GET or POST*/
    char *uri;
    char version;

    char *parse_buff = buff;
    char *parse_buff_stop;
    int head_long = 0;
    /*判断请求方法*/
    if(!memcmp(parse_buff,"GET",3))
    {
        method = M_GET;
        head_long = 3;
        printf("GET\n");
    }
    else if(!memcmp(parse_buff,"POST",4))
    {
        method = M_POST;
        head_long = 4;
        printf("POST\n");
    }
    else
    {
        perror("malformed request\n");
        return -1;
    }
    PARSE_HEAD_OPTION = 1;
    /*parse_buff移动到uri起始处;parse_buff_stop移动到uri结尾处*/
    parse_buff = parse_buff + head_long;
    while(*(++parse_buff) == ' ')
    parse_buff_stop = parse_buff;    
    while(*parse_buff_stop != '\0' && *parse_buff_stop != ' ')
    {
        ++parse_buff_stop;
    }

    memcpy(uri,parse_buff,parse_buff_stop - parse_buff);
    printf("%s\n",uri);

    /*解析http版本*/
    if(*parse_buff_stop == ' ')
    {
        /*移动到http版本头部*/
        ++parse_buff_stop;
        while(*parse_buff_stop == '\0' && *parse_buff_stop == ' ')
        {
            ++parse_buff_stop;
        }
        int p1,p2;
        if (sscanf(parse_buff_stop, "HTTP/%u.%u", &p1, &p2) == 2) 
        {
            if (p1 == 1 && (p2 == 0 || p2 == 1)) 
            {
                version = parse_buff_stop;
                printf("%s\n",version);
            } else if (p1 > 1 || (p1 != 0 && p2 > 1)) 
            {
                perror("bad HTTP version");
                return -1;
            }
        }
        else
        {
            perror("bad HTTP version");
            return -1;
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
    printf("recv from client:%s\n",buff);
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



