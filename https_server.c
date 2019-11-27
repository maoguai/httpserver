//httpserver
#include <stdio.h>
#include <stdlib.h>
#include <evhttp.h>
#include <event.h>
#include <string.h>

#include "event2/http.h"
#include "event2/event.h"
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include <event2/bufferevent_ssl.h>
#include "event2/bufferevent_compat.h"
#include "event2/http_struct.h"
#include "event2/http_compat.h"
#include "event2/util.h"
#include "event2/listener.h"
#include <event2/keyvalq_struct.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <unistd.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUF_MAX 1024*16
#define MYHTTPD_SIGNATURE   "httpserver v 0.0.1"
char *find_http_header(struct evhttp_request *req,struct evkeyvalq *params,const char *query_char);
//解析post请求数据
void get_post_message(char *buf, struct evhttp_request *req)
{
	size_t post_size = 0;
	
	post_size = evbuffer_get_length(req->input_buffer);//获取数据长度
	printf("====line:%d,post len:%d\n",__LINE__,post_size);
	if (post_size <= 0)
	{
		printf("====line:%d,post msg is empty!\n",__LINE__);
		return;
	}
	else
	{
		size_t copy_len = post_size > BUF_MAX ? BUF_MAX : post_size;
		printf("====line:%d,post len:%d, copy_len:%d\n",__LINE__,post_size,copy_len);
		memcpy(buf, evbuffer_pullup(req->input_buffer,-1), copy_len);
		buf[post_size] = '\0';
		printf("====line:%d,post msg:%s\n",__LINE__,buf);
	}
}


//识别/r/n开头
//识别--------结尾
//处理post请求
void http_handler_testpost_msg(struct evhttp_request *req,void *arg)
{
	if(req == NULL)
	{
		printf("====line:%d,%s\n",__LINE__,"input param req is null.");
		return;
	}
	if (evhttp_request_get_command (req) != EVHTTP_REQ_POST)
	{
		return;
	}
    printf("====line:%d,%s\n",__LINE__,"post");
	char *file = NULL;
 	char filetype[1024];
 	struct evkeyvalq file_params = {0};
 	file = find_http_header(req,&file_params,"file");//获取get请求uri中的file参数
	//get_post_message(buf, req);//获取请求数据，一般是json格式的数据
    printf("====line:%d,get request param: file=[%s]\n",__LINE__,file);
	get_filetype(file, filetype);
	/* Decode the payload */
    struct evbuffer *buf = evhttp_request_get_input_buffer (req);
    evbuffer_enable_locking(buf, NULL);
    evbuffer_add (buf, "", 1);    /* NUL-terminate the buffer */
    char *payload = (char *) evbuffer_pullup (buf, -1);
    int post_data_len = evbuffer_get_length(buf);
	printf("file:-%s-%d\n", file, post_data_len);
    char request_data_buf[BUF_MAX] = {0};
    post_data_len = 3000;
    memcpy(request_data_buf, payload, post_data_len);
    printf("%s\n", request_data_buf);
    
    struct evbuffer *removebuf = evbuffer_new();
    size_t len = evbuffer_get_length(buf);
    char * line = evbuffer_readln( buf , &len , EVBUFFER_EOL_CRLF_STRICT);
    
    //--------------
    if ( line != NULL) {
        printf("===evbuffer_readln(--------------): line[%s] len[%d]===\n" , line , len);
        free(line);
    }
    //Content-Disposition
    line = evbuffer_readln( buf , &len , EVBUFFER_EOL_CRLF_STRICT);
    if ( line != NULL) {
        printf("===evbuffer_readln(Content-Disposition): line[%s] len[%d]===\n" , line , len);
        free(line);
    }
    //Content-Type
    line = evbuffer_readln( buf , &len , EVBUFFER_EOL_CRLF_STRICT);
    if ( line != NULL) {
        printf("===evbuffer_readln(Content-Type): line[%s] len[%d]===\n" , line , len);
        free(line);
    }
    //\r\n
    line = evbuffer_readln( buf , &len , EVBUFFER_EOL_CRLF_STRICT);
    if ( line != NULL) {
        printf("===evbuffer_readln(\r\n): line[%s] len[%d]===\n" , line , len);
        free(line);
    }
    
    //file
    line = evbuffer_readln( buf , &len , EVBUFFER_EOL_CRLF_STRICT);
    if ( line != NULL) {
        printf("===evbuffer_readln(file): line[] len[%d]===\n"  , len);
        FILE *fp = NULL;
        fp = fopen(file, "wb");   //以二进制写入,创建文件
        if (fp == NULL)
        {
            printf("file not found \n");
            fclose(fp);
            return ;
        }
        char result[BUF_MAX] = {0};
        memcpy(result, line, len);
        fputs(result, fp);
        fclose(fp);
        free(line);
    }
    /*
    FILE *fp = NULL;
    fp = fopen(file, "wb");   //以二进制写入,创建文件
    if (fp == NULL)
    {
       printf("file not found \n");
       fclose(fp);
       return ;
    }
    fputs(line, fp);
    fclose(fp);
    free(line);
    */
	//回响应
	struct evbuffer *retbuff = NULL;
	retbuff = evbuffer_new();
	if(retbuff == NULL)
	{
		printf("====line:%d,%s\n",__LINE__,"retbuff is null.");
		return;
	}
	evbuffer_add_printf(retbuff,"Receive post file");
	evhttp_send_reply(req,HTTP_OK,"Client",retbuff);
	evbuffer_free(retbuff);
}

//解析http头，主要用于get请求时解析uri和请求参数
char *find_http_header(struct evhttp_request *req,struct evkeyvalq *params,const char *query_char)
{
	if(req == NULL || params == NULL || query_char == NULL)
	{
		printf("====line:%d,%s\n",__LINE__,"input params is null.");
		return NULL;
	}
	
	struct evhttp_uri *decoded = NULL;
	char *query = NULL;	
	char *query_result = NULL;
	const char *path;
	const char *uri = evhttp_request_get_uri(req);//获取请求uri
	
	if(uri == NULL)
	{
		printf("====line:%d,evhttp_request_get_uri return null\n",__LINE__);
		return NULL;
	}
	else
	{
		printf("====line:%d,Got a request for <%s>\n",__LINE__,uri);
	}
	
	//解码uri
	decoded = evhttp_uri_parse(uri);
	if (!decoded) 
	{
		printf("====line:%d,It's not a good URI. Sending BADREQUEST\n",__LINE__);
		evhttp_send_error(req, HTTP_BADREQUEST, 0);
		return;
	}
	
	//获取uri中的path部分
	path = evhttp_uri_get_path(decoded);
	if (path == NULL) 
	{
		path = "/";
	}
	else
	{
		printf("====line:%d,path is:%s\n",__LINE__,path);
	}
	
	//获取uri中的参数部分
	query = (char*)evhttp_uri_get_query(decoded);
	if(query == NULL)
	{
		printf("====line:%d,evhttp_uri_get_query return null\n",__LINE__);
		return NULL;
	}
	
	//查询指定参数的值
	evhttp_parse_query_str(query, params);			
	query_result = (char*)evhttp_find_header(params, query_char);
	
	return query_result;
}
//文件类型
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

//内存映射
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
//内存释放
void Munmap(void *start, size_t length) 
{
    if (munmap(start, length) < 0)
    {
        perror("munmap error");
        exit(0);
    }
}

//处理请求
void http_handler_testget_msg(struct evhttp_request *req,void *arg)
{
	if(req == NULL)
	{
		printf("====line:%d,%s\n",__LINE__,"input param req is null.");
		return;
	}
	if (evhttp_request_get_command (req) == EVHTTP_REQ_GET)
    {
 		int srcfd;
 		struct stat sbuf;
 		char *file = NULL;
 		char *srcp,filetype[1024];
 		struct evkeyvalq file_params = {0};
 		file = find_http_header(req,&file_params,"file");//获取get请求uri中的file参数
 		if(file == NULL)
 		{
 			printf("====line:%d,%s\n",__LINE__,"request uri no param file.");
 		}
 		else
 		{
 			printf("====line:%d,get request param: file=[%s]\n",__LINE__,file);
 		}

 		if (stat(file, &sbuf) < 0) 
  		 {
  		     printf("couldn't find this file");
  		     return;
  		 }
  		get_filetype(file, filetype);
 		printf("文件处理\n");
 		if((srcfd = open(file, O_RDONLY, 0)) < 0)
  		     printf("open file error");
  		 //将文件内容映射到虚拟内存中，提高文件的读写效率
  		 srcp = Mmap(0, sbuf.st_size, PROT_READ, MAP_PRIVATE, srcfd, 0);
  		 close(srcfd);   
 		//回响应
 		struct evbuffer *retbuff = NULL;
 		retbuff = evbuffer_new();
 		if(retbuff == NULL)
 		{
 			printf("====line:%d,%s\n",__LINE__,"retbuff is null.");
 			return;
 		}
 		evhttp_add_header(req->output_headers, "Server", MYHTTPD_SIGNATURE);
  		 evhttp_add_header(req->output_headers, "Content-Type", filetype);
  		 //evhttp_add_header(req->output_headers, "Connection", "close");
 		evbuffer_add(retbuff,srcp,sbuf.st_size);
 		//常规
 		//evhttp_send_reply(req,HTTP_OK,"Client",retbuff);
 		//chunk发送
 		evhttp_send_reply_start(req,HTTP_OK, "Client");
 		evhttp_send_reply_chunk (req,retbuff);
 		evhttp_send_reply_end (req);
 		Munmap(srcp, sbuf.st_size);
 		evbuffer_free(retbuff);
	}
}
static void server_setup_certs (SSL_CTX *ctx,
        const char *certificate_chain,
        const char *private_key)
{ 
    printf ("Loading certificate chain from '%s'\n"
            "and private key from '%s'\n",
            certificate_chain, private_key);

    if (1 != SSL_CTX_use_certificate_chain_file (ctx, certificate_chain))
        die_most_horribly_from_openssl_error ("SSL_CTX_use_certificate_chain_file");

    if (1 != SSL_CTX_use_PrivateKey_file (ctx, private_key, SSL_FILETYPE_PEM))
        die_most_horribly_from_openssl_error ("SSL_CTX_use_PrivateKey_file");

    if (1 != SSL_CTX_check_private_key (ctx))
        die_most_horribly_from_openssl_error ("SSL_CTX_check_private_key");
}

static struct bufferevent* bevcb (struct event_base *base, void *arg)
{ 
    struct bufferevent* r;
    SSL_CTX *ctx = (SSL_CTX *) arg;

    r = bufferevent_openssl_socket_new (base,
            -1,
            SSL_new (ctx),
            BUFFEREVENT_SSL_ACCEPTING,
            BEV_OPT_CLOSE_ON_FREE);
    return r;
}
/* 这个是调用openSSL提供的打印log接口 */
void die_most_horribly_from_openssl_error (const char *func)
{ 
    fprintf (stderr, "%s failed:\n", func);

    /* This is the OpenSSL function that prints the contents of the
     * error stack to the specified file handle. */
    ERR_print_errors_fp (stderr);

    exit (EXIT_FAILURE);
}
static void *my_zeroing_malloc (size_t howmuch)
{ 
    return calloc (1, howmuch); 
}

void common_setup (void)
{ 
    signal (SIGPIPE, SIG_IGN);

    CRYPTO_set_mem_functions (my_zeroing_malloc, realloc, free);
    SSL_library_init ();
    SSL_load_error_strings ();
    OpenSSL_add_all_algorithms ();

    printf ("Using OpenSSL version \"%s\"\nand libevent version \"%s\"\n",
            SSLeay_version (SSLEAY_VERSION),
            event_get_version ());
}
void show_help() {
    char *help = "http://localhost:8080\n"
        "-l <ip_addr> interface to listen on, default is 0.0.0.0\n"
        "-p <num>     port number to listen on, default is 1984\n"
        "-d           run as a deamon\n"
        "-t <second>  timeout for a http request, default is 120 seconds\n"
        "-h           print this help and exit\n"
        "\n";
    fprintf(stderr,"%s",help);
}
//当向进程发出SIGTERM/SIGHUP/SIGINT/SIGQUIT的时候，终止event的事件侦听循环
void signal_handler(int sig) {
    switch (sig) {
        case SIGTERM:
        case SIGHUP:
        case SIGQUIT:
        case SIGINT:
            event_loopbreak();  //终止侦听event_dispatch()的事件侦听循环，执行之后的代码
            break;
    }
}

int main(int argc, char *argv[])
{
	//自定义信号处理函数
    signal(SIGHUP, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);

	struct evhttp *http_server = NULL;
	short http_port = 8081;
	char *http_addr = "127.0.0.1";
	int httpd_option_daemon = 0;
    int httpd_option_timeout = 120; //in seconds

    //获取参数
    int c;
    while ((c = getopt(argc, argv, "l:p:dt:h")) != -1) {
        switch (c) {
            case 'l' :
                http_addr = optarg;
                break;
            case 'p' :
                http_port = atoi(optarg);
                break;
            case 'd' :
                httpd_option_daemon = 1;
                break;
            case 't' :
                httpd_option_timeout = atoi(optarg);
                break;
            case 'h' :
            default :
                show_help();
                exit(EXIT_SUCCESS);
        }
    }

    //判断是否设置了-d，以daemon运行
    if (httpd_option_daemon) {
        pid_t pid;
        pid = fork();
        if (pid < 0) {
            perror("fork failed");
            exit(EXIT_FAILURE);
        }
        if (pid > 0) {
            //生成子进程成功，退出父进程
            exit(EXIT_SUCCESS);
        }
    }

    //SSL
    /*OpenSSL 初始化 */
    common_setup (); 

	//初始化
	event_init();
	//启动http服务端
	http_server = evhttp_start(http_addr,http_port);
	if(http_server == NULL)
	{
		printf("====line:%d,%s\n",__LINE__,"http server start failed.");
		return -1;
	}
	/* 创建SSL上下文环境 ，可以理解为 SSL句柄 */
    SSL_CTX *ctx = SSL_CTX_new (SSLv23_server_method ());
    SSL_CTX_set_options (ctx,
            SSL_OP_SINGLE_DH_USE |
            SSL_OP_SINGLE_ECDH_USE |
            SSL_OP_NO_SSLv2);

    EC_KEY *ecdh = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
    if (! ecdh)
        die_most_horribly_from_openssl_error ("EC_KEY_new_by_curve_name");
    if (1 != SSL_CTX_set_tmp_ecdh (ctx, ecdh))
        die_most_horribly_from_openssl_error ("SSL_CTX_set_tmp_ecdh");
    /* 选择服务器证书 和 服务器私钥. */
    const char *certificate_chain = "server-certificate-chain.pem";
    const char *private_key = "server-private-key.pem";
    /* 设置服务器证书 和 服务器私钥 到 
     OPENSSL ctx上下文句柄中 */
    server_setup_certs (ctx, certificate_chain, private_key);
    /* 
        使我们创建好的evhttp句柄 支持 SSL加密
        实际上，加密的动作和解密的动作都已经帮
        我们自动完成，我们拿到的数据就已经解密之后的
    */
    evhttp_set_bevcb (http_server, bevcb, ctx);
	//设置请求超时时间(s)
	evhttp_set_timeout(http_server,httpd_option_timeout);
	//设置事件处理函数，evhttp_set_cb针对每一个事件(请求)注册一个处理函数，
	//区别于evhttp_set_gencb函数，是对所有请求设置一个统一的处理函数
	evhttp_set_cb(http_server,"/post",http_handler_testpost_msg,NULL);
	evhttp_set_cb(http_server,"/get",http_handler_testget_msg,NULL);
	
	//循环监听
	event_dispatch();
	//实际上不会释放，代码不会运行到这一步
	evhttp_free(http_server);
		
	return 0;
}