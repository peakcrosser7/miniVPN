#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <shadow.h>
#include <crypt.h> //client verify
#include <memory.h>
#include <pthread.h>


/* define HOME to be dir for key and cert files... */
// 证书根目录
#define HOME "./cert_server/"
/* Make these what you want for cert & key files */
#define CERTF HOME "server.crt"
#define KEYF HOME "server.key"
#define CACERT HOME "ca.crt"

#define  CHK_SSL(err)                 \
    if ((err) < 1)                   \
    {                                \
        ERR_print_errors_fp(stderr); \
        exit(2);                     \
    }
#define CHK_NULL(x)  \
    if ((x) == NULL) \
    exit(1)
#define CHK_ERR(err, s) \
    if ((err) == -1)    \
    {                   \
        perror(s);      \
        exit(1);        \
    }

#define BUFF_SIZE 2000  

//监听端口号
int ListenPort = 4433;
SSL_CTX* ctx;

//初始化TLS服务端
SSL_CTX* setupTLSServer() {
    SSL_METHOD *meth;
    SSL_CTX *ctx;

    // Step 0: OpenSSL library initialization
    // This step is no longer needed as of version 1.1.0.
    // 初始化OpenSSL库
    SSL_library_init();             //使用OpenSSL前的协议初始化工作 
    SSL_load_error_strings();       //加载错误处理机制，打印出一些方便阅读的调试信息
    SSLeay_add_ssl_algorithms();    // 添加SSL的加密/HASH算法

    // Step 1: SSL context initialization
    // SSL上下文初始化
    meth = (SSL_METHOD *)SSLv23_server_method(); //选择会话协议
    //创建会话协议
    ctx = SSL_CTX_new(meth);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(2);
    }
    //制定证书验证方式
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

    // Step 2: Set up the server certificate and private key
    //设置服务器证书和私钥
    //为SSL会话加载用户证书
    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(3);
    }
    //为SSL会话加载用户私钥
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(4);
    }
    //验证私钥和证书是否相符
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(5);
    } else {
        printf("Private key match the certificate public key\n");
    }
    return ctx;
}

//初始化TCP服务端
int setupTCPServer() {
    struct sockaddr_in serverAddr;
    int listenSock;
    //创建套接字
    listenSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listenSock, "socket");
    memset(&serverAddr, '\0', sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(ListenPort); //服务端端口4433
    //将端口和套接字进行绑定
    int err = bind(listenSock, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    CHK_ERR(err, "bind");
    //监听套接字
    err = listen(listenSock, 5); //等待连接队列的最大长度为5
    CHK_ERR(err, "listen");

    fprintf(stdout, "listenSock = %d\n", listenSock);
    return listenSock;
}

//登录函数
int login(char *user, char *passwd) {
	//shadow文件的结构体 
	struct spwd *pw = getspnam(user);    //从shadow文件中获取给定用户的帐户信息
	if (pw == NULL) return -1;

	printf("Login name: %s\n", user);       //用户登录名 
	// printf("Passwd: %s\n", passwd);         // 加密口令 

	char *epasswd = crypt(passwd, pw->sp_pwdp);   //对passwd进行加密 
	if (strcmp(epasswd, pw->sp_pwdp)) {
		return -1;
	}
	return 1;
}


//客户端验证
int verifyClient(SSL *ssl) {
    //获取用户名和密码
	char iptNameMsg[]="Please input username: ";
    SSL_write(ssl, iptNameMsg, strlen(iptNameMsg)+1);
    char username[BUFF_SIZE];
    int len = SSL_read(ssl, username, BUFF_SIZE);

    char iptPasswdMsg[]="Please input password: ";
    SSL_write(ssl, iptPasswdMsg, strlen(iptPasswdMsg)+1);
    char passwd[BUFF_SIZE];
    len = SSL_read(ssl, passwd, BUFF_SIZE);

    int r = login(username, passwd);
    if(r != 1){
        char no[] = "Client verify failed";
		printf("%s\n",no);
        SSL_write(ssl, no, strlen(no)+1);
		return -1; 
	}
    char yes[] = "Client verify succeed";
    printf("%s\n",yes);
    SSL_write(ssl, yes, strlen(yes)+1);
    return 1;
}


void processRequest(SSL* ssl) {
    char buf[1024];
    int len = SSL_read (ssl, buf, sizeof(buf));
    CHK_SSL(len);
    // buf[len] = '\0';
    printf("Received: %s\n",buf);

    // Construct and send the HTML page
    char html[] =
	"HTTP/1.1 200 OK\r\n"
	"Content-Type: text/html\r\n\r\n"
	"<!DOCTYPE html><html>"
	"<head><title>Hello World</title></head>"
	"<style>body {background-color: black}"
	"h1 {font-size:3cm; text-align: center; color: white;"
	"text-shadow: 0 0 3mm yellow}</style></head>"
	"<body><h1>Hello,HHY miniVPN!</h1></body></html>";
    len = SSL_write(ssl, html, strlen(html)+1);
    CHK_SSL(len);
}


pthread_mutex_t mutex;

//发送给客户端其虚拟IP
void sendVirtualIP(SSL* ssl, int virtualIP) {
    char buf[10];
    sprintf(buf,"%d",virtualIP);
    printf("send virtual IP: 192.168.53.%s/24\n",buf);
    SSL_write(ssl,buf,strlen(buf)+1);
}


//创建虚拟网卡设备
//虚拟网卡绑定一个设备以及一个TCP套接字
int createTunDevice(SSL* ssl, int* virtualIP) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    //IFF_TUN:表示创建一个TUN设备
    //IFF_NO_PI:表示不包含包头信息
  
    //创建虚拟网卡设备
    //此处由系统自己找合适的名称, 可用名称是一个共享的资源，需要加锁
    pthread_mutex_lock(&mutex);
    int tunfd = open("/dev/net/tun", O_RDWR);
    pthread_mutex_unlock(&mutex);
    if (tunfd == -1) {
        printf("Open TUN failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }

    //注册设备工作模式
    int ret = ioctl(tunfd, TUNSETIFF, &ifr);
    if (ret == -1) {
        printf("Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    printf("Create a tun device :%s\n", ifr.ifr_name);  //tunXXX

    //虚拟设备编号
    int tunId = atoi(ifr.ifr_name+3);
    if(tunId == 127) {
        printf("Exceed the maximum number of clients!\n");
        return -1;
    }

    //根据网卡名称配置服务端TUN设备的虚拟IP(IP=192.168.53.1+tunId)
    char cmd[60];
    sprintf(cmd,"sudo ifconfig tun%d 192.168.53.%d/24 up",tunId,tunId+1);
    // printf("%s\n",cmd);
    //根据虚拟设备设定分配给客户端TUN的虚拟IP地址, 并设置路由走当前创建的虚拟设备
    system(cmd);
    sprintf(cmd,"route add -host 192.168.53.%d tun%d",tunId+127,tunId);
    // printf("%s\n",cmd);
	system(cmd);
    system("sudo sysctl net.ipv4.ip_forward=1");

    *virtualIP = tunId + 127;   //分配给客户端TUN接口的虚拟IP
    return tunfd;
}


//向VPN隧道发送数据
//TUN数据就绪,将数据从TUN写到套接字进行发送
void tunSelected(SSL* ssl, int tunfd) {
    int len;
    char buff[BUFF_SIZE];
    bzero(buff, BUFF_SIZE);

    len = read(tunfd, buff, BUFF_SIZE); //从TUN设备中读取数据
    buff[len] = '\0';
    printf("[ ->tunnel ] Got a %d-byte packet from  TUN   and will write in socket\n", len);

    SSL_write(ssl, buff, len);  //将数据写入到套接字中
}


//从VPN隧道接收数据
//套接字数据就绪,将数据由套接字写到TUN设备进行后续读取
int socketSelected(SSL* ssl, int tunfd) {
    int len;
    char buff[BUFF_SIZE];
    bzero(buff, BUFF_SIZE);

    len = SSL_read(ssl, buff, BUFF_SIZE - 1); //从套接字读取数据
    if(len == 0) {
        printf("[ <-tunnel ] Socket closed\n");
        return 0;
    }
    buff[len] = '\0';
    printf("[ <-tunnel ] Got a %d-byte packet from socket and will write in  TUN\n", len);

    write(tunfd, buff, len);    //将数据写入TUN设备
    return 1;
}

//select监听套接字和虚拟设备
void selectTunnel(SSL* ssl, int sockfd, int tunfd) {
    while (1) {
        //使用select进行IO多路复用监听套接字和虚拟设备
        fd_set readFDSet;           //读取文件描述符集
        FD_ZERO (&readFDSet);        //将文件描述符集清空
        FD_SET(sockfd, &readFDSet); //将套接字描述符加入集合
        FD_SET(tunfd, &readFDSet);  //将设备端口加入集合
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
        //监听到TUN设备就绪
        if (FD_ISSET(tunfd, &readFDSet)) {
            tunSelected(ssl, tunfd);
        }
        //监听到套接字就绪
        if (FD_ISSET(sockfd, &readFDSet)) {
           if(socketSelected(ssl, tunfd)==0){
               printf("VPN Client Closed: sockfd = %d\n", sockfd);
               return;
           }
        }
    }
}


//线程处理函数
void *threadFunc(void *arg) {
    int sockfd = (int)arg;
   
    /*----------------TLS handshake ---------------------*/
    //新建SSL套接字
    SSL* ssl = SSL_new(ctx);
    //SSL绑定读写套接字为已建立连接的套接字
    SSL_set_fd(ssl, sockfd);
    //使用SSL_accept代替原accept完成连接握手
    int err = SSL_accept(ssl);
    if(err <= 0) {
        printf("SSL_accept failed!\n");
        close(sockfd);
        return NULL;
    }
    fprintf(stdout, "SSL_accept return %d\n", err);

    printf("SSL connection established!\n");
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    /*----------------Verify client ---------------------*/
    //客户端认证
    if (verifyClient(ssl) != 1) {
        //验证失败
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
        return NULL;   //子进程返回
    }

    // processRequest(ssl);

    /*----------------Create TUN device ---------------------*/
    //创建虚拟设备TUN
    int virtualIP;
    int tunfd = createTunDevice(ssl, &virtualIP);
    if(tunfd == -1) return NULL;

    /*----------------Send Virtual IP ---------------------*/
    sendVirtualIP(ssl,virtualIP);

    /*----------------Send/Receive data --------------------*/
    //select监听套接字和虚拟设备
    selectTunnel(ssl, sockfd, tunfd);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    return NULL;
}

//获取连接套接字
int acceptTCPClient(int listenSock) {
    struct sockaddr_in clientAddr;
    size_t clientAddrLen = sizeof(struct sockaddr_in);
    //从等待连接队列中获取创建的连接
    int sockfd = accept(listenSock, (struct sockaddr *)&clientAddr, &clientAddrLen);
    fprintf(stdout, "sockfd = %d\n", sockfd);

    if (sockfd == -1) {
        fprintf(stderr, "Accept TCP connect failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    printf("Connection from IP:%s port:%d\n", inet_ntoa(clientAddr.sin_addr), clientAddr.sin_port);
    return sockfd;
}


int main(int argc,char *argv[]) {
    //可选参数端口号
    if (argc>1) ListenPort=atoi(argv[1]);
    
    /*----------------TLS initialization ----------------*/
    ctx = setupTLSServer();

    /*----------------Create a TCP connection ---------------*/
    int listenSock = setupTCPServer();   //初始化TCP服务端

    while (1) {
        /*------------Accept TCP connection -----------------*/
        int sockfd = acceptTCPClient(listenSock);
        if(sockfd == -1) continue;

        /*-- -------Create a new thread for connection ------*/
        pthread_t tid;
        //创建新的线程处理连接
        int ret = pthread_create(&tid, NULL, threadFunc, (void*)sockfd);
        if (ret != 0) {
            close(sockfd);
            perror("pthread_create failed");
            return -1;
        } 
    }

    close(listenSock);
    SSL_CTX_free(ctx);
    return 0;    
}