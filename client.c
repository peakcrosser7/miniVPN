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
#include <termios.h> //隐藏密码
#include <signal.h>  //处理 ctrl+c 信号并向服务端发送终止指令

/* define HOME to be dir for key and cert files... */
// 证书根目录
#define HOME "./cert_server/"
/* Make these what you want for cert & key files */

#define CACERT HOME "ca.crt"
// #define CERTF HOME "client.crt"
// #define KEYF HOME "client.key"

#define CHK_SSL(err)                 \
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


//证书验证
int verifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    char buf[300];
    X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("certificate subject= %s\n", buf);

    if (preverify_ok == 0) {
        int err = X509_STORE_CTX_get_error(x509_ctx);
        printf("Verification failed: %s.\n",
               X509_verify_cert_error_string(err));
        return 0;   //返回0结束TLS握手连接
    }
    printf("Verification passed.\n");
    return 1;   //返回1继续TLS连接
}

//创建虚拟网卡设备
//虚拟网卡绑定一个设备以及一个TCP套接字
int createTunDevice(int virtualIP) {
    int tunfd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    //IFF_TUN:表示创建一个TUN设备
    //IFF_NO_PI:表示不包含包头信息

    //打开TUN设备
    tunfd = open("/dev/net/tun", O_RDWR);
    if (tunfd == -1) {
        printf("Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    //注册设备工作模式
    int ret = ioctl(tunfd, TUNSETIFF, &ifr);
    if (ret == -1) {
        printf("Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    printf("Create a tun device :%s\n", ifr.ifr_name);
    //虚拟设备编号
    int tunId = atoi(ifr.ifr_name+3);

    char cmd[60];
    //将虚拟IP绑定到TUN设备上
    sprintf(cmd,"sudo ifconfig tun%d 192.168.53.%d/24 up",tunId, virtualIP);
    system(cmd);
    //将发送给192.168.60.0/24的数据包交由TUN设备处理
    sprintf(cmd,"sudo route add -net 192.168.60.0/24 dev tun%d",tunId);
    system(cmd);
    return tunfd;
}

//初始化TLS客户端
SSL *setupTLSClient(const char *hostname) {
    // Step 0: OpenSSL library initialization
    // This step is no longer needed as of version 1.1.0.
    //初始化OpenSSL库
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    SSL_METHOD *meth = (SSL_METHOD *)SSLv23_client_method();
    //创建会话协议
    SSL_CTX *ctx = SSL_CTX_new(meth);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        // exit(2);
    }
    
    //设置证书验证方式
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verifyCallback);
    //加载证书
    if (SSL_CTX_load_verify_locations(ctx, CACERT, NULL) < 1)  {
        printf("Error setting the verify locations. \n");
        exit(0);
    }

    // if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     exit(-2);
    // }
    // if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     exit(-3);
    // }
    // if (!SSL_CTX_check_private_key(ctx)) {
    //     printf("Private key does not match the certificate public keyn");
    //     exit(-4);
    // }

    SSL *ssl = SSL_new(ctx);
    X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);
    SSL_CTX_free(ctx);
    return ssl;
}


//初始化TCP客户端
int setupTCPClient(const char *hostname, int port) {
    struct sockaddr_in serverAddr;

    // 由域名获取IP地址
    struct hostent *hp = gethostbyname(hostname);

    // 创建TCP套接字
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(sockfd,"socket");

    // 填充服务端信息(IP, 端口号, 协议族)
    memset(&serverAddr, '\0', sizeof(serverAddr));
    memcpy(&(serverAddr.sin_addr.s_addr), hp->h_addr, hp->h_length);
    //   server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14");
    serverAddr.sin_port = htons(port);
    serverAddr.sin_family = AF_INET;

    // 与服务端建立连接
    connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    printf("TCP connect succeed! hostname IP:%s port:%d\n", inet_ntoa(serverAddr.sin_addr), port);
    return sockfd;
}


int mygetch() {
    struct termios oldt, newt;
    int ch;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return ch;
}

//输入密码函数
int getPasswd(char *passwd, int size) {
    int c, n = 0;
    do {
        c = mygetch();
        if (c != '\n' && c != '\r' && c != 127) {
            passwd[n] = c;
            printf("*");
            n++;
        } else if ((c != '\n' | c != '\r') && c == 127) { //判断是否是回车或则退格
            if (n > 0) {
                n--;
                printf("\b \b"); //输出退格
            }
        }
    } while (c != '\n' && c != '\r' && n < (size - 1));
    passwd[n] = '\0'; //消除一个多余的回车
    putchar('\n');
    return n;
}

//客户端认证
int verifyClient(SSL *ssl) {
    char username[20];
    char passwd[20];
    char recvBuf[BUFF_SIZE];
    int len = SSL_read(ssl,recvBuf,BUFF_SIZE);
    
    //输入用户名
    printf("%s\n",recvBuf);
    scanf("%s", username);
    getchar();
    SSL_write(ssl,username,strlen(username)+1);
    //输入密码
    SSL_read(ssl,recvBuf,BUFF_SIZE);
    printf("%s\n",recvBuf);
    getPasswd(passwd, 20);
    SSL_write(ssl,passwd,strlen(passwd)+1);
    //获取验证结果
    SSL_read(ssl,recvBuf,BUFF_SIZE);

    if(strcmp(recvBuf, "Client verify succeed") != 0) {
        printf("Client verify failed!\n");
        return -1;
    }
    printf("Client verify succeed\n");
    return 1;
}

void sendRequest(SSL* ssl) {
    char msg[]="Hello VPN!";
    int len = SSL_write(ssl,msg,strlen(msg)+1);
    CHK_SSL(len);
    char recvBuf[BUFF_SIZE];
    len = SSL_read(ssl,recvBuf,BUFF_SIZE);
    CHK_SSL(len);
    printf("Got %d bytes: %s\n",len,recvBuf);
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

    len = SSL_read(ssl, buff, BUFF_SIZE- 1);    //从套接字读取数据
    if(len == 0) {
        printf("[ <- tunnel ] Socket closed\n");
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
        FD_ZERO(&readFDSet);        //将文件描述符集清空
        FD_SET(sockfd, &readFDSet); //将套接字描述符加入集合
        FD_SET(tunfd, &readFDSet);  //将设备端口加入集合
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
        //监听到TUN设备就绪
        if (FD_ISSET(tunfd, &readFDSet)) {
            tunSelected(ssl, tunfd);
        }
        //监听到套接字就绪
        if (FD_ISSET(sockfd, &readFDSet)) {
            if(socketSelected(ssl, tunfd) == 0){
                printf("VPN Server Closed\n");
                return;
            }
        }
    }
}

//获取服务端分配的虚拟IP
int recvVirtualIP(SSL* ssl) {
    char buf[10];
    SSL_read(ssl,buf,10);
    int virtualIP = atoi(buf);
    printf("virtualIP: 192.168.53.%d/24\n",virtualIP);
    return virtualIP;
}


int main(int argc, char *argv[]) {
    char *hostname = "hhyServer.com";   //服务器主机域名
    int port = 4433;    //服务器主机端口

    if(argc > 1) hostname = argv[1];
    if(argc > 2) port = atoi(argv[2]);

    /*----------------TLS initialization ----------------*/
    SSL *ssl = setupTLSClient(hostname);

    /*----------------Create a TCP connection ---------------*/
    int sockfd = setupTCPClient(hostname, port);

    /*----------------TLS handshake ---------------------*/
    SSL_set_fd(ssl, sockfd); 
    int err = SSL_connect(ssl);
    if(err <= 0) {
        printf("SSL_connect failed!\n");
        close(sockfd);
        return 0;
    }

    printf("SSL connection is successful\n");
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    /*----------------Verify client ---------------------*/
    if (verifyClient(ssl) != 1) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        exit(2);
    }

    // sendRequest(ssl);

    /*----------------Receive Virtual IP ---------------------*/
    int virtualIP = recvVirtualIP(ssl);

    /*----------------Create TUN device ---------------------*/
    int tunfd = createTunDevice(virtualIP);

    /*----------------Send/Receive data --------------------*/
    selectTunnel(ssl,sockfd,tunfd);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    return 0;
}
