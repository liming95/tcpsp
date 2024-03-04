#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <pthread.h>

#define  MAX_LINE 8192
#define  PORT 10001
#define  LISTENQ 6666


struct _server_data{
	uint8_t listenfd;
	uint8_t connfd;
	uint8_t buf[MAX_LINE];
	uint32_t buflen;
};
struct _server_data server_data;

int server_init()
{
	/*声明服务器地址和客户链接地址*/
	struct sockaddr_in servaddr , cliaddr;
	
	pid_t childpid;

	/*声明缓冲区*/
	socklen_t clilen;

	/*(1) 初始化监听套接字listenfd*/
	if((server_data.listenfd = socket(AF_INET , SOCK_STREAM , 0)) < 0)
	{
		perror("socket error");
		exit(1);
	}//if
	
	/*(2) 设置服务器sockaddr_in结构*/
	bzero(&servaddr , sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); //表明可接受任意IP地址
	servaddr.sin_port = htons(PORT);

	/*(3) 绑定套接字和端口*/
	if(bind(server_data.listenfd , (struct sockaddr*)&servaddr , sizeof(servaddr)) < 0)
	{
		perror("bind error");
		exit(1);
	}//if

	/*(4) 监听客户请求*/
	if(listen(server_data.listenfd , LISTENQ) < 0)
	{
		perror("listen error");
		exit(1);
	}//if
		
	clilen = sizeof(cliaddr);
	if((server_data.connfd = accept(server_data.listenfd , (struct sockaddr *)&cliaddr , &clilen)) < 0 )
	{
		perror("accept error");
		exit(1);
	}//if
	printf("...fd:%d\n",server_data.connfd);
	return 0;
}

int server_msg_proc()
{
	/*接受客户请求*/
	server_data.buflen = read(server_data.connfd , server_data.buf , MAX_LINE);
	if(server_data.buflen > 0)
	{
		int count = 0;
//		for(count = 0; count < server_data.buflen; count++)
//		{
//			printf("buf[%d] = %d\n", count, server_data.buf[count]);
//		}
		// printf("read %d bytes, the content is %s\n", server_data.buflen, server_data.buf);
	        int send_len = write(server_data.connfd, server_data.buf, server_data.buflen);
		// printf("write %d bytes, the content is %s\n", send_len, server_data.buf);
		memset(server_data.buf, 0, MAX_LINE);

		return 0;
	}//while
	return -1;
}

int server_close()
{
	close(server_data.connfd);
	/*关闭监听套接字*/
	close(server_data.listenfd);
}
void* pthread_socket()
{
	int ret;
	pthread_detach(pthread_self());
	ret = server_init();					//创建用于通信的套接字
	printf("ret = %d, server_data.connfd = %d, server_data.listenfd = %d\n", ret, server_data.connfd, server_data.listenfd);
	for(;;)
	{
		if(server_data.connfd < 0)
		{
			printf("初始化失败，请重试！\n");
			return 0;
		}
		while(1)
		{
			ret = server_msg_proc();
//		    if(ret = -1)
//			{
//		 		printf("数据读取完毕！\n");
//				return 0;
//			}
		}
	}//for
	server_close();
}



void pthread_socket_start()		//创建线程函数
{
	pthread_t threadbx;
	int ret_thread;
	ret_thread = pthread_create(&threadbx, NULL, pthread_socket, NULL);
	if (ret_thread != 0){
		printf("线程创建失败\n");
	}
	else{
   		printf("线程创建成功\n");
	}
}
int main(int arg, char **argc)
{
	pthread_socket_start();
	sleep(~0l);
	return 0;
}

