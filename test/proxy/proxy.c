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

#define listen_ip   INADDR_ANY
#define listen_port 15001

#define connect_ip   "192.168.122.1"
#define connect_port 10001

#define LISTEN 0
#define CONNECT 1

#define MAX_LINE 1024
#define LISTENQ 6666

typedef struct server_data_{
	uint8_t listenfd;
	uint8_t connfd;
	uint8_t tx_buf[MAX_LINE];
	uint32_t tx_buflen;
	uint8_t rx_buf[MAX_LINE];
	uint32_t rx_buflen;
} server_data_t;

typedef struct client_data{
	uint8_t connfd;
	uint8_t tx_buf[MAX_LINE];
	uint32_t tx_buflen;
	uint8_t rx_buf[MAX_LINE];
	uint32_t rx_buflen;
} client_data_t;

typedef struct socket_{
	int socket_type;                 //listen(server), connect(client)
	struct sockaddr_in local_info;
	struct sockaddr_in remote_info;
} socket_t;

typedef struct vcl_seeion_pair_{
	int session_pair_fd;
} vcl_session_pair_t;

int server_init(socket_t socket_server, server_data_t * server_connection);
void* process_new_connection(void *server_connection_ptr);

int main(int arg, char **argc){
	//1. the stage of connecting	
	socket_t socket;
	socket.socket_type = LISTEN;
	bzero(&socket.local_info, sizeof(socket.local_info));        //initilize the socket_info
	socket.local_info.sin_family = AF_INET;
	socket.local_info.sin_addr.s_addr = htonl(listen_ip);        //listen  ip
	socket.local_info.sin_port = htons(listen_port);

	//listen the socket
	server_data_t server_connection;
	server_init(socket, &server_connection);
	//process new connection
	pthread_t threadbx;
	int ret_thread;
	ret_thread = pthread_create(&threadbx, NULL, process_new_connection, (void *)(&server_connection));
	if (ret_thread != 0)
		printf(" Failly create the thread !\n");
	else
		printf(" Successfully create the thread !\n");
	
	sleep(~0l);
        return 0;

}

//return the information of new connection
int server_init(socket_t socket_server, server_data_t * server_connection){
	//1.create socket
	if ((server_connection->listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		printf("socket error\n");
		exit(1);
	}
	//2.bind
	if(bind(server_connection->listenfd, (struct sockaddr *)&(socket_server.local_info), sizeof(socket_server.local_info)) < 0){
		printf("bind error\n");
		exit(1);
	}
	//3.listen
	if(listen(server_connection->listenfd, LISTENQ) < 0){
		printf("listen error\n");
		exit(1);
	}
	printf("listen: fd[%d]\n", server_connection->listenfd); 
	//4.accept
	socklen_t len = sizeof(socket_server.remote_info);
	if ((server_connection->connfd = accept(server_connection->listenfd, (struct sockaddr *)&(socket_server.remote_info), &len)) < 0 ){
		printf("accept error");
		exit(1);
	}
	printf("client-proxy connection: fd[%d]\n", server_connection->connfd); 

	return 0;	
}
#define SO_SESSION_PAIR 100

int connect_server(socket_t socket_client, client_data_t * client_connection, server_data_t  server_connection){
	//1.socket
	client_connection->connfd = socket(PF_INET, SOCK_STREAM, 0);
	//2.setsockopt
	//vcl_session_pair_t  session_pair;
	//session_pair.session_pair_fd = server_connection.connfd;

	uint32_t op = SO_SESSION_PAIR;
	socklen_t len;

	int session_pair_fd = server_connection.connfd;
	len = sizeof(int);

	setsockopt(client_connection->connfd, SOL_SOCKET, op, &session_pair_fd, len); 
	
	//
	//
	//
	//
	//3.connect
	if (connect(client_connection->connfd, (struct sockaddr *) & (socket_client.local_info), sizeof(socket_client.local_info)) < 0){
		printf("connect error\n");
		exit(1);
	}
	printf("server-proxy connection: fd[%d] \n", client_connection->connfd);
	return 0;
}
//
void* process_new_connection(void *server_connection_ptr){
	printf("process_new_connection \n");
	server_data_t server_connection;
	server_connection = *((server_data_t *)server_connection_ptr);
	socket_t socket_client;
	socket_client.socket_type = CONNECT;
	bzero(&socket_client.local_info, sizeof(socket_client.local_info));
	socket_client.local_info.sin_family = AF_INET;
	socket_client.local_info.sin_addr.s_addr = inet_addr (connect_ip);        
	socket_client.local_info.sin_port = htons(connect_port);
	memset(socket_client.local_info.sin_zero, '\0', sizeof(socket_client.local_info.sin_zero));

	printf("conneting connection...\n");	
	//1. create connection with client
	client_data_t  client_connection;
	connect_server(socket_client, &client_connection, server_connection);
	//2. the stage of data forwarding
	printf("data forwarding...\n");
	while(1){
		//read request from client
	        printf("client-proxy data: fd[%d]\n", server_connection.connfd); 
		printf("server-proxy data: fd[%d]\n", client_connection.connfd);
		server_connection.rx_buflen = read(server_connection.connfd, server_connection.rx_buf, MAX_LINE);
		printf("read from client. len:%d\n", server_connection.rx_buflen);
		//send request to server
		if(server_connection.rx_buflen > 0){
			int count = 0;
			for(count = 0; count < server_connection.rx_buflen; count++){
				printf("proxy request: buf[%d] = %d\n", count, server_connection.rx_buf[count]);
				client_connection.tx_buf[count] = server_connection.rx_buf[count];
			}
			client_connection.tx_buflen = count;
			write(client_connection.connfd, client_connection.tx_buf, client_connection.tx_buflen);
		}
		//read respond from server
		client_connection.rx_buflen = read(client_connection.connfd, client_connection.rx_buf, MAX_LINE);
		//send respond to client
		if(client_connection.rx_buflen > 0){
			int count = 0;
			for(count = 0; count < client_connection.rx_buflen; count++){
				printf("proxy respond: buf[%d] = %d\n", count, client_connection.rx_buf[count]);
				server_connection.tx_buf[count] = client_connection.rx_buf[count];
			}
			server_connection.tx_buflen = count;
			write(server_connection.connfd, server_connection.tx_buf, server_connection.tx_buflen);
		}
	}
	return NULL;
}
