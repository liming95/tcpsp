#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define PORT 8888
//#define IP_ADDR "0.0.0.0"
#define IP_ADDR "192.168.122.94"
#define true 1
#define TEST_TIME 1000
#define BUF_LEN 2048

typedef struct vcl_session_pair_ {
	//uint32_t peer_session_index;
	//uint32_t peer_wrk_index;
	uint64_t session_pair_handle;
	
} vcl_session_pair_t;

#define SO_SESSION_PAIR 100;

int main(){
	int clientSocket;
	char buf[BUF_LEN];
	char inBuf[BUF_LEN];
	struct sockaddr_in serverAddr;
	socklen_t addr_size;
	struct timespec start_time, end_time;

        // create the socket
	clientSocket = socket(PF_INET, SOCK_STREAM, 0);

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.s_addr = inet_addr (IP_ADDR);
	memset(serverAddr.sin_zero, '\0', sizeof(serverAddr.sin_zero));
	
	//int vlsh;
	//vlsh = ldp_fd_to_vlsh(clientSocket);
	uint32_t op = SO_SESSION_PAIR; //VPPCOM_ATTR_SET_ENDPT_EXT_CFG;

	vcl_session_pair_t session_pair;
	session_pair.session_pair_handle = 0x11111111;
	//session_pair.peer_wrk_index = 1;


	socklen_t len;
	len = sizeof (vcl_session_pair_t);
	
	// set socket option
	//vls_attr(vlsh, op, &session_pair, len); 
	//setsockopt(clientSocket, SOL_SOCKET, op, &session_pair, len);

	addr_size = sizeof serverAddr;
	int error = connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size);
	
	if ( error == 0 ) printf( "connect successfully\n");

        //int num = read(clientSocket, buffer, 1024, 0);
	//if (num > 0) {
	//	printf("Data received: %s", buffer);
	while(true) {
		
 		memset(inBuf, 0, sizeof(inBuf));
		scanf("%s", inBuf);
		if ( ! strcmp(inBuf, "exit") ){
			close(clientSocket);
			printf ("connection closing\n");
			return 0;
		}
		int str_len = strlen(inBuf);
                int send_len = write(clientSocket, inBuf, str_len);
                printf("write %d bytes, the content is %s\n", send_len, inBuf);

                memset(buf, 0, sizeof(buf));
                int receive_len = 0; 
		while (receive_len < str_len) {
			int len = read(clientSocket, buf, sizeof(buf));
			receive_len += len;
		}
                printf("read %d bytes[%d], the content is %s\n", receive_len, strlen(buf), buf);
		
		clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
		for (int i = 0; i < TEST_TIME; i++){
			//printf("test time: %d", i);
			int send_len = write(clientSocket, inBuf, str_len);
			//printf("write %d bytes, the content is %s\n", send_len, inBuf);

		        memset(buf, 0, sizeof(buf));
			receive_len = 0;
			while ( receive_len < str_len) {
			   int len = read(clientSocket, buf, sizeof(buf));
			   receive_len += len;
	        	// printf("read %d bytes[%d], the content is %s\n", receive_len, strlen(buf), buf);
			
			}
		}
		clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);

		uint elapsed_time = (end_time.tv_sec - start_time.tv_sec) * 1000000000 +
				    (end_time.tv_nsec - start_time.tv_nsec);
		
		printf("avg_latency: %u microseconds\n", elapsed_time / 1000 / TEST_TIME);
	//	buf[receive_len] = '\0';
        //        if (strlen(buf) > 0) {
	//	    int i = 4;
	//	    //for (i = 0; i < strlen(buf); i++){
	//		printf("buf[%d] = %d\n", i, buf[i]);
	//	    //}
	//	}
	}
	return 0;
}
