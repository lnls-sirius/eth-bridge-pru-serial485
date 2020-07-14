// gcc -o teste -O3 -lPRUserial485 -lprussdrv -pthread teste-server.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <PRUserial485.h>

#define BUFFER_SIZE 2048
#define on_error(...) { fprintf(stderr, __VA_ARGS__); fflush(stderr); exit(1); }

int main (int argc, char *argv[]) {

  if (argc < 2) on_error("Usage: %s [port]\n", argv[0]);

  int port = atoi(argv[1]);

  int server_fd, client_fd, err, opt_val = 1;
  struct sockaddr_in server, client;
  char buf[BUFFER_SIZE];

  uint8_t received_data[BUFFER_SIZE];
  uint8_t header_buff[5], timeout_buff[4];
  uint32_t received_size, message_size;
  uint8_t* reply_buffer = malloc(BUFFER_SIZE * sizeof(uint8_t)); // array to hold the result



  init_start_PRU(6, 'M');


  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
  {
    on_error("Could not create socket\n");
  }

  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  server.sin_addr.s_addr = htonl(INADDR_ANY);

  
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof opt_val);
  setsockopt(server_fd, IPPROTO_IP, TCP_NODELAY, &opt_val, sizeof opt_val);


  if ((bind(server_fd, (struct sockaddr *) &server, sizeof(server))) < 0)
  {
    on_error("Could not bind socket\n");
  }

  if ((listen(server_fd, 128)) < 0)
  { 
    on_error("Could not listen on socket\n");
  }

  printf("Server is listening on %d\n", port);

  while (1) {
    socklen_t client_len = sizeof(client);
    client_fd = accept(server_fd, (struct sockaddr *) &client, &client_len);

    if (client_fd < 0) on_error("Could not establish new connection\n");

    fprintf(stdout,"Client %s:%d connected\n", inet_ntoa(client.sin_addr), (int) ntohs(client.sin_port));
    fflush(stdout);

    while (1) {
      int rd1 = recv(client_fd, header_buff, 5, MSG_WAITALL);
      int rd2 = recv(client_fd, timeout_buff, 4, MSG_WAITALL);
      message_size = (header_buff[1] *(256*256*256) + header_buff[2] *(256*256) + header_buff[3] *256 + header_buff[4]) - 4;
      int rd3 = recv(client_fd, buf, message_size, MSG_WAITALL);

      if (rd1 < 0 | rd2 <0 | rd3 < 0)
      { 
        fprintf(stdout, "Client %s:%d disconnected\n", inet_ntoa(client.sin_addr), (int) ntohs(client.sin_port)); 
        fflush(stdout);
        break;
      }

      send_data_PRU(buf, &message_size, 1.0);
      recv_data_PRU(received_data, &received_size, 0);

      header_buff[1] = received_size / (256*256*256);
      header_buff[2] = received_size / (256*256);
      header_buff[3] = received_size / 256;
      header_buff[4] = received_size / 1; 

      memcpy(reply_buffer, header_buff, 5 * sizeof(uint8_t)); 
      memcpy(reply_buffer + 5, received_data, received_size * sizeof(uint8_t));

      int out2 = send(client_fd, reply_buffer, received_size+5, 0);
      if (out2 < 0) on_error("Client write failed\n");
    }
  }
  return 0;
}