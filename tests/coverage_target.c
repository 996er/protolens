#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void finish(int sig) { exit(0); }

int main(int argc, char **argv) {
  signal(SIGUSR1, finish);
  int server = socket(AF_INET, SOCK_STREAM, 0);
  int yes = 1;
  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(atoi(argv[1]));
  if (bind(server, (struct sockaddr *)&addr, sizeof addr) || listen(server, 8)) return 2;
  for (;;) {
    int client = accept(server, 0, 0);
    if (client < 0) continue;
    char request[2048] = {0};
    int length = read(client, request, sizeof request);
    const char *reply;
    if (length > 0 && request[0] == 'A') {
      reply = "RTSP/1.0 200 A\r\n\r\n";
    } else if (length > 0 && request[0] == 'B') {
      reply = "RTSP/1.0 200 B\r\n\r\n";
    } else {
      reply = "RTSP/1.0 400 Bad Request\r\n\r\n";
    }
    send(client, reply, strlen(reply), 0);
    close(client);
  }
}
