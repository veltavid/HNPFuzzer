#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include "alloc-inl.h"
#include "aflnet.h"

#define server_wait_usecs 10000
unsigned int socket_timeout = 1000;
unsigned int poll_timeout = 1;
int dev_null_fd,crash_log_fd;

unsigned int* (*extract_response_codes)(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref) = NULL;

/* Expected arguments:
1. Path to the test case directory (e.g., crash-triggering input)
2. Application protocol (e.g., RTSP, FTP)
3. Server's network port
Optional:
4. First response timeout (ms), default 1
5. Follow-up responses timeout (us), default 1000
*/

int spawn_target(int mode, char** argv){
  int target_pid;
  target_pid = fork();
  if (target_pid < 0) PFATAL("fork() failed");
  if (!target_pid) {
    setsid();
    dup2(dev_null_fd, 0);
    dup2(dev_null_fd, 1);
    if(mode==0)
      dup2(dev_null_fd, 2);
    else if(mode==1)
      dup2(crash_log_fd, 2);
    execv(argv[0], &argv[0]);
    exit(0);
  }

  return target_pid;
}

int do_replay(char *input_file,char *prot,int portno){
  FILE *fp;
  int n;
  struct sockaddr_in serv_addr;
  char* buf = NULL, *response_buf = NULL;
  int response_buf_size = 0;
  unsigned int size, i, state_count, packet_count = 0;
  unsigned int *state_sequence;

  fp = fopen(input_file,"rb");

  if (!strcmp(prot, "RTSP")) extract_response_codes = &extract_response_codes_rtsp;
  else if (!strcmp(prot, "FTP")) extract_response_codes = &extract_response_codes_ftp;
  else if (!strcmp(prot, "DNS")) extract_response_codes = &extract_response_codes_dns;
  else if (!strcmp(prot, "DTLS12")) extract_response_codes = &extract_response_codes_dtls12;
  else if (!strcmp(prot, "DICOM")) extract_response_codes = &extract_response_codes_dicom;
  else if (!strcmp(prot, "SMTP")) extract_response_codes = &extract_response_codes_smtp;
  else if (!strcmp(prot, "SSH")) extract_response_codes = &extract_response_codes_ssh;
  else if (!strcmp(prot, "TLS")) extract_response_codes = &extract_response_codes_tls;
  else if (!strcmp(prot, "SIP")) extract_response_codes = &extract_response_codes_sip;
  else if (!strcmp(prot, "HTTP")) extract_response_codes = &extract_response_codes_http;
  else {fprintf(stderr, "[AFLNet-replay] Protocol %s has not been supported yet!\n", prot); exit(1);}

  //Wait for the server to initialize
  usleep(server_wait_usecs);

  if (response_buf) {
    ck_free(response_buf);
    response_buf = NULL;
    response_buf_size = 0;
  }

  int sockfd;
  if ((!strcmp(prot, "DTLS12")) || (!strcmp(prot, "SIP")) || (!strcmp(prot, "DNS"))) {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  } else {
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
  }

  if (sockfd < 0) {
    PFATAL("Cannot create a socket");
  }

  //Set timeout for socket data sending/receiving -- otherwise it causes a big delay
  //if the server is still alive after processing all the requests
  struct timeval timeout;

  timeout.tv_sec = 0;
  timeout.tv_usec = socket_timeout;

  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

  memset(&serv_addr, '0', sizeof(serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(portno);
  serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    //If it cannot connect to the server under test
    //try it again as the server initial startup time is varied
    for (n=0; n < 1000; n++) {
      if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) break;
      usleep(1000);
    }
    if (n== 1000) {
      close(sockfd);
      return 1;
    }
  }

  //Send requests one by one
  //And save all the server responses
  while(!feof(fp)) {
    if (buf) {ck_free(buf); buf = NULL;}
    if (fread(&size, sizeof(unsigned int), 1, fp) > 0) {
      packet_count++;
    	//fprintf(stderr,"\nSize of the current packet %d is  %d\n", packet_count, size);

      buf = (char *)ck_alloc(size);
      fread(buf, size, 1, fp);

      if (net_recv_(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size)) break;
      n = net_send_(sockfd, timeout, buf,size);
      if (n != size) break;

      if (net_recv_(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size)) break;
    }
  }

  fclose(fp);
  close(sockfd);

  /*//Extract response codes
  state_sequence = (*extract_response_codes)(response_buf, response_buf_size, &state_count);

  fprintf(stderr,"\n--------------------------------");
  fprintf(stderr,"\nResponses from server:");

  for (i = 0; i < state_count; i++) {
    fprintf(stderr,"%d-",state_sequence[i]);
  }

  fprintf(stderr,"\n++++++++++++++++++++++++++++++++\nResponses in details:\n");
  for (i=0; i < response_buf_size; i++) {
    fprintf(stderr,"%c",response_buf[i]);
  }
  fprintf(stderr,"\n--------------------------------");
  //Free memory
  ck_free(state_sequence);*/
  
  if (buf) ck_free(buf);
  ck_free(response_buf);
}

void check_crash(int status,char *fn){
  int kill_signal;
  printf("input: %s status: %d\n",fn,status);
  if (WIFSIGNALED(status)) {
    kill_signal = WTERMSIG(status);
    if (kill_signal == SIGTERM){
      unlink(fn);
      return;
    }
  }
  else
    unlink(fn);
}

int main(int argc, char* argv[])
{
  int mode,target_pid,nl_cnt,i;
  struct dirent **nl;
  if (argc < 6) {
    PFATAL("Usage: ./replay-crashes mode packet_file_directory protocol port /path/to/target [ ... ]");
  }
  dev_null_fd = open("/dev/null", O_RDWR);
  mode = atoi(argv[1]);
  if(mode==1)
    crash_log_fd = open("crash_log", O_CREAT | O_RDWR, 0666);
  nl_cnt = scandir(argv[2], &nl, NULL, alphasort);
  if(nl_cnt<0)
    PFATAL("Unable to open '%s'", argv[2]);

  for(i=0;i<nl_cnt;i++){
    struct stat st;
    int status;
    u8* fn = alloc_printf("%s/%s", argv[2], nl[i]->d_name);
    free(nl[i]);

    if (lstat(fn, &st) || access(fn, R_OK))
      PFATAL("Unable to access '%s'", fn);
    if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn, "/README.txt")) {
      ck_free(fn);
      continue;
    }

    if(mode==1){
      printf("%s\n",fn);
      write(crash_log_fd,fn,strlen(fn));
      write(crash_log_fd,"\n",1);
    }

    target_pid=spawn_target(mode,&argv[5]);
    do_replay(fn ,argv[3],atoi(argv[4]));
    if(mode==0){
      sleep(1);
      kill(target_pid, SIGTERM);
      waitpid(target_pid,&status,0);
      check_crash(status,fn);
    }
    else if(mode==1){
      waitpid(target_pid,&status,0);
      write(crash_log_fd,"\n\n",2);
    }
    ck_free(fn);
  }
  free(nl);
  return 0;
}

