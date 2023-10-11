#define _GNU_SOURCE

#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <signal.h>
#include <netdb.h>
#include <pthread.h>
#include <poll.h>
#include <execinfo.h>

#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <linux/kcmp.h>
#include <arpa/inet.h>

#include "sock2shm_utils.h"
#include "alloc-inl.h"
#include "llvm_mode/containers.h"

//#define DEBUG_MODE
#define LOG_FILE_NAME "hnpfuzzer_log"
#define REGION_FOR_FORK "/hnpfuzzer_region"
//#define session_fd 400
#define MAX_FD 64
#define MAX_LOOP 3
#define kcmp_fd(pid1,pid2,fd1,fd2) (syscall(__NR_kcmp,pid1,pid2,KCMP_FILE,fd1,fd2))

#if defined(DEBUG_MODE)
  static FILE * __log_fd=NULL;
  #define DO_LOG(...) original_fprintf(__log_fd, __VA_ARGS__); fflush(__log_fd);
#else
  #define DO_LOG(...) do {} while (0)
#endif

msg* session_msg;
FILE *sock_log;
int* netport_ptr,*fd_map=NULL;
sighandler_t original_sighandlers[__SIGRTMIN];

static s32 shm_send_buf_size_id;
char* send_buf;
int shared_fd_for_fork,max_send_buf_size=0x1000;
int *send_buf_size;

atomic_int has_recv_msg;
atomic_int *connection_state;
int *is_mem_leaked, *is_global_val_written, *proc_ref_cnt, *is_M2;
int disable_shm, disable_shmsync;
int *sign;
int is_kill,socket_type,is_child=0;
int netport,max_fd,read_p,epoll_event_op=EPOLLOUT;
int select_loop_cnt,poll_loop_cnt,epoll_loop_cnt;
int server_fd=-403,epoll_session_fd=-402,epoll_server_fd=-401,session_fd=-400;
struct timeval select_timeout = {.tv_sec = 0, .tv_usec = 0};
enum fd_type {OTHER,SESSION_FD,SERVER_FD=2,E_SESSION_FD=4,E_SERVER_FD=8};

int (*original_kill)(pid_t pid, int sig)=NULL;
sighandler_t (*original_signal)(int signum, sighandler_t handler)=NULL;
__attribute__((noreturn)) void (*original__exit)(int status)=NULL;
__attribute__((noreturn)) void (*original_exit)(int status)=NULL;
pid_t (*original_fork)()=NULL;
int (*original_execve)(const char *pathname, char *const argv[], char *const envp[])=NULL;
int (*original_dup)(int oldfd)=NULL;
int (*original_dup2)(int oldfd, int newfd)=NULL;
int (*original_poll)(struct pollfd *fds, nfds_t nfds, int timeout);
int (*original_epoll_ctl)(int epfd, int op, int fd, struct epoll_event *event);
int (*original_epoll_wait)(int epfd, struct epoll_event *events,
                      int maxevents, int timeout);
int (*original_select)(int nfds, fd_set *restrict readfds,
                  fd_set *restrict writefds, fd_set *restrict exceptfds,
                  struct timeval *restrict timeout)=NULL;
int (*original_ioctl)(int fd, unsigned long request, char *argp)=NULL;
unsigned int (*original_sleep)(unsigned int seconds)=NULL;
int (*original_usleep)(useconds_t usec)=NULL;
int (*original_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen)=NULL;
int (*original_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen)=NULL;
int (*original_listen)(int sockfd, int backlog)=NULL;
int (*original_accept)(int, struct sockaddr*, socklen_t*)=NULL;
int (*original_accept4)(int sockfd, struct sockaddr *addr,  socklen_t *addrlen, int flags)=NULL;
int (*original_getsockname)(int sockfd, struct sockaddr *restrict addr,
                       socklen_t *restrict addrlen)=NULL;
int (*original_getpeername)(int sockfd, struct sockaddr *restrict addr,
                       socklen_t *restrict addrlen)=NULL;
int (*original_setsockopt)(int sockfd, int level, int optname,
	const void* optval, socklen_t optlen)=NULL;
ssize_t (*original_send)(int sockfd, const void *buf, size_t len, int flags)=NULL;
ssize_t (*original_sendto)(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen)=NULL;
ssize_t (*original_sendmsg)(int sockfd, const struct msghdr *msg, int flags)=NULL;
ssize_t (*original_recv)(int sockfd, void *buf, size_t len, int flags)=NULL;
ssize_t (*original_recvfrom)(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen)=NULL;
ssize_t (*original_recvmsg)(int sockfd, struct msghdr *msg, int flags)=NULL;
int (*original_close)(int fd)=NULL;
int (*original_fclose)(FILE* stream)=NULL;
int (*original_shutdown)(int socket, int how)=NULL;
ssize_t (*original_read)(int fd, void *buf, size_t count)=NULL;
ssize_t (*original_write)(int fd, const void *buf, size_t count)=NULL;
ssize_t (*original_readv)(int fd, const struct iovec *iov, int iovcnt)=NULL;
ssize_t (*original_writev)(int fd, const struct iovec *iov, int iovcnt)=NULL;
int (*original_fprintf)(FILE *restrict stream, const char *restrict format, ...)=NULL;
char* (*original_fgets)(char *restrict s, int n, FILE *restrict stream)=NULL;
int (*original_fputs)(const char *restrict s, FILE *restrict stream)=NULL;
int (*original_fputc)(int c, FILE *stream)=NULL;
size_t (*original_fread)(void *restrict ptr, size_t size, size_t nmemb,
                    FILE *restrict stream)=NULL;
size_t (*original_fwrite)(const void *restrict ptr, size_t size, size_t nmemb,
                    FILE *restrict stream)=NULL;

static int compare_pthread_t(const pthread_t* const one, const pthread_t* const two) {
  const pthread_t a = *(pthread_t *) one;
  const pthread_t b = *(pthread_t *) two;

  return a - b;
}

void static do_backtrace(int signum){
  void *buffer[100];
  char **strings;
  int nptrs = backtrace(buffer, 100);

  strings = backtrace_symbols(buffer, nptrs);
  if (strings == NULL) {
    exit(EXIT_FAILURE);
  }
  for (int j = 0; j < nptrs; j++)
    DO_LOG("%d %d backtrace:%s\n", getpid(), signum, strings[j]);
  free(strings);
}

static void setup_shm(){
    char *id_str = getenv(SHM_ENV_MSG_VAR);

    if(id_str) {
      u32 shm_msg_id = atoi(id_str);
      session_msg = (msg*)shmat(shm_msg_id, NULL ,0);
      if(session_msg == (void *)-1)
        _exit(1);
    }
    else
      _exit(1);

    id_str=getenv(SHM_ENV_NETPORT_VAR);
    if(id_str){
      u32 shm_netport_id=atoi(id_str);
      netport_ptr=shmat(shm_netport_id,NULL,0);
      if (netport_ptr==(void *)-1)
        _exit(1);
      netport=*netport_ptr;
    }
    else
      _exit(1);

    id_str=getenv(SHM_ENV_CHECK_VAR);
    if(id_str){
      u32 shm_check_id=atoi(id_str);
      sign=shmat(shm_check_id,NULL,0);
      if (sign==(void *)-1)
        _exit(1);
      is_mem_leaked = &sign[0];
      is_global_val_written = &sign[1];
      connection_state = (atomic_int*)&sign[2];
      proc_ref_cnt = &sign[3];
      disable_shm = sign[6];
      disable_shmsync = sign[7];
      is_M2 = &sign[8];
    }
    else
      _exit(1);
    
    shm_send_buf_size_id=shmget(IPC_PRIVATE, sizeof(int)*2, IPC_CREAT | IPC_EXCL | 0600);
    if(shm_send_buf_size_id<0)
      _exit(1);
    send_buf_size=(int *)shmat(shm_send_buf_size_id, NULL, 0);

    shared_fd_for_fork = shm_open(REGION_FOR_FORK, O_CREAT | O_RDWR, 0600);
    if (shared_fd_for_fork == -1 || ftruncate(shared_fd_for_fork, max_send_buf_size) == -1){
      _exit(1);
    }
    send_buf = mmap(0, max_send_buf_size, PROT_READ | PROT_WRITE, MAP_SHARED, shared_fd_for_fork, 0);
    if (send_buf == MAP_FAILED){
      _exit(1);
    }
}

__attribute__((constructor)) void init_sock2shm(){
    #ifdef DEBUG_MODE
      original_fprintf=dlsym(RTLD_NEXT,"fprintf");
    #endif
    
    if(strcmp(getenv(ENV_PROTOCOL_TYPE),"UDP"))
      socket_type=SOCK_STREAM;
    else
      socket_type=SOCK_DGRAM;

    if(getenv(ENV_IS_KILL))
      is_kill=1;
    else
      is_kill=0;
    max_fd=MAX_FD;
    setup_shm();
}

static int check_fd(int fd,int target){
  if(fd<0 || !fd_map || !session_msg->is_init)
    return 0;
  
  while(fd>=max_fd){
    max_fd<<=1;
    fd_map=ck_realloc(fd_map,max_fd*sizeof(int));
    memset(&fd_map[(max_fd>>1)],0,max_fd<<1);
  }

  return fd_map[fd]&target;
}

static int next_dup_fd(int target){
  int i;

  if(fd_map && session_msg->is_init)
    for(i=0;i<max_fd;i++){
      if(fd_map[i]&target)
        return i;
    }
  
  return -400;
}

static void clr_dup_fd(int start,int target){
  int i;

  if(fd_map && session_msg->is_init)
    for(i=start;i<max_fd;i++){
      fd_map[i]&=~target;
    }
}


void new_sighandler(int signum)
{
  int next_fd;
  
  #ifdef DEBUG_MODE
    do_backtrace(signum);
  #endif

  switch (signum)
  {
    case SIGHUP:
      _exit(0);
    default:
      break;
  }
  
  if(!original_signal)
    original_signal=dlsym(RTLD_NEXT,"signal");
  if(signum<__SIGRTMIN && original_sighandlers[signum])
    original_signal(signum, original_sighandlers[signum]);
  kill(getpid(), signum);
}

static void reset_loop_cnt(){
  poll_loop_cnt=0;
  epoll_loop_cnt=0;
  select_loop_cnt=0;
}

void session_init(){
  if(session_msg->is_init){ // Session has already initiated
    return;
  }
  
  #ifdef DEBUG_MODE
    if(!__log_fd){
      chmod(LOG_FILE_NAME,0666);
      __log_fd=fopen(LOG_FILE_NAME,"w");
    }
  #endif
  
  DO_LOG("%d start session %d %d %d %d %d\n",getpid(),session_msg->is_end,session_fd,server_fd,next_dup_fd(SESSION_FD),sign[4]);
  reset_loop_cnt();
  memset(session_msg,0,sizeof(struct msg_struct));
  session_msg->mx.avail=1;
  send_buf_size[0]=0; // present send buf size
  send_buf_size[1]=max_send_buf_size; // max send buf size
  memset(sign,0,4*sizeof(int));
  atomic_store(connection_state,UNINITIALIZED);
  
  //epoll_event_op=EPOLLOUT;
  if(!fd_map){
    fd_map=ck_alloc(sizeof(int)*max_fd);
    DO_LOG("%d fd_map:%p\n",getpid(),fd_map);
  }

  has_recv_msg=ATOMIC_VAR_INIT(0);
  memset(fd_map,0,sizeof(int)*max_fd);
  read_p=0;
  server_fd=-1;
  session_msg->is_init=1;
}

int session_end(){
  DO_LOG("%d session end %d %d %d %d\n",getpid(),session_msg->buf_size,session_msg->len1,session_msg->len2,session_msg->is_end);
  if(socket_type==SOCK_DGRAM)
    exit(0);
  errno=ECONNRESET;

  return -1;
}

static void check_global_state(){
  int i;

  if(*is_mem_leaked>0 || *is_global_val_written>0){ // check if any long-term data is written or memory leaks occur
    if(!original_close)
      original_close = dlsym(RTLD_NEXT,"close");

    for(i=0;i<max_fd;i++){
      if(check_fd(i,SERVER_FD) || check_fd(i,SESSION_FD))
        original_close(i);
    }
    
    memset(fd_map,0,sizeof(int)*max_fd);
    session_fd=-400;
    server_fd=-400;
    epoll_server_fd=-400;
    epoll_session_fd=-400;
    DO_LOG("exit %d %d\n",*is_mem_leaked,*is_global_val_written);
    exit(0);
  }
}

void suspend(){
  reset_loop_cnt();
  if(!is_kill && socket_type!=SOCK_DGRAM){  // Can't determine when to end a session in connectionless protocol udp
    raise(SIGSTOP);
  }
}

static void remap(int old_size,int new_size){
  char *new_send_buf;
  
  new_send_buf=mmap(0, new_size, PROT_READ | PROT_WRITE, MAP_SHARED, shared_fd_for_fork, 0);
  if (new_send_buf == MAP_FAILED){
    _exit(1);
  }
  
  memcpy(new_send_buf,send_buf,old_size);
  munmap(send_buf,old_size);
  send_buf=new_send_buf;
}

static int get_line_end(const void *buf,int size){
  void *line_end;
  
  line_end=memchr(buf,'\n',size);
  if(!line_end)
    return -1;

  return line_end-buf;
}

static int shm_read(int fd,char *buf,size_t size,int read_line){
  int result=0,line_end,buf_size;
  sigset_t sigset;
  
  DO_LOG("%d %d shm_read() starts waiting\n",getpid(),gettidv());
  thread_block_signal(&sigset);
  lock(&session_msg->mx);
  reset_loop_cnt();
  
  if(atomic_load(connection_state)==ENDING || session_msg->is_end){
    unlock(&session_msg->mx);
    thread_unblock_signal(&sigset);
    return session_end();
  }

  shm_wait(&session_msg->state,CLIENT,-1);
  if(atomic_load(connection_state)==ENDING || session_msg->is_end){
    unlock(&session_msg->mx);
    thread_unblock_signal(&sigset);
    return session_end();
  }
  else if(session_msg->len1==0){
    if(atomic_exchange(&has_recv_msg,0)){ // no more msg to read
      errno = EAGAIN;
      epoll_event_op = EPOLLOUT;
      unlock(&session_msg->mx);
      thread_unblock_signal(&sigset);
      return -1;
    }
    else{ // waiting for client's msg
      shm_notify(&session_msg->state,CLIENT);
      epoll_event_op = EPOLLIN;
      unlock(&session_msg->mx);
      thread_unblock_signal(&sigset);
      return 0;
    }
  }
  else // during message receiving
    atomic_store(&has_recv_msg,1);
  
  do{
    if(read_line){
      buf_size=size<session_msg->buf_size?size:session_msg->buf_size;
      line_end=get_line_end(session_msg->data1+read_p,buf_size);
      if(line_end>=0)
        size=line_end+1;
    }
    
    if(session_msg->buf_size>size){
      memcpy(buf+result,session_msg->data1+read_p,size);
      result+=size;
      session_msg->buf_size-=size;
      session_msg->len1-=size;
      read_p+=size;
      size=0;
    }
    else{
      memcpy(buf+result,session_msg->data1+read_p,session_msg->buf_size);
      result+=session_msg->buf_size;
      session_msg->len1-=session_msg->buf_size;
      size-=session_msg->buf_size;
      session_msg->buf_size=0;
      read_p=0;
      if(session_msg->len1>0){
        shm_notify(&session_msg->state,CLIENT);
        if(size) // size > buf_size and size < len1
          shm_wait(&session_msg->state,CLIENT,-1);
      }
      else
        break;
        //epoll_event_op = EPOLLOUT;
      DO_LOG("\n%d read2 %d %d %d %s\n",fd,read_p,session_msg->len1,session_msg->state,buf);
    }
  }while(size);
  
  unlock(&session_msg->mx);
  thread_unblock_signal(&sigset);
  DO_LOG("%d %d shm_read() finishes\n",getpid(),gettidv());

  return result;
}

static int shm_write_buf(const char* buf,size_t len){
  DO_LOG("%d %d shm_write_buf() starts waiting\n",getpid(),gettidv());
  sigset_t sigset;
  
  if(!*is_M2){
    atomic_store(&has_recv_msg,0);
    return len;
  }
  thread_block_signal(&sigset);
  lock(&session_msg->mx);
  reset_loop_cnt();
  
  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d write buf %d %d %d %d %p %s\n",gettidv(),len,send_buf_size[0],send_buf_size[1],max_send_buf_size,send_buf,buf);
  #endif
  atomic_store(&has_recv_msg,0);
  
  if (send_buf_size[1] != max_send_buf_size) // Max send buf size is modified by other process
  {
    remap(max_send_buf_size,send_buf_size[1]);
    max_send_buf_size=send_buf_size[1];
  }
  
  if(send_buf_size[0]+len>max_send_buf_size){
    int old_size=max_send_buf_size;
    DO_LOG("%d start expanding %d %d %p\n",getpid(),send_buf_size[0]+len,max_send_buf_size,send_buf);
    do{
      max_send_buf_size<<=1;
    }while(send_buf_size[0]+len>max_send_buf_size);
    DO_LOG("%d finish expanding %d %d %p\n",getpid(),send_buf_size[0]+len,max_send_buf_size,send_buf);
    ftruncate(shared_fd_for_fork, max_send_buf_size);
    send_buf_size[1]=max_send_buf_size;
    remap(old_size,max_send_buf_size);
  }
  
  memcpy(send_buf+send_buf_size[0],buf,len);
  send_buf_size[0]+=len;
  epoll_event_op=EPOLLIN;
  unlock(&session_msg->mx);
  thread_unblock_signal(&sigset);
  DO_LOG("%d %d shm_write_buf() finishes\n",getpid(),gettidv());

  return len;
}

static int shm_write(int is_lock){
  int remain,p;
  sigset_t sigset;

  if(!*is_M2){
    atomic_store(&has_recv_msg,0);
    return 0;
  }
  
  thread_block_signal(&sigset);
  if(is_lock)
    lock(&session_msg->mx);
  reset_loop_cnt();
  atomic_store(&has_recv_msg,0);
  
  if(send_buf_size[0]>0 && session_msg->len1==0){
    shm_wait(&session_msg->state,CLIENT,-1);
    session_msg->len2=send_buf_size[0];
    
    for(remain=send_buf_size[0],p=0;remain>0;){
      if(remain<=MAX_MSG_SIZE){
        memcpy(session_msg->data2,send_buf+p,remain);
        p+=remain;
        remain=0;
        shm_notify(&session_msg->state,CLIENT);
      }
      else{
        memcpy(session_msg->data2,send_buf+p,MAX_MSG_SIZE);
        remain-=MAX_MSG_SIZE;
        p+=MAX_MSG_SIZE;
        shm_notify(&session_msg->state,CLIENT);
        shm_wait(&session_msg->state,CLIENT,-1);
      }
    }
    send_buf_size[0]=0;
  }
  
  if(is_lock)
    unlock(&session_msg->mx);
  thread_unblock_signal(&sigset);

  return p;
}

static void send_state_trans(){
  reset_loop_cnt();
  atomic_store(&has_recv_msg,0);
  shm_notify(&session_msg->state,CLIENT);
}

static int recv_state_trans(int fd){
  struct pollfd pfd[1];
  int rv;
  
  if(session_msg->is_end || atomic_load(connection_state)==ENDING)
	  return session_end();
  
  shm_wait(&session_msg->state,CLIENT,-1);
  if(session_msg->is_end || atomic_load(connection_state)==ENDING)
	  return session_end();
  reset_loop_cnt();
  pfd[0].fd = fd;
  pfd[0].events = POLLIN;
  
  if(!original_poll)
    original_poll=dlsym(RTLD_NEXT,"poll");
  rv=original_poll(pfd, 1, 0);
  
  if(rv>0)
    atomic_store(&has_recv_msg,1);
  else{
    if(atomic_exchange(&has_recv_msg,0)){
      errno = EAGAIN;
      return -1;
    }
    else
      shm_notify(&session_msg->state,CLIENT);
  }

  return 0;
}

void check_before_close(int is_lock,int fd){
  sigset_t sigset;

  if(check_fd(fd,SESSION_FD)){
    thread_block_signal(&sigset);
    if(is_lock)
      lock(&session_msg->mx);
    fd_map[fd]=OTHER;
    session_fd=next_dup_fd(SESSION_FD);
    DO_LOG("%d %d closed %d %d %d %d %d\n",getpid(),gettidv(),fd,session_fd,server_fd,send_buf_size[0],*proc_ref_cnt);
    
    if(session_fd<0)
      __sync_fetch_and_sub(proc_ref_cnt,1); // race condition here if no lock
    
    if(session_msg->is_init && __sync_bool_compare_and_swap(proc_ref_cnt,0,0)){
      shm_write(0);
      session_fd=-402;
      atomic_store(&has_recv_msg,0);
      session_msg->is_end=6;
      if(epoll_session_fd>=0)
        clr_dup_fd(0,E_SESSION_FD);
      shm_notify(&session_msg->state,CLIENT);
      shm_notify(connection_state,ENDING);
    }

    if(is_lock)
      unlock(&session_msg->mx);
    thread_unblock_signal(&sigset);
  }
  else if(check_fd(fd,SERVER_FD)){ // It's likely that this happens in the child process
    fd_map[fd]=OTHER;
    server_fd=next_dup_fd(SERVER_FD);
    DO_LOG("%d %d server fd closed %d next: %d %d %d\n",getpid(),gettidv(),fd,server_fd,send_buf_size[0],*proc_ref_cnt);
  }
}

int kill(pid_t pid, int sig){
  if(!original_kill)
    original_kill=dlsym(RTLD_NEXT,"kill");
  
  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d %d kill:%d %d\n",getpid(),gettidv(),pid,sig);
  #endif

  return original_kill(pid,sig);
}

sighandler_t signal(int signum, sighandler_t handler){
  if(!original_signal)
    original_signal=dlsym(RTLD_NEXT,"signal");
  
  if(signum<__SIGRTMIN){
    original_sighandlers[signum]=handler;
    original_signal(signum,new_sighandler);
    return 0;
  }
  else
    return original_signal(signum,handler);
}

__attribute__((noreturn)) void _exit(int status){
  sigset_t sigset;
  
  if(!original__exit)
    original__exit=dlsym(RTLD_NEXT,"_exit");

  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d %d exit0:%d %d\n",getpid(),gettidv(),status,*proc_ref_cnt);
  #endif

  thread_block_signal(&sigset);
  lock(&session_msg->mx);
  if(fd_map){
    if(session_fd>=0 || (session_fd=next_dup_fd(SESSION_FD))>=0){
      memset(fd_map,0,max_fd*sizeof(int));
      fd_map[session_fd]=SESSION_FD;
      check_before_close(0,session_fd);
    }
    ck_free(fd_map);
    fd_map=NULL;
  }
  unlock(&session_msg->mx);
  thread_unblock_signal(&sigset);

  original__exit(status);
}

__attribute__((noreturn)) void exit(int status){
  sigset_t sigset;

  if(!original_exit)
    original_exit=dlsym(RTLD_NEXT,"exit");
  
  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d %d exit1:%d %d %d %d\n",getpid(),gettidv(),status,*proc_ref_cnt,session_fd,session_msg->is_init);
  #endif
  
  thread_block_signal(&sigset);
  lock(&session_msg->mx);
  if(fd_map){
    if(session_fd>=0 || (session_fd=next_dup_fd(SESSION_FD))>=0){
      memset(fd_map,0,max_fd*sizeof(int));
      fd_map[session_fd]=SESSION_FD;
      check_before_close(0,session_fd);
    }
    ck_free(fd_map);
    fd_map=NULL;
  }
  unlock(&session_msg->mx);
  thread_unblock_signal(&sigset);

  /*if(session_msg->is_init){
    thread_block_signal(&sigset);
    lock(&session_msg->mx);
    if(session_fd>=0 || next_dup_fd(SESSION_FD)>=0){
      __sync_fetch_and_sub(proc_ref_cnt,1);
      DO_LOG("in exit:%d %d %d\n",*proc_ref_cnt,send_buf_size[0],session_msg->len1);
      if(__sync_bool_compare_and_swap(proc_ref_cnt,0,0)){
        shm_write(0);
        session_fd=-402;
        atomic_store(&has_recv_msg,0);
        session_msg->is_end=5;
        shm_notify(&session_msg->state,CLIENT);
        shm_notify(connection_state,ENDING);
      }
    }
    unlock(&session_msg->mx);
    thread_unblock_signal(&sigset);
  }*/
  
  original_exit(status);
}

pid_t fork(){
  int ret_val;

  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d do fork... %d\n",getpid(),*proc_ref_cnt);
  #endif
  
  if(!original_fork)
    original_fork=dlsym(RTLD_NEXT,"fork");
  if(session_fd>=0 || next_dup_fd(SESSION_FD)>=0)
    __sync_fetch_and_add(proc_ref_cnt,1);

  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d do fork2... %d %d\n",getpid(),*proc_ref_cnt,next_dup_fd(SESSION_FD));
  #endif
  
  reset_loop_cnt();
  ret_val=original_fork();
  if(!ret_val){
    is_child=1;
    if(!original_sighandlers[SIGHUP])
      signal(SIGHUP,SIG_DFL);
    #ifdef DEBUG_MODE
      if(__log_fd)
        DO_LOG("%d fork child %d %d\n",getpid(),*proc_ref_cnt,next_dup_fd(SESSION_FD));
    #endif
  }

  return ret_val;
}

int execve(const char *pathname, char *const argv[], char *const envp[]){
  if(!original_execve)
    original_execve=dlsym(RTLD_NEXT,"execve");
  
  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d execve: %d %s\n",getpid(),next_dup_fd(SESSION_FD),pathname);
  #endif
  
  int next_fd;
  if((next_fd=next_dup_fd(SESSION_FD))>=0){
    memset(fd_map,0,max_fd*sizeof(int));
    fd_map[next_fd]=SESSION_FD;
    check_before_close(1,next_fd);
  }

  return original_execve(pathname,argv,envp);
}

int dup(int oldfd){
  int ret_val;
  
  if(!original_dup)
    original_dup=dlsym(RTLD_NEXT,"dup");
  ret_val=original_dup(oldfd);
  
  if(session_msg->is_init && ret_val>=0 && fd_map){
    check_fd(ret_val,OTHER); // just expand the fd_map if in need
    fd_map[ret_val]=fd_map[oldfd];
  }
  
  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d dup:%d %d\n",getpid(),oldfd,ret_val);
  #endif

  return ret_val;
}

int dup2(int oldfd, int newfd){
  int ret_val,log_fd;
  
  #ifdef DEBUG_MODE
    if(__log_fd){
      log_fd=fileno(__log_fd);
      if(newfd==log_fd){
        DO_LOG("log file dupped\n");
        fclose(__log_fd);
      }
    }
  #endif
  
  if(!original_dup2)
    original_dup2=dlsym(RTLD_NEXT,"dup2");
  ret_val=original_dup2(oldfd,newfd);
  if(session_msg->is_init && ret_val>=0 && fd_map){
    check_fd(ret_val,OTHER);
    fd_map[ret_val]=fd_map[oldfd];
  }
  
  #ifdef DEBUG_MODE
    if(__log_fd && fd_map)
      DO_LOG("%d dup2:%d %d %d %d %d\n",getpid(),oldfd,newfd,ret_val,fd_map[oldfd],fd_map[newfd]);
  #endif

  return ret_val;
}

int __poll(struct pollfd *fds, nfds_t nfds, int timeout){
  return poll(fds,nfds,timeout);
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout){
  int i,session_i=-1,server_i=-1,ret_val=0,tmp,tmp_session_fd=-1;
  
  if(!original_poll)
    original_poll=dlsym(RTLD_NEXT,"poll");
  
  for(i=0;i<nfds;i++){
    if(check_fd(fds[i].fd,SESSION_FD)){ //&& (epoll_event_op==EPOLLIN || (fds[i].events&POLLIN)==0)){
      ret_val++;
      session_i=i;
      tmp_session_fd=fds[i].fd;
    }
    else if(check_fd(fds[i].fd,SERVER_FD)){
      server_i=i;
    }
  }
  
  if((session_msg->is_end || session_i<0) && server_i>=0){
      shm_wait(connection_state,RUNNING,-1);
      if(__sync_bool_compare_and_swap(connection_state,ENDING,UNINITIALIZED)){
        check_global_state();
        suspend();
      }
  }
  
  #ifdef DEBUG_MODE
    if(__log_fd && original_fprintf)
      DO_LOG("poll:%d\n",session_i);
  #endif

  if(!disable_shmsync && session_i>=0 && poll_loop_cnt<MAX_LOOP){
    tmp=original_poll(fds,nfds,0);
    fds[session_i].fd=tmp_session_fd; // poll may modify the fd
    fds[session_i].revents=POLLIN | POLLOUT;
    poll_loop_cnt++;
    atomic_store(&has_recv_msg,0);
  }
  else
    tmp=original_poll(fds,nfds,timeout);
  
  if(tmp>=0 && poll_loop_cnt<MAX_LOOP)
    ret_val+=tmp;
  else
    ret_val=tmp;

  #ifdef DEBUG_MODE
    if(__log_fd && original_fprintf)
      DO_LOG("poll:%d %d %d %d\n",session_i,server_i,ret_val,tmp);
  #endif

  return ret_val;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event){
  
  if(op==EPOLL_CTL_ADD){
    if(check_fd(fd,SESSION_FD)){
      epoll_session_fd=epfd;
      fd_map[epfd]|=E_SESSION_FD;
    }
    else if(check_fd(fd,SERVER_FD)){
      epoll_server_fd=epfd;
      fd_map[epfd]|=E_SERVER_FD;
    }
  }
  else if(op==EPOLL_CTL_DEL){
    if(check_fd(fd,SESSION_FD)){
      //epoll_session_fd=-402;
      epoll_session_fd=next_dup_fd(E_SESSION_FD);
      fd_map[epfd]&=~E_SESSION_FD;
    }
    else if(check_fd(fd,SERVER_FD)){
      //epoll_server_fd=-401;
      epoll_server_fd=next_dup_fd(E_SERVER_FD);
      fd_map[epfd]&=~E_SERVER_FD;
    }
  }
  
  if(!original_epoll_ctl)
    original_epoll_ctl = dlsym(RTLD_NEXT, "epoll_ctl");

  return original_epoll_ctl(epfd,op,fd,event);
}

int epoll_wait(int epfd, struct epoll_event *events, // Really naive implementation
                      int maxevents, int timeout){
  static struct epoll_event event;
  int ret_val;
  
  if(check_fd(epfd,E_SESSION_FD) && !session_msg->is_end && epoll_loop_cnt<MAX_LOOP){ // Watch session sockets and it has higher priority.
    if(disable_shmsync)
      return original_epoll_wait(epfd,events,maxevents,timeout);
    event.events = EPOLLOUT | EPOLLIN; //epoll_event_op;
    event.data.fd = session_fd;
    *events=event;
    epoll_loop_cnt++;
    atomic_store(&has_recv_msg,0);
    return 1;
  }
  else if(check_fd(epfd,E_SERVER_FD)){
    shm_wait(connection_state,RUNNING,-1);
    if(__sync_bool_compare_and_swap(connection_state,ENDING,UNINITIALIZED)){
      check_global_state();
      suspend();
    }
  }
  
  if(!original_epoll_wait)
    original_epoll_wait = dlsym(RTLD_NEXT, "epoll_wait");
  ret_val=original_epoll_wait(epfd,events,maxevents,timeout);
  
  #ifdef DEBUG_MODE
    if(__log_fd){
      DO_LOG("%d %d %d epoll_wait:%d %d %d %d %d\n",getpid(),gettidv(),ret_val,epfd,check_fd(epfd,E_SESSION_FD),check_fd(epfd,E_SERVER_FD),check_fd(epfd,SESSION_FD),check_fd(epfd,SERVER_FD));
      if(ret_val>0)
        DO_LOG("%d epoll_wait2: %d %d %d\n",epfd,events->data.fd,events->events,fd_map[events->data.fd]);
    }
  #endif

  return ret_val;
}

static int extract_select_fd(int nfds,fd_set *restrict fds,int target){
  int i;
  
  if(!fd_map)
    return -1;
  
  for(i=0;i<nfds;i++){
    if(fd_map[i]&target && FD_ISSET(i,fds))
      return i;
  }

  return -1;
}

int select(int nfds, fd_set *restrict readfds,
                  fd_set *restrict writefds, fd_set *restrict exceptfds,
                  struct timeval *restrict timeout){
  int ret_val,tmp=0,extract_read,extract_write,server_extract_read=-1;
  
  if(!original_select)
    original_select=dlsym(RTLD_NEXT,"select");
  
  if(readfds){
    if(session_fd>=0 && FD_ISSET(session_fd,readfds)){
      if(!disable_shmsync)
        FD_CLR(session_fd,readfds);
      tmp|=1;
    }
    else if((extract_read=extract_select_fd(nfds,readfds,SESSION_FD))>=0){
      if(!disable_shmsync)
        FD_CLR(extract_read,readfds);
      tmp|=4;
    }
    if(server_fd>=0 && FD_ISSET(server_fd,readfds) || (server_extract_read=extract_select_fd(nfds,readfds,SERVER_FD))>=0){
      if((tmp&5)==0){
        shm_wait(connection_state,RUNNING,-1);
        if(__sync_bool_compare_and_swap(connection_state,ENDING,UNINITIALIZED)){
          check_global_state();
          suspend();
        }
      }
      else if(!disable_shmsync) // accept() only creates 1 session
        FD_CLR(server_extract_read>=0?server_extract_read:server_fd,readfds);
    }
  }

  if(writefds && !disable_shmsync){
    if(session_fd>=0 && FD_ISSET(session_fd,writefds)){
      FD_CLR(session_fd,writefds);
      tmp|=2;
    }
    else if((extract_write=extract_select_fd(nfds,writefds,SESSION_FD))>=0){
      FD_CLR(extract_write,writefds);
      tmp|=8;
    }
  }
  
  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d select:%d %d %d %d\n",getpid(),tmp,socket_type,select_loop_cnt,tmp);
  #endif

  if(!disable_shmsync && tmp>0 && select_loop_cnt<MAX_LOOP){
    ret_val=original_select(nfds,readfds,writefds,exceptfds,&select_timeout); // always readable or writable
    ret_val=ret_val<0?0:ret_val;
    select_timeout.tv_sec=0; // select() may modify the timeout struct
    select_timeout.tv_usec=0;
    select_loop_cnt++;
  }
  else{
    ret_val=original_select(nfds,readfds,writefds,exceptfds,timeout);
  }
  
  if(!disable_shmsync && ret_val>=0 && select_loop_cnt<MAX_LOOP){
    if(tmp&1){
      FD_SET(session_fd,readfds);
      ret_val++;
      atomic_store(&has_recv_msg,0);
    }
    if(tmp&2){
      FD_SET(session_fd,writefds);
      ret_val++;
    }
    if(tmp&4){
      FD_SET(extract_read,readfds);
      ret_val++;
      atomic_store(&has_recv_msg,0);
    }
    if(tmp&8){
      FD_SET(extract_write,writefds);
      ret_val++;
    }
  }
  
  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d select:%d %d %d %d %d\n",getpid(),session_fd,server_fd,FD_ISSET(server_fd,readfds),ret_val,errno);
  #endif

  return ret_val;
}

unsigned int sleep(unsigned int seconds){
  return 0;
}

int usleep(useconds_t usec){
  return 0;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
  int ret_val,reuse=1;
  int type,length=sizeof(int);

  if(!original_bind)
    original_bind=dlsym(RTLD_NEXT, "bind");
  
  if(ntohs(((struct sockaddr_in *)addr)->sin_port)==netport)
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse));
  ret_val=original_bind(sockfd,addr,addrlen);
  
  if(sign[4]==0 && ret_val==0 && ntohs(((struct sockaddr_in *)addr)->sin_port)==netport){
    getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &length);
    if(type==socket_type){
      session_init();
      if(socket_type==SOCK_DGRAM){
        session_fd = sockfd;
        fd_map[sockfd] |= SESSION_FD;
      }
      else{
        server_fd = sockfd;
        fd_map[sockfd] |= SERVER_FD;
      }
    }
  }
  
  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d bind:%d %d %d %d\n",getpid(),sockfd,server_fd,ntohs(((struct sockaddr_in *)addr)->sin_port),((struct sockaddr_in *)addr)->sin_family);
  #endif
  
  return ret_val;
}

int accept(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen){
  int ret_val;
  
  if(!original_accept)
    original_accept=dlsym(RTLD_NEXT,"accept");
  
  shm_wait(connection_state,RUNNING,-1);
  if(check_fd(sockfd,SERVER_FD)){
    if(atomic_load(connection_state)==ENDING){
      check_global_state();
      suspend();
    }
    atomic_store(connection_state,RUNNING);
  }
  
  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d accept: %d %d\n",getpid(),sockfd,session_msg->is_end);
  #endif
  
  ret_val=original_accept(sockfd,addr,addrlen);
  if(check_fd(sockfd,SERVER_FD) && ret_val>=0){
    session_fd=ret_val;
    fd_map[ret_val]|=SESSION_FD;
    __sync_fetch_and_add(proc_ref_cnt,1);
  }
  
  #ifdef DEBUG_MODE
    if(__log_fd){
      DO_LOG("%d accept:%d %d %d %d %d\n",getpid(),sockfd,server_fd,ret_val,session_fd,session_msg->is_end);
      if(ret_val<0)
        DO_LOG("%d accept errno:%d\n",getpid(),errno);
    }
  #endif

  return ret_val;
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags){
  int ret_val;
  
  if(!original_accept4)
    original_accept4=dlsym(RTLD_NEXT,"accept4");
  
  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d %d accept4_1: %d %d\n",getpid(),gettidv(),sockfd,flags&O_NONBLOCK);
  #endif
  
  if(!(flags & O_NONBLOCK))
    shm_wait(connection_state,RUNNING,-1);
  
  if(check_fd(sockfd,SERVER_FD) && atomic_load(connection_state)<=ENDING){
    if(atomic_load(connection_state)==ENDING){
      check_global_state();
      suspend();
    }
    atomic_store(connection_state,RUNNING);
  }
  ret_val=original_accept4(sockfd,addr,addrlen,flags);
  
  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d %d accept4_2: %d %d\n",getpid(),gettidv(),sockfd,ret_val);
  #endif
  
  if(check_fd(sockfd,SERVER_FD) && ret_val>=0){
    session_fd=ret_val;
    fd_map[ret_val]|=SESSION_FD;
    __sync_fetch_and_add(proc_ref_cnt,1);
  }
  
  return ret_val;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags){
  int ret_val;
  
  if(!original_send)
    original_send=dlsym(RTLD_NEXT, "send");
  
  if(!disable_shm && check_fd(sockfd,SESSION_FD)){
    ret_val=shm_write_buf(buf,len);
  }
  else{
    ret_val=original_send(sockfd,buf,len,flags);
    if(!disable_shmsync && check_fd(sockfd,SESSION_FD))
      send_state_trans();
  }
  
  return ret_val;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen){
  int ret_val;
  
  if(!original_sendto)
    original_sendto=dlsym(RTLD_NEXT, "sendto");
  
  if(!disable_shm && check_fd(sockfd,SESSION_FD)){
    ret_val=shm_write_buf(buf,len);
  }
  else{
    ret_val=original_sendto(sockfd,buf,len,flags,dest_addr,addrlen);
    if(!disable_shmsync && check_fd(sockfd,SESSION_FD))
      send_state_trans();
  }

  return ret_val;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags){
  int i,ret_val;
  
  if(!original_sendmsg)
    original_sendmsg=dlsym(RTLD_NEXT, "sendmsg");
  
  if(!disable_shm && check_fd(sockfd,SESSION_FD)){
    for(i=0,ret_val=0;i<msg->msg_iovlen;i++){
      ret_val+=shm_write_buf(msg->msg_iov[i].iov_base,msg->msg_iov[i].iov_len);
    }
  }
  else{
    ret_val=original_sendmsg(sockfd,msg,flags);
    if(!disable_shmsync && check_fd(sockfd,SESSION_FD))
      send_state_trans();
  }

  return ret_val;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags){
  int ret_val=0;
  
  if(!original_recv)
    original_recv=dlsym(RTLD_NEXT, "recv");
  
  if(!disable_shm && check_fd(sockfd,SESSION_FD)){
    shm_write(1);
    while(!(ret_val=shm_read(sockfd,buf,len,0)));
  }
  else{
    if(!disable_shmsync && check_fd(sockfd,SESSION_FD))
      ret_val=recv_state_trans(sockfd);
    if(ret_val>=0)
      ret_val=original_recv(sockfd,buf,len,flags);
  }

  return ret_val;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen){
  int ret_val=0;
  
  if(!original_recvfrom)
    original_recvfrom=dlsym(RTLD_NEXT, "recvfrom");
  
  if(!disable_shm && check_fd(sockfd,SESSION_FD)){
    shm_write(1);
    *addrlen=sizeof(struct sockaddr);
    ((struct sockaddr_in*)src_addr)->sin_family=AF_INET;
    ((struct sockaddr_in*)src_addr)->sin_port=0x8383;
    ((struct sockaddr_in*)src_addr)->sin_addr.s_addr=0x100007f;
    while(!(ret_val=shm_read(sockfd,buf,len,0)));
  }
  else{
    if(!disable_shmsync && check_fd(sockfd,SESSION_FD))
      ret_val=recv_state_trans(sockfd);
    if(ret_val>=0)
      ret_val=original_recvfrom(sockfd,buf,len,flags,src_addr,addrlen);
  }
  
  return ret_val;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags){
  int i,tmp,ret_val=0;
  
  if(!original_recvmsg)
      original_recvmsg=dlsym(RTLD_NEXT,"recvmsg");
  
  if(!disable_shm && check_fd(sockfd,SESSION_FD)){
    shm_write(1);
    for(i=0,ret_val=0;i<msg->msg_iovlen;i++){
      do{
        tmp=shm_read(sockfd,msg->msg_iov[i].iov_base,msg->msg_iov[i].iov_len,0);
        if(tmp<0)
          return -1;
      }while(tmp==0);
      ret_val+=tmp;
    }
  }
  else{
    if(!disable_shmsync && check_fd(sockfd,SESSION_FD))
      ret_val=recv_state_trans(sockfd);
    if(ret_val>=0)
      ret_val=original_recvmsg(sockfd,msg,flags);
  }

  return ret_val;
}

ssize_t read(int fd, void * buf, size_t count) {
  int ret_val=0;
  
  if(!original_read)
      original_read=dlsym(RTLD_NEXT, "read");
  
  if(!disable_shm && check_fd(fd,SESSION_FD)){
    shm_write(1);
    while(!(ret_val=shm_read(fd,buf,count,0)));
  }
  else{
    if(!disable_shmsync && check_fd(fd,SESSION_FD))
      ret_val=recv_state_trans(fd);
    if(ret_val>=0)
      ret_val=original_read(fd,buf,count);
  }

  return ret_val;
}

ssize_t write(int fd, const void * buf, size_t count) {
  int ret_val;
  
  if(!original_write)
    original_write=dlsym(RTLD_NEXT, "write");
  
  if(!disable_shm && check_fd(fd,SESSION_FD)){
    ret_val=shm_write_buf(buf,count);
  }
  else{
    ret_val=original_write(fd,buf,count);
    if(!disable_shmsync && check_fd(fd,SESSION_FD))
      send_state_trans();
  }

  return ret_val;
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt){
  int i,tmp,ret_val=0;

  if(!original_readv)
      original_readv=dlsym(RTLD_NEXT,"readv");
  
  if(!disable_shm && check_fd(fd,SESSION_FD)){
    shm_write(1);
    for(i=0,ret_val=0;i<iovcnt;i++){
      do{
        tmp=shm_read(fd,iov[i].iov_base,iov[i].iov_len,0);
        if(tmp<0)
          return -1;
      }while(tmp==0);
      ret_val+=tmp;
    }
  }
  else{
    if(!disable_shmsync && check_fd(fd,SESSION_FD))
      ret_val=recv_state_trans(fd);
    if(ret_val>=0)
      ret_val=original_readv(fd,iov,iovcnt);
  }

  return ret_val;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt){
  int i,ret_val;

  if(!original_writev)
    original_writev=dlsym(RTLD_NEXT, "writev");
  
  if(!disable_shm && check_fd(fd,SESSION_FD)){
    for(i=0,ret_val=0;i<iovcnt;i++){
      ret_val+=shm_write_buf(iov[i].iov_base,iov[i].iov_len);
    }
  }
  else{
    ret_val=original_writev(fd,iov,iovcnt);
    if(!disable_shmsync && check_fd(fd,SESSION_FD))
      send_state_trans();
  }

  return ret_val;
}

int fprintf(FILE *restrict stream, const char *restrict format, ...) {
  va_list ap,ap2;
  int fd = fileno(stream),ret_val;
  char *buf;

  if(!disable_shm && check_fd(fd,SESSION_FD)){
    va_start(ap, format);
    va_copy(ap2, ap);
    ret_val = vsnprintf(NULL, 0, format, ap);
    buf=(char*)ck_alloc(ret_val+1);
    if(!buf)
      return -1;
    vsprintf(buf, format, ap2);
    va_end(ap);
    va_end(ap2);
    ret_val=shm_write_buf(buf, ret_val);
    ck_free(buf);
  }
  else{
    va_start(ap, format);
    ret_val=vfprintf(stream, format, ap);
    va_end(ap);
    if(!disable_shmsync && check_fd(fd,SESSION_FD))
      send_state_trans();
  }

  return ret_val;
}

char* fgets(char *restrict s, int n, FILE *restrict stream){
  int fd = fileno(stream),ret_val=0;

  if(!original_fgets)
      original_fgets=dlsym(RTLD_NEXT, "fgets");
  
  if(!disable_shm && check_fd(fd,SESSION_FD)){
    shm_write(1);
    while(!(ret_val=shm_read(fd,s,n-1,1)));
    if(ret_val<0)
      return NULL;
    *(s+ret_val)='\0';
    return s;
  }
  else{
    if(!disable_shmsync && check_fd(fd,SESSION_FD))
      ret_val=recv_state_trans(fd);
    if(ret_val>=0)
      return original_fgets(s,n,stream);
    else
      return NULL;
  }
}

int fputs(const char *restrict s, FILE *restrict stream){
  int fd = fileno(stream),ret_val;

  if(!original_fputs)
    original_fputs=dlsym(RTLD_NEXT, "fputs");
  
  if(!disable_shm && check_fd(fd,SESSION_FD)){
    shm_write_buf(s,strlen(s));
    ret_val=0;
  }
  else{
    ret_val=original_fputs(s,stream);
    if(!disable_shmsync && check_fd(fd,SESSION_FD))
      send_state_trans();
  }
  
  return ret_val;
}

int fputc(int c, FILE *stream){
  int fd = fileno(stream),ret_val;
  unsigned char ch=c;

  if(!original_fputc)
    original_fputc=dlsym(RTLD_NEXT, "fputc");
  
  if(!disable_shm && check_fd(fd,SESSION_FD)){
    shm_write_buf(&ch,1);
    ret_val=c;
  }
  else{
    ret_val=original_fputc(c,stream);
    if(!disable_shmsync && check_fd(fd,SESSION_FD))
      send_state_trans();
  }

  return ret_val;
}

size_t fread(void *restrict ptr, size_t size, size_t nmemb, FILE *restrict stream){
  int fd = fileno(stream),ret_val=0;
  
  if(!original_fread)
    original_fread=dlsym(RTLD_NEXT, "fread");
  
  if(!disable_shm && check_fd(fd,SESSION_FD)){
    shm_write(1);
    while(!(ret_val=shm_read(fd,ptr,size*nmemb,0)));
  }
  else{
    if(!disable_shmsync && check_fd(fd,SESSION_FD))
      ret_val=recv_state_trans(fd);
    if(ret_val>=0)
      ret_val=original_fread(ptr,size,nmemb,stream);
  }
  
  return ret_val;
}

size_t fwrite(const void *restrict ptr, size_t size, size_t nmemb, FILE *restrict stream){
  int fd = fileno(stream),ret_val;

  if(!original_fwrite)
    original_fwrite=dlsym(RTLD_NEXT, "fwrite");
  
  if(!disable_shm && check_fd(fd,SESSION_FD)){
    ret_val=shm_write_buf(ptr,size*nmemb);
  }
  else{
    ret_val=original_fwrite(ptr,size,nmemb,stream);
    if(!disable_shmsync && check_fd(fd,SESSION_FD))
      send_state_trans();
  }
  
  return ret_val;
}

int close(int fd) {
  int ret_val,is_log_closed=0;
  
  #ifdef DEBUG_MODE
    if(__log_fd && fd==fileno(__log_fd)){
      DO_LOG("%d log closed\n",getpid());
      is_log_closed=1;
    }
    if(__log_fd)
      DO_LOG("%d close %d %d\n",getpid(),fd,check_fd(fd,SESSION_FD));
  #endif
  
  check_before_close(1,fd);
  if(!original_close)
    original_close=dlsym(RTLD_NEXT, "close");
  ret_val=original_close(fd);
  
  #ifdef DEBUG_MODE
    if(is_log_closed){
      __log_fd=fopen(LOG_FILE_NAME,"a+");
      DO_LOG("%d log reopened successfully %d\n",getpid(),errno);
    }
  #endif
  
  return ret_val;
}

int fclose(FILE * stream) {
  int fd = fileno(stream),ret_val,is_log_closed=0;

  #ifdef DEBUG_MODE
    if(__log_fd && fd==fileno(__log_fd)){
      DO_LOG("%d log fclosed\n",getpid());
      is_log_closed=1;
    }
    if(__log_fd)
      DO_LOG("%d %d fclose %d\n",getpid(),gettidv(),fd);
  #endif
  
  check_before_close(1,fd);
  if(!original_fclose)
    original_fclose=dlsym(RTLD_NEXT, "fclose");
  ret_val=original_fclose(stream);
  
  #ifdef DEBUG_MODE
    if(is_log_closed){
      __log_fd=fopen(LOG_FILE_NAME,"a+");
      DO_LOG("%d log reopened successfully\n",getpid());
    }
  #endif
  
  return ret_val;
}

/*int shutdown(int sockfd, int how) {
  #ifdef DEBUG_MODE
    if(__log_fd)
      DO_LOG("%d shutdown %d\n",getpid(),sockfd);
  #endif
  if(check_fd(sockfd,SESSION_FD)){// || sockfd==server_fd){
    DO_LOG("shutdown %d %d\n",sockfd,server_fd);
    if(send_buf_size[0]>0){
      int msg_buf_size,msg_len;
      msg_buf_size=session_msg->buf_size; // in case that server invokes shutdown() in the process of message reading
      msg_len=session_msg->len;
      shm_write();
      shm_wait(&session_msg->len,send_buf_size);  // if client wakes earlier, then session_msg->len won't be equal with send_buf_size
      session_msg->len=msg_len;
      session_msg->buf_size=msg_buf_size;
      ck_free(send_buf);
      send_buf=NULL;
      
    }
  }
  if(!original_shutdown)
    original_shutdown=dlsym(RTLD_NEXT, "shutdown");
	return original_shutdown(sockfd, how);
}*/

static void detach_shm(){
  /*if(__sync_bool_compare_and_swap(&sign[4],0,0)){
    shmctl(shm_send_buf_size_id, IPC_RMID, NULL);
  }*/

  shmdt(netport_ptr);
  shmdt(session_msg);
  shmdt(send_buf_size);
}

__attribute__((destructor)) void fini_sock2shm(){
  munmap(send_buf,max_send_buf_size);
  close(shared_fd_for_fork);

  if(fd_map){
    if(session_fd>=0 || (session_fd=next_dup_fd(SESSION_FD))>=0){
      memset(fd_map,0,max_fd*sizeof(int));
      fd_map[session_fd]=SESSION_FD;
      check_before_close(1,session_fd);
    }
    ck_free(fd_map);
    fd_map=NULL;
  }
  
  #ifdef DEBUG_MODE
    if(__log_fd){
      DO_LOG("%d fini invoked %d\n",getpid(),*proc_ref_cnt);
      if(!original_fclose)
        original_fclose=dlsym(RTLD_NEXT,"fclose");
      original_fclose(__log_fd);
    }
  #endif

  if(!is_child)
    detach_shm();
}
