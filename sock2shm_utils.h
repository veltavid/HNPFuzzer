#include <linux/futex.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>
#include <syscall.h>

#include "types.h"

#define MAX_MSG_SIZE 0x4000
#define WAITING_TIME 100
#define SHM_ENV_MSG_VAR "__AFL_SHM_MSG_ID"
#define SHM_ENV_NETPORT_VAR "__AFL_SHM_NETPORT_ID" 
#define SHM_ENV_CHECK_VAR "__AFL_SHM_CHECK_ID" 
#define ENV_PROTOCOL_TYPE "__AFL_PROTOCOL_TYPE"
#define ENV_IS_KILL "__AFL_KILL_ON"
#define gettidv() (syscall(__NR_gettid))
#define futex_wait(addr,val,timeout) (syscall(SYS_futex,addr,FUTEX_WAIT,val,timeout,NULL,0)) 
#define futex_wake(addr,val) (syscall(SYS_futex,addr,FUTEX_WAKE,val,NULL,NULL,0)) 
enum session_state { SERVER, CLIENT };
enum connection_state { UNINITIALIZED=-1, ENDING, RUNNING };

typedef struct fu_semaphore {
  int avail;
  int waiters;
}fsemaphore;

typedef struct msg_struct {
  atomic_int state;
  int is_init;
  int is_end;
  int len1; // client writes and server reads
  int len2; // client reads and server writes
  int buf_size;
  struct fu_semaphore mx;
  u8 data1[MAX_MSG_SIZE];
  u8 data2[MAX_MSG_SIZE];
}msg;

int shm_wait(atomic_int *state,int val,int timeout);
void shm_notify(atomic_int *state,int val);
void lock(fsemaphore* who);
void unlock(fsemaphore* who);
void thread_block_signal(sigset_t *oldset);
void thread_unblock_signal(sigset_t *sigset);

msg* session_msg;