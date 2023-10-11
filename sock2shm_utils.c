#include <signal.h>
#include <sys/time.h>
#include "sock2shm_utils.h"

static u64 get_cur_time(void) {

  struct timeval tv;
  gettimeofday(&tv, NULL);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}

int shm_wait(atomic_int *state,int val,int timeout){
  u64 start;

  if(timeout>0){
  	start = get_cur_time();
    while (atomic_load(state) == val && get_cur_time()-start<timeout) ;
  }
  else
    while (atomic_load(state) == val) ;
  return atomic_load(state) == val;
}

void shm_notify(atomic_int* state,int val) {
	atomic_store(state,val);
}

void lock(fsemaphore* who)
{
  //int val;
  if(!who)
    return;
  do {
   //val = who->avail;
   if(__sync_bool_compare_and_swap(&who->avail, 1, 0) )
      return;
    __sync_fetch_and_add(&who->waiters, 1);
    futex_wait(&who->avail,0,NULL);
    __sync_fetch_and_sub(&who->waiters, 1);
  } while(1);
}

void unlock(fsemaphore* who)
{
  //int nval;
  if(!who)
    return;
  __sync_bool_compare_and_swap(&who->avail, 0, 1);
  if( who->waiters > 0 )
  {
    futex_wake(&who->avail,1);
  }
}

void thread_block_signal(sigset_t *oldset){
  sigset_t set;
  sigfillset(&set);
  pthread_sigmask(SIG_SETMASK, &set, oldset);
}

void thread_unblock_signal(sigset_t *sigset){
  pthread_sigmask(SIG_SETMASK, sigset, NULL);
}