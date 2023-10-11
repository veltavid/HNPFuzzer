#include <signal.h>
#include <sys/shm.h>

#include "../config.h"
#include "../types.h"
#include "../sock2shm_utils.h"
#include "containers.h"

int *sign=NULL,target_pid=-1; // idx 0:chunk_set's size>0; idx 1: global state is modified; idx 2: if start a session
set chunk_set=NULL;
fsemaphore mx;

static int compare_key_addr(const void * const one, const void * const two) {

  	const void * a = *(void **)one;
  	const void * b = *(void **)two;
	return a==b?0:a<b?-1:1;
}

int setup_shm(){
	char *id_str = getenv(SHM_ENV_CHECK_VAR);
  	if(id_str) {
    	u32 shm_check_id = atoi(id_str);
    	sign = shmat(shm_check_id, NULL ,0);
		if(sign == (void *)-1){
      		sign=NULL;
			return -1;
		}
	}
	else
    	return -1;
	if(sign[5]){
        target_pid=-1; // disable persistent mode
		sign[0]=1; // exit after the connection is closed
        return -1;
    }
	return 0;
}

__attribute__((constructor (0)))
void init_checker() {
	target_pid=getpid(); // Memory state of the child forked from this process won't be recorded

	if(!setup_shm()){
		//if(chunk_set)
		//	set_clear(chunk_set);
		//else
		chunk_set=set_init(sizeof(void*),compare_key_addr);
	}

	mx.avail=1;
	mx.waiters=0;
}

void check_global_store(void *addr,int alignment){
	sigset_t sigset;

	if(target_pid<0 || getpid()!=target_pid || !(sign && sign[2]==RUNNING && !sign[1]))
		return;

	sign[1]=1;
}

void new_alloc_record(void * addr) {
	set_put(chunk_set,&addr);
	sign[0]=1;
}

void free_alloc_record(void * addr) {
	if(!sign)
		return;

	set_remove(chunk_set,&addr);
	if(set_is_empty(chunk_set))
		sign[0]=0;
}

void new_heap_alloc_record(void * addr, uint64_t size) {
	sigset_t sigset;

	if(target_pid<0 || getpid()!=target_pid || !(sign && sign[2]==RUNNING && !sign[1]))
		return;
	
	thread_block_signal(&sigset);
	lock(&mx);
	new_alloc_record(addr);
	unlock(&mx);
	thread_unblock_signal(&sigset);
}

void free_heap_alloc_record(void * addr, uint64_t size) {
	sigset_t sigset;
	
	if(target_pid<0 || getpid()!=target_pid || !(sign && sign[2]==RUNNING && !sign[1]))
		return;
	
	thread_block_signal(&sigset);
	lock(&mx);
	free_alloc_record(addr);
	unlock(&mx);
	thread_unblock_signal(&sigset);
}

void trace_calloc(void * addr, int size, int nmemb) {
	sigset_t sigset;
	
	if(target_pid<0 || getpid()!=target_pid || !(sign && sign[2]==RUNNING && !sign[1]))
		return;
	
	thread_block_signal(&sigset);
	lock(&mx);
	new_alloc_record(addr);
	unlock(&mx);
	thread_unblock_signal(&sigset);
}

void trace_realloc(void * addr, int size, void * oldaddr) {
	sigset_t sigset;
	
	if(!sign || addr==oldaddr || target_pid<0 || getpid()!=target_pid || !(sign && sign[2]==RUNNING && !sign[1]))
		return;
  	
	thread_block_signal(&sigset);
	lock(&mx);
	
	int found = set_contains(chunk_set,&oldaddr);
  	if(found) {
		set_remove(chunk_set,&oldaddr);
		set_put(chunk_set,&addr);
  	}
	else
		new_alloc_record(addr);
	unlock(&mx);
	thread_unblock_signal(&sigset);
}
