#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"
//do we need threads include?s


struct lock file_lock;

void syscall_init (void);
void real_addr_convert(void* vaddr);
void ptr_check(void* vaddr);


void close_process(int fd);
void close_all();

#endif /* userprog/syscall.h */
