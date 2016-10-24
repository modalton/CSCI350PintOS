#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
//do we need threads include?s

void syscall_init (void);
void real_addr_convert(void* vaddr);


void close_process(int fd);
void close_all();

#endif /* userprog/syscall.h */
