#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (int status);
void process_activate (void);
void stack_prep(char* cmd_string, char* argv[], int* argc);
static bool setup_stack (void **esp, char** argv, int argc);

#endif /* userprog/process.h */
