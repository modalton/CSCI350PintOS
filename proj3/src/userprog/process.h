#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

//put mmentry in this file bc necessary for alot of process funcs
struct mmentry
{
	struct file* file; //pointer to our spt entry
	void* ptr;
	int mapid;
	int totalpgs;
	
	struct hash_elem hash_elem;
};

unsigned mm_hash (const struct hash_elem* elem, void* aux);
bool mm_less (const struct hash_elem* a, const struct hash_elem* b, void* aux);
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (int status);
void process_activate (void);
void stack_prep(char* cmd_string, char* argv[], int* argc);
static bool setup_stack (void **esp, char** argv, int argc);
bool install_page (void *upage, void *kpage, bool writable);


#endif /* userprog/process.h */
