#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
//do we need threads include?

struct thread_process {
	int process_id;
	int status;
	bool waiting;
	bool exit;

	struct lock delay_lock;
	struct list_elem element;
};
// User added: so child process stucts
// adds/gets/remove methods for these

void syscall_init (void);

struct thread_process* add_thread_process(int process_id);
struct thread_process* get_thread_process)int process_id);

//User added: ways to removes them from list or clear list
void remove_them_all(void);
void remove_child_process(struct thread_process *tp); //haha tp

void process_close_file(int closed);



#endif /* userprog/syscall.h */
