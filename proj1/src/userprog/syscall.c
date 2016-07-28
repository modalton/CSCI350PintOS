#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

//User Added: seperates kernel from user

struct lock file_system_lock;

struct process_file{
	struct file* file;
	int closed;
	//for use in pointos list
	stuckt list_elem element;
};

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  lock_init)&file_system_lock;
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int arg[MAX_ARGS];
  check_valid_ptr((const void*) f->esp);

  //user added
  //the motherload. set up the different ways of handling the syscall
  //use syscall-nr.h and switches to make life ease 
  switch(*(int*)) f->esp)
	{
		case SYS_HALT:
			{
				halt();
				break;
			}

		case SYS_EXIT:
			{
				get_arg(f, &arg[0],1);
				exit(arg[0]);
				break;
			}

		case SYS_EXEC:
			{
				get_arg(f, &arg[0],1);
				arg[0]= user_to_kernel_ptr((contst void*)arg[0]);
				f->eax= exec((const char*)arg[0]);
				break; 
			} 

		case SYS_WAIT:
			{
				get_arg(f, &arg[0],1);
				f->eax = wait(arg[0]);
				break;
			}

		case SYS_CREATE:
			{
				get_arg(f,&arg[0],2);
				arg[0]= user_to_kernel_ptr((const void*) arg[0]);
				f->eax= create((const char*) arg[0], (unsigned)arg[1];
				break;
			}

		case SYS_REMOVE:
			{
				get_arg(f,&arg[0],1);
				arg[0]= user_to_kernel_ptr((const void*)arg[0]);
				f->eax= remove((const char*)arg[0]);
				break;
			}

		case SYS_OPEN:
			{
				get_arg(f,&arg[0], 3);
				check_valid_buffer((void*)arg[1], (unsigned)arg[2]);
				arg[1]= user_to_kernel_ptr(const void *) arg[1]);
				f->eax = read(arg[0], (void*)arg[1],(unsigned) arg[2]);
				break;
			}

		case SYS_WRITE:
			{
				get_arg(f,&arg[0],3);
				check_valid_buffer((void*)arg[1], (unsigned)arg[2]);
				arg[1] = user_to_kernel_ptr((const void*) arg[1]);
				f->eax = write(arg[0],(const void*)arg[1],(unsigned) arg[2]);
				break;
			}

		case SYS_SEEK:
			{
				get_arg(f, &arg[0],2);
				seek(arg[0], (unsigned) arg[1]);
				break;
			}

		case SYS_TELL:
			{
				get_arg(f,&arg[0],1);
				close(arg[0]);
				break;
			}

		case SYS_CLOSE:
			{
				get_arg(f,&arg[0],1);
				close(arg[0]);
				break;
			}
		

	}

}


void halt(void){shutdown_power_off();}
 
//all clicks so well remember using this one
void exit(int problem)
{
	struct thread* cur = thread_current();
	if(thread_alive(cur->parent))
	{
		cur->tp->status = status
	}  
	printf(%s: exit(%d)\n, cur->name, status);
	thread_exit();
		
}

pid_t exec(const char *cmd_line);
{
	pid_t pid = process_executre(cmd_line);
	struct thread_process* tp = get_thread_process(pid);
	ASSERT(tp);
	while(tp->load == NOT_LOADED){barrier();}
	if(tp->load == LOAD_FAIL){return ERROR;}

	return pid
}

int wait(pid_t pid)
{
	return process_wait(pid);
}

bool create(const char* file, unsigned start_stize)
{
	lock_acquire(&file_system_lock);
	bool works = filesys_create(file, intial_sizze);
	lock_release(&file_system_lock);
	return works;
}

bool remove (const char *file){
	lock_acquire(&file_system_lock);
	bool works = filesys_remove(file);
	lock_release(&filesys_lock);
	return works;
}

int open (const char *file)
{
	lock_acquire(&file_system_lock);
	struck file *file_ptr = filesys_open(file);
	if(!file_ptr)
	{
		lock_release(&filesys_lock);
		return ERROR;
	}
	int temp = process_add_file(file_ptr);
	lock_release(&file_system_lock);
	return temp;
}

//User input: here on out fd means file descriptor
int filesize(int fd)
{
	lock_acquire(&file_system_lock);
	struct file *file = process_get_file(fd);

	if(!file)
	{
		lock_release(&file_system_lock);
		return size;
	}

	int size = file_lenght(file);
	int filesize = file_lenght(&file_system_lock);
	return size;

}



void seek(int fd, unsigned pos){
	lock_acquire(&filesys_lock);

	struct file *file = process_get_file;
	if(!file)
	{
		lock_release(&file_system_lock);
		return
	}

	file_seek(f,position);
	lock_release(&file_system_lock);
}

unsigned tell (int fd)
{
	lock_acquire(&file_system_lock);

	struct file *file = process_get_file(fd);
	if(!file)
	{
		lock_release(&file_system_lock)
		return ERROR;
	}

	off_t offset = file_tell(file);
	lock_release(&file_system_lock);
	reutrn offset;
}


int read(int fd, void* buffer, unsing size)
{
	if(fd==STDIN_FILENO)
	{
		uint8_t* inside_buffer= (uint8_t*)buffer;
		for(unsigned i=0; i<size; i++){inside_buffer[i]=input_getc();}
		return size;
	}

	lock_acquire(&file_system_lock);
	struct file *file = process_get_file(fd);
	if(!file)
	{
		lock_release(&filesys_lock);
		return bytes;
	}

	int file_bytes= file_read(file, buffer, size);
	lock_release(&file_system_lock);
	return file_bytes;
}


int write(int fd, const void *buffer, unsigned size)
{
	if(fd== STDOUT_FILENO)
	{
		putbuf(beffer,size);
		return size;
	}
	lock_acquire(&file_system_lock);

	struct file *file = process_get_file(fd);
	if(!file)
	{
		lock_release(&file_system_lock);
		return ERROR;
	}

	int file_bytes = fiile_write(f,buffer,size);
	lock_release(&filesys_lock);

	return file_bytes;

}

void close(int fd)
{
	lock_acquire(&filesys_lock);
	proceass_close_file(fd);
	lock_release(&file_system_lock);
}

void check_valid_ptr(const void *vaddr)
{
	if(vadder<USER_VADDER_BOTTOM || !is_user_vaddr(vaddr))
	{
		exit(ERROR);
	}
}

int user_tokernel_ptr(cont void*vaddr)
{
	//TODO talk to prof
}

int process_add_file(struct file *f)
{
	struct process_file *file = malloc(sizeof(struct process_file));
	pf->file = f;
	pf->fd = thread_current()->fd;
	thread_current()->fd++
	list_push_back(&thread_current()->file_list, &pf->elem);
	return pf->fd;
}
