#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);

//helper functions
struct fd_elem* get_entry(int fd);
void ptr_check(void* vaddr);
void parser(struct intr_frame *f, int *args, int i);
int file_add_helper(char* filename);
bool validate_memory(void* esp, int argc);
void exit(int);

//helper file directory struct
struct fd_elem
{
  int fd;
  char* name;
  struct file* file;
  struct list_elem elem;
};


void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  uint32_t* esp = f->esp;
  int arg[3]; //most args we'll have
  ptr_check(esp);

  int call_num = *(esp);
  if(call_num < 0 || call_num >=20)
  {
    thread_exit(-1);
  }

  switch(*(int*)f->esp)
  {


    case SYS_HALT:
    {
      shutdown_power_off();
      break;
    }



    case SYS_EXIT:
    {
      parser(f, &arg[0],1);
      exit(arg[0]);
      break;
    }

    case SYS_READ:
    {
      parser(f,&arg[0],3);
      buf_check(arg[1], arg[2]);
      real_addr_convert(arg[1]);
      
      lock_acquire(&file_lock);

      if(arg[0]==STDOUT_FILENO)
      {
        int i = 0;
        while(i<=arg[2])
        {
          *((char*)arg[1]+i) = input_getc();
          i++;
        }
        if(i ==0){i=-1;} //incase you wait until it fails and dont type anything
        f->eax = i;
        break;
      }


      if(get_entry(arg[0]))
      {
        struct fd_elem* fd_elem = get_entry(arg[0]);
        f->eax = file_read(fd_elem->file,arg[1],arg[2]);

      }
      else
      {
        f->eax = -1;
      }

      lock_release(&file_lock);
      break;
    } 
    
    case SYS_WRITE:
    {
      parser(f,&arg[0],3);
      buf_check(arg[1], arg[2]);
      real_addr_convert(arg[1]);

      if(arg[0]==STDOUT_FILENO)
      {
        putbuf((char*)arg[1],arg[2]);
        f->eax = arg[2];
        break;
      }
     
      lock_acquire(&file_lock);
      if(get_entry(arg[0]))
      {
        
        f->eax = (int)file_write(get_entry(arg[0])->file,arg[1],arg[2]);
        lock_release(&file_lock);
        break;
      }
      
      lock_release(&file_lock);
      f->eax = -1;
      break;
    } 
    


    case SYS_CREATE:
    {
      parser(f,&arg[0],2);
      real_addr_convert(arg[0]);

      lock_acquire(&file_lock);
      f->eax = filesys_create((char*)arg[0],arg[1]);
      lock_release(&file_lock);

      break;
    }


    case SYS_OPEN:
    {
      parser(f, &arg[0],1);
      real_addr_convert(arg[0]);

      lock_acquire(&file_lock);
      f->eax= file_add_helper((char*) arg[0]);
      lock_release(&file_lock);

      break;

    }


    case SYS_EXEC:
    {
      parser(f, &arg[0], 1);
      real_addr_convert(arg[0]);

      tid_t tid = process_execute(arg[0]);
      if(tid == -1){
        f->eax = -1;
        break;
        }

      struct thread* created = get_thread(tid);
      if(created == NULL)
      {
        f->eax = -1;
        break;
      }

      while(!created->executable)
      {
        if(thread_current()->load_fail)
        {
          tid = -1;
          break;
        }
        barrier();
      }
      
      f->eax = tid;
      
      break;

    }


    case SYS_WAIT:
    {
      parser(f,&arg[0],1);
      f->eax = process_wait(arg[0]);
      break;
    }

    case SYS_REMOVE:
    {
      parser(f,&arg[0],1);
      real_addr_convert(arg[0]);

      lock_acquire(&file_lock);
      f->eax = filesys_remove(arg[0]);
      lock_release(&file_lock);
      break;
    }

    case SYS_FILESIZE:
    {
      parser(f,&arg[0],1);

      lock_acquire(&file_lock);

      if(get_entry(arg[0]))
      {
        struct fd_elem* fd_elem = get_entry(arg[0]);
        f->eax = file_length(fd_elem->file);
      }
      else
      {
        f->eax = -1;
      }

      lock_release(&file_lock);

      break;
    }

    

    case SYS_SEEK:
    {
      parser(f,&arg[0],2);
      lock_acquire(&file_lock);

      if(get_entry(arg[0]))
      {
        struct fd_elem* fd_elem = get_entry(arg[0]);
        file_seek(fd_elem->file, arg[1]);
        f->eax = 0;
      }
      else
      {
        f->eax = -1; 
      }

      lock_release(&file_lock);
      break;
    }

    case SYS_TELL:
    {
      parser(f, &arg[0], 1);
      lock_acquire(&file_lock);

      if(get_entry(arg[0]))
      {
        struct fd_elem* fd_elem = get_entry(arg[0]);
        f->eax = file_tell(fd_elem->file);
      }
      else
      {
        f->eax = -1;
      }

      lock_release(&file_lock);
      break;
    }

    case SYS_CLOSE:
    {
      parser(f,&arg[0],1);
      lock_acquire(&file_lock);

      close_process(arg[0]);
      
      lock_release(&file_lock);
      break;
    }

    case SYS_MMAP:
    {
      parser(f,&arg[0],2);
      f->eax = mmap(arg[0], arg[1]);
      break;
    }

    case SYS_MUNMAP:
    {
      parser(f,&arg[0],1);
      f->eax = munmap(arg[0]);
      break;
    }

  
  }

}

//mmap/munmap helpers. too man exception cases for main sysclal
mapid_t mmap(int fd, void* addr)
{

  if(!addr || pg_ofs(addr) || fd==0 || fd==1){return -1;}

  struct mmentry* mm_ptr;
  struct fd_elem* fd_elem = get_entry(fd);
  struct thread* cur = thread_current();

  if(!fd_elem){return -1;}

  int file_size = file_length(fd_elem->file);
  if(file_size<= 0){return -1;}

  mm_ptr = malloc(sizeof(struct mmentry));
  mm_ptr->mapid = cur->mapid++;
  mm_ptr->file = fd_elem->file;
  mm_ptr->ptr = addr;
  //check if any part mapped/size then add to spt
  int offset =0;
  int pages = 0;
  while(offset < file_size)
  {
    //should put ina spt get?
    if(find_page(addr+offset) || pagedir_get_page(thread_current()->pagedir, addr+offset))
    {
      return -1;
    }

    size_t page_bytes = offset < PGSIZE ? offset : PGSIZE;
    if(!spt_insert_mmf(fd_elem->file, offset, addr, page_bytes));
    {
      //put in munmap for id
      return-1;
    }

    pages++;
    offset+= PGSIZE;
    file_size -= PGSIZE;
    addr += PGSIZE;
  }

  mm_ptr->totalpgs = pages;


  hash_insert(&cur->maptable, &mm_ptr->hash_elem);
  //success! add to thread adn not just spt
  return cur->mapid;

}

void munmap(mapid_t id)
{
  process_unmap(id);
}


void exit (int status)
{
  printf ("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit(status);
}


void ptr_check(void* vaddr)
{
  //if your a ptr outside allowed scope exit
  //right value is bottom of user vitrual space
  if(!is_user_vaddr(vaddr) || !pagedir_get_page(thread_current()->pagedir, vaddr)){
    exit(-1);
  }
}

void  buf_check(void* buffer, int size)
{
  char* ptr = (char*) buffer;
  for(int i=0; i<size;i++)
  {
    ptr_check((const void*) ptr);
    ptr++;
  }
}

void parser(struct intr_frame* f, int* args, int i)
{
  int *ptr;
  for(int j=0; j<i; j++)
  {
    ptr=(int*)f->esp+(j+1);
    ptr_check((void*)ptr);
    args[j]=(void*)(*ptr);
  }
  if(i==3){args[2]==(void*)(*((int*)f->esp + 2));}
}

//turn virtual address into actual location in memory
//also can check if memory mapped
void real_addr_convert(void* vaddr)
{
  //gotta be void ptr bc dont wanna cast null
  ptr_check(vaddr);
  void* phys_addr = pagedir_get_page(thread_current()->pagedir,vaddr);
  if(phys_addr==NULL){exit(-1);}

  vaddr = phys_addr; 
}

struct fd_elem* get_entry(int fd)
{
  for(struct list_elem* itr=list_begin(&thread_current()->fdtable);itr != list_end(&thread_current()->fdtable); itr = list_next(itr)) 
  {
    struct fd_elem *temp = list_entry(itr, struct fd_elem, elem);
    if(temp->fd==fd)
    {
      return temp;
    }
  }

  return NULL;
}

int file_add_helper(char* filename)
{
  //try to make file
  struct file* file= filesys_open(filename);
  if(!file){return -1;}

  //if we can set up fd elem
  struct fd_elem* fd_elem = malloc(sizeof(struct fd_elem));
  if(!fd_elem){return -1;}

  //give it its attributes and put it on threads table & return fd num
  fd_elem->name=filename;

  fd_elem->file = file;
  fd_elem->fd = thread_current()->fd++;
  list_push_back(&thread_current()->fdtable, &fd_elem->elem);

  return fd_elem->fd;
}

void close_process(int fd)
{
  if(get_entry(fd)!=NULL)
  {
    struct fd_elem* fd_elem = get_entry(fd);
    file_close(fd_elem->file);
    list_remove(&fd_elem->elem);
    free(fd_elem);
  }
}

void close_all()
{
  while(!list_empty(&thread_current()->fdtable))
  {
    struct fd_elem* temp = list_pop_front(&thread_current()->fdtable);
    close_process(temp->fd);
  }

  file_close(thread_current()->executable);
}

//from pintos doc
static int
get_user (const uint8_t *uaddr)
{
  if(!is_user_vaddr(uaddr))
    return -1;
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

bool validate_memory(void* esp, int argc)
{
  for(uint8_t i=0; i<argc; ++i)
  {
    if(get_user(((uint8_t*)esp)+i)==-1)
    {
      return false;
    }
  }
  return true;
}