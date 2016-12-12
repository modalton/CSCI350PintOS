#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include "vm/page.h"


static thread_func start_process NO_RETURN;
static bool load (const char *file_name, void (**eip) (void), void **esp);


/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);


  char *saveptr;
  char *cmd = malloc(strlen(fn_copy)+1);
  get_cmnd(fn_copy,cmd);
  

 
  tid = thread_create (cmd, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);
   
  free(cmd);
  //sema so child thread can wake us when loaded exe
  sema_down(&thread_current()->sema_exe);


  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  hash_init(&thread_current()->maptable, mm_hash, mm_less, NULL);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  
  success = load (file_name, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success){
    //sema up wakes us parent saying we didnt load
    thread_current()->parent->load_fail = true;
    sema_up(&thread_current()->parent->sema_exe);
    thread_exit (-1);
  }
  else{
    //just wakes parent to keep going
    sema_up(&thread_current()->parent->sema_exe);
  }


  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

bool check_child(tid_t tid)
{
  struct list_elem *itr = NULL;
  if(list_empty(&thread_current()->children)){return false;}
  for(itr=list_begin(&thread_current()->children); itr!=list_end(&thread_current()->children); itr=list_next(itr))
  {
    if(list_entry(itr, struct thread, child_elem)->tid == tid)
      {break;}
  }
  if(itr != NULL)
    {
      return true;
    }
  return false;
}


/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{ 
  struct thread* current = thread_current();
  struct thread* child = get_thread(child_tid);


  if(current ==NULL || child ==NULL)
  {
    return -1;
  }

  //check child will remove child and prevent double waiting
  if(child->waiting || !check_child(child->tid))
  {
    return -1;
  }


  current->waiting = true;
  sema_down(&current->sema_lock);
  current->waiting = false;

  list_remove(&child->child_elem);
  return current->child_status;
}


/* Free the current process's resources. */
void
process_exit (int status)
{

  struct thread *cur = thread_current ();
  uint32_t *pd;

if(thread_tid()==1){return;}

close_all();
if(cur->parent->waiting)
{ 
  cur->parent->child_status = status;
  sema_up(&cur->parent->sema_lock);
}

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }


}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */


static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  
  //another copy for extraction
  char f_copy[100];
  strlcpy(f_copy, file_name, strlen(file_name)+1);
  char* argv[30];
  int argc;
  stack_prep(f_copy, argv, &argc);

  //put here instead of thread init bc of some preprocessor confilcts
  hash_init(&t->spt, hash_page, page_less, NULL);
 
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */

  file = filesys_open (argv[0]);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", argv[0]);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", argv[0]);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }
  if (!setup_stack (esp, argv, argc))
    goto done;
 
  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
 if(success){
    t->executable = file;
    // deny write to executables
    file_deny_write(file);
  }else
    file_close(file);
  return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. 
*/

//needed another bc boot straping process uses the above one
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  //lazy load. just put it in spt then deal w it as needed later
  while (read_bytes > 0 || zero_bytes > 0) 
    {

      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE -page_read_bytes;

      if(!spt_insert_file(file, ofs, upage, page_read_bytes, page_zero_bytes,writable))
      {
        return false;
      }

      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }

  return true;
} 

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, char **argv, int argc)
{
  uint8_t *kpage;
  bool success = false;
  //kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  kpage = frame_alloc(PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
       {
        *esp = PHYS_BASE;
        //put pointers to args in stack_argv while writing cmdline to stack
        //then when we have to put argv on stack its waiting for us
        int* stack_argv[argc];
        int all_chars=0;

        //write cmdline args to stack
        for(int i=argc-1; i>=0; --i)
        {
          *esp -= (strlen(argv[i])+1);
          stack_argv[i] = (int*) *esp;
          all_chars+=(strlen(argv[i])+1);
          memcpy(*esp,argv[i],strlen(argv[i])+1);
        }

        //4 byte word align
        *esp -= all_chars%4;
        memset(*esp,0, all_chars%4);
        all_chars+=all_chars%4;

        //last of args
        *esp -= 4;
        memset(*esp,0,4);
        all_chars+=4;

        //write argv pointer values to stack (except exe pointer)
        for(int i=argc-1; i>=0; i--)
        {
          *esp -= sizeof(char*); 
          all_chars+= sizeof(char*);
          (*(int**)(*esp)) = stack_argv[i];
        }
        
        //exe pointer
        char* temp = *esp;
        *esp -= sizeof(char**);
        memcpy(*esp, &temp, sizeof(char**));
        all_chars+= sizeof(char**);

        //write argc to stack
        *esp-=4;
        *(int*)(*esp) = argc; //memset sets em all. this will just change as much as it needs

        //Null pointer return address
        *esp -=4;
        memset(*esp,0,4);

        all_chars+=8;
      }

      else
      {
        palloc_free_page (kpage);
      }
    }
  return success;
}

unsigned mm_hash (const struct hash_elem* elem, void* aux)
{
  struct mmentry* temp = hash_entry(elem, struct mmentry, hash_elem);
  return hash_bytes(&temp->mapid, sizeof(temp->mapid));
}

bool mm_less (const struct hash_elem* a, const struct hash_elem* b, void* aux)
{
  const struct mmentry* tempa = hash_entry (a, struct mmentry, hash_elem);
  const struct mmentry* tempb = hash_entry (b, struct mmentry, hash_elem);
  return tempa->mapid < tempb->mapid;
}


/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();
  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

void stack_prep(char* cmd_string, char* argv[], int* argc)
{
  char* saveptr;
  argv[0]=strtok_r(cmd_string," ",&saveptr);
  char* holder;
  *argc=1;
  while((holder=strtok_r(NULL," ",&saveptr))!=NULL)
  {
    argv[(*argc)++] = holder;
    if(*argc == 30){thread_exit(-1);}
  }
}

void get_cmnd(char* cmd_string, char*name)
{
  char* saveptr;
  strlcpy(name,cmd_string,PGSIZE);
  name = strtok_r(name," ",&saveptr);
}


void process_unmap(int id)
{
  struct thread* cur = thread_current();
  struct mmentry mmentry;
  struct mmentry* mm_ptr;
  struct hash_elem* holder;
  struct page_entry page_entry;
  struct page_entry* page_ptr;

  //grab mmentry from threads table then use entry to see
  //how many pages we need to delete in our supp page table

  mmentry.mapid = id;
  holder = hash_delete(&cur->maptable, &mmentry.hash_elem); // use he to deallocate!
  mm_ptr = hash_entry(holder, struct mmentry, hash_elem);

  int counter = mm_ptr->totalpgs;
  int ofs = 0;
  while(counter-- >0)
  {
    page_entry.vaddr = mm_ptr->ptr + ofs;
    holder = hash_delete(&cur->spt, &page_entry.hash_elem);
    if(holder)
    {
      page_ptr = hash_entry(holder, struct page_entry, hash_elem);
      if(pagedir_is_dirty(cur->pagedir, page_ptr->vaddr))
      {
        //if its dirty we can unmap w/o writing it back
        lock_acquire(&file_lock);
        file_write_at(page_ptr->file, page_ptr->vaddr, page_ptr->read_bytes, page_ptr->offset);
        lock_release(&file_lock);
      }
      free(page_ptr);
    }
    //right?
    ofs += PGSIZE;
  }

  lock_acquire(&file_lock);
  file_close(mm_ptr->file);
  lock_release(&file_lock);
}