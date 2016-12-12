#include "frame.h"
#include "page.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"


struct frame_table* fr_table;

//Necessary functions and compartors for hashtable initialization
unsigned hash_frame(const struct hash_elem* elem, void *aux UNUSED)
{
	const struct frame_elem *temp = hash_entry(elem, struct frame_elem, hash_elem);
	return hash_bytes(&temp->frame, sizeof(temp->frame));
}

bool frame_less(const struct hash_elem* a, const struct hash_elem* b, void* aux UNUSED)
{
	const struct frame_elem* temp_a = hash_entry(a, struct frame_elem, hash_elem);
	const struct frame_elem* temp_b = hash_entry(b, struct frame_elem, hash_elem);

	return temp_a->frame < temp_b->frame;
	
}

struct frame_elem* find_frame( void* vaddr)
{
	//see pintos doc ofr this impl and same for frame
	struct frame_elem f;
	struct hash_elem *e;
	if(fr_table==NULL){printf("here\n");}
	f.frame = vaddr;
	e = hash_find(&fr_table, &f.hash_elem);
	return e!=NULL ? hash_entry(e, struct frame_elem, hash_elem) : NULL;
}

void frame_page_link(void* upage, void* frame, uint32_t* addr)
{
	struct frame_elem* f = find_frame(frame);
	f->addr = addr;
	f->page_entry = find_page(upage);
}


void frame_table_init(int frames) 
{
	//Alocate then init frame data structs
	fr_table = malloc(sizeof(struct frame_table));
	fr_table->bit_ft = bitmap_create(frames);
	lock_init(&fr_table->ftable_lock);
	hash_init(&fr_table->hash_ft, hash_frame, frame_less, NULL);
}

void add_frame(void* frame)
{
	struct frame_elem* f_elem = malloc(sizeof(struct frame_elem));
	f_elem->frame = frame;
	f_elem->pagedir = thread_current()->pagedir;

	lock_acquire(&fr_table->ftable_lock);
	hash_insert(&fr_table->hash_ft, &f_elem->hash_elem);
	lock_release(&fr_table->ftable_lock);

}

void* frame_alloc(int flags)
{
	void* new_frame = NULL;
	
	if((flags & PAL_USER))
	{
		if(flags & PAL_ZERO)
		{
			new_frame = palloc_get_page(PAL_USER | PAL_ZERO);
		}
		else
		{
			new_frame = palloc_get_page(PAL_USER);
		}
	}

	//chance to add frame or evict pg to swap
	if(new_frame)
	{
		add_frame(new_frame);
	}
	else
	{
		printf("had to evict\n");
		new_frame = frame_evict();
		printf("done\n");
		if(!new_frame){PANIC("FRAME EVICT PROB\n");}
	}

	return new_frame;
}

void free_frame(void* frame)
{
	lock_acquire(&fr_table->ftable_lock);
	
	struct frame_elem f;
	struct hash_elem* h;

	f.frame = frame;
	h = hash_find(&fr_table->hash_ft, &f.hash_elem);
	hash_delete(&fr_table->hash_ft, &h);
	lock_release(&fr_table->ftable_lock);
}

//save for swapping
void save_evict(struct frame_elem* frame_elem)
{	
	//see if page is in threads sup page table. if not make one
	struct page_entry* spe = frame_elem->page_entry;

	if(pagedir_is_dirty(thread_current()->pagedir, spe->vaddr) && spe->type == MMAP)
	{
		file_write_at(spe->file, spe->vaddr, spe->read_bytes, spe->offset);
	}
	else if(pagedir_is_dirty(thread_current()->pagedir, spe->vaddr))
	{	
		printf("swap now\n");
		spe->type = SWAP;
		spe->swap_slot_index = swap_out(spe->vaddr);
	}

	memset(frame_elem->frame, 0,PGSIZE);
	printf("cur pagedir:%p, uvaddr:%p\n",thread_current()->pagedir,spe->vaddr);
	pagedir_clear_page(thread_current()->pagedir, spe->vaddr);
	printf("b\n");
}
 
void* frame_evict()
{
	lock_acquire(&fr_table->ftable_lock);

	struct frame_elem* frame_elem;
	struct hash_iterator i;
	hash_first(&i, fr_table);
    
    int pass =1;
    while(pass++<2)
    {
    	bool firstpass = false;
    	while (hash_next (&i))
      	{
        	frame_elem = hash_entry (hash_cur(&i), struct frame_elem, hash_elem);
          	if(!pagedir_is_accessed(thread_current()->pagedir, frame_elem->page_entry->vaddr) 
        		&& !pagedir_is_dirty(thread_current()->pagedir, frame_elem->page_entry->vaddr))
        	{
        		hash_delete(fr_table, &frame_elem->hash_elem);
        		firstpass = true;
        		break;
        	}
        	else
        	{
        		pagedir_set_accessed(thread_current()->pagedir, frame_elem->page_entry->vaddr, false);
        	} 
      	}
      	if(firstpass){break;}
    }
    
    if(!frame_elem){PANIC("No frames to evict");}

    save_evict(frame_elem);
	lock_release(&fr_table->ftable_lock);

	return frame_elem;
}


