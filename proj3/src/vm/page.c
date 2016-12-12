#include "vm/page.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/syscall.h"

bool page_less(const struct hash_elem *a, const struct hash_elem *b,void *aux)
{
	const struct page_entry* temp_a = hash_entry(a,struct page_entry, hash_elem);
	const struct page_entry* temp_b = hash_entry(b, struct page_entry, hash_elem);
	return temp_a->vaddr < temp_b->vaddr;
}

unsigned hash_page(const struct hash_elem *h, void* aux)
{
	const struct page_entry* temp= hash_entry(h, struct page_entry, hash_elem);
	return hash_bytes(&temp->vaddr, sizeof(temp->vaddr));

}

struct page_entry* find_page( void* vaddr)
{
	//see pintos doc ofr this impl and same for frame
	struct page_entry p;
	struct hash_elem *e;
	struct thread* cur = thread_current();

	p.vaddr = vaddr;
	e = hash_find(&cur->spt, &p.hash_elem);
	return e!=NULL ? hash_entry(e, struct page_entry, hash_elem) : NULL;
}

bool load_page_file(struct page_entry* spe)
{

 //grab memory. do we join w PAL_ZERO if ofs = 0?
 uint8_t* kpage = frame_alloc(PAL_USER);
 if(!kpage){return false;}

 //load it
 if(file_read_at(spe->file, kpage, spe->read_bytes, spe->offset)!=spe->read_bytes)
 {
 	free_frame(kpage);
 	return false;
 }

 memset(kpage +spe->read_bytes,0,spe->zero_bytes);

 if(!install_page(spe->vaddr, kpage ,true))
 {
 	free_frame(kpage);
 	return false;
 }

 spe->loaded = true;
 return true;
}

bool load_page_swap(struct page_entry* spe)
{
	uint8_t* kpage = frame_alloc(PAL_USER);
	if(!kpage){return false;}

	if(!install_page(spe->vaddr, kpage,spe->writeable))
	{
		free_frame(kpage);
		return false;
	}

	swap_in(spe->swap_slot_index, spe->vaddr);
	spe->loaded = true;
	return true;
}

bool load_page_mmap(struct page_entry* spe)
{
	 //move file pos to where it's should be before load
 file_seek(spe->file, spe->offset);

 //grab memory. do we join w PAL_ZERO if ofs = 0?
 uint8_t* kpage = frame_alloc(PAL_USER); 
 if(!kpage){return false;}

 //load it
 if(file_read(spe->file, kpage, spe->read_bytes)!=spe->read_bytes)
 {
 	free_frame(kpage);
 	return false;
 }

 memset(kpage +spe->read_bytes,0,spe->zero_bytes);

 if(!install_page(spe->vaddr, kpage ,spe->writeable))
 {
 	free_frame(kpage);
 	return false;
 }

 spe->loaded = true;
 if(spe->type& SWAP)
 {
 	printf("can imerge\n");
 	spe->type = MMAP;
 }
 return true;
}

bool load_page(struct page_entry* spe)
{
	bool loaded;

	switch(spe->type)
	{
		case FILE:
			
			lock_acquire(&file_lock);
			loaded = load_page_file(spe);
			lock_release(&file_lock);
			break;

		case MMAP:
			printf("laod mmap\n");
			loaded = load_page_mmap(spe);
			break;

		case SWAP:
			printf("laod swap\n");
			loaded = load_page_swap(spe);
			break;

		default:
			loaded = false;
			break;
	}
	if(loaded == false){printf("load problem\n");}
	return loaded;
}

void grow_stack(void* vaddr)
{
	printf("growing stack\n");
	void* temp = frame_alloc(PAL_USER | PAL_ZERO);
	if(temp == NULL)
	{
		return;
	}
	else
	{
		if(!install_page(pg_round_down(vaddr),temp,true))
		{
			free_frame(temp);
		}
	}
}

bool spt_insert_mmf(struct file* file, off_t offset, uint8_t* upage, uint32_t read_bytes)
{
	struct page_entry* page_entry = malloc(sizeof(*page_entry));
	if(!page_entry){return false;}

 	page_entry->type = MMAP;
	page_entry->read_bytes = read_bytes;
	page_entry->file = file;
	page_entry->offset = offset;
	page_entry->vaddr = upage;


	return (!hash_insert(&thread_current()->spt, &page_entry->hash_elem));
}

bool spt_insert_file(struct file* file, off_t offset, uint8_t* upage, uint32_t read_bytes, uint32_t zero_bytes, bool writeable)
{
	struct page_entry* page_entry = malloc(sizeof(*page_entry));
	if(!page_entry){return false;}

	page_entry->type = FILE;
	page_entry->read_bytes = read_bytes;
	page_entry->zero_bytes = zero_bytes;
	page_entry->file = file;
	page_entry->offset = offset;
	page_entry->vaddr = upage;
	page_entry->writeable = writeable;
	page_entry->loaded = false;

	//printf("spt insert:%p\n",upage);
	return (!hash_insert(&thread_current()->spt, &page_entry->hash_elem));
}


