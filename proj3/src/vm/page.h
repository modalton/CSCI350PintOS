#ifndef PAGE_H
#define PAGE_H

#include <hash.h>
#include "threads/thread.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/off_t.h"
#include "threads/palloc.h"

#define STACK_MAX (1<<23) //ala pintos

enum entry_type
{
	FILE,
	MMAP,
	SWAP
};

struct supplement_ptable
{
	struct hash* spt_htable;
};

struct page_entry
{
	void* vaddr;
	
	struct file* file;
	uint32_t read_bytes;
	uint32_t zero_bytes;
	off_t offset;

	uint8_t dirty_bit;
	bool writeable;
	bool loaded;
	enum entry_type type;

	size_t swap_slot_index;


	struct hash_elem hash_elem;
};

struct page_entry* find_page(void* vaddr);
unsigned hash_page(const struct hash_elem *h, void* aux);
bool page_less(const struct hash_elem *a, const struct hash_elem *b,void *aux);

#endif