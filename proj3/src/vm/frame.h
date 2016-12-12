#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include <stdint.h>
#include <bitmap.h>
#include "threads/synch.h"
#include "vm/page.h"


struct frame_table 
{
	struct hash hash_ft;
	struct bitmap* bit_ft;  //has to be pointer bc of functions
	struct lock ftable_lock;
};

struct frame_elem
{
	//do i need addr like pintos ex?
	void* frame;
	uint32_t* addr;
	struct page_entry* page_entry;
	uint32_t* pagedir;
	struct hash_elem hash_elem;
};

void frame_table_init();
void* frame_alloc(int flags);
void free_frame(void* frame);
void add_frame(void* frame);
void* frame_evict();
#endif