#include <bitmap.h>
#include "threads/vaddr.h"
#include "vm/swap.h"
#include "devices/block.h"

#define SECTOR_SIZE (PGSIZE/BLOCK_SECTOR_SIZE)

struct block* swap_block;
struct bitmap* swap_map;

void swap_init()
{
	swap_block = block_get_role(BLOCK_SWAP);
	swap_map = bitmap_create((block_size(swap_block)/SECTOR_SIZE));
	if(!swap_block || !swap_map)
	{
		PANIC("Panic initialzing swap");
	}

	bitmap_set_all(swap_map, true);

}

size_t swap_out(void* vaddr)
{
	size_t swap_index = bitmap_scan_and_flip(swap_map,0,1,true);

	if(swap_index == BITMAP_ERROR)
	{
		PANIC("Swap partitions full");
	}

	int i = 0;
	while(i++ < SECTOR_SIZE)
	{
		block_write(swap_block, swap_index*SECTOR_SIZE + i, vaddr+ i*SECTOR_SIZE);

	}
	return swap_index;
}

void swap_in(size_t swap_index, void* vaddr)
{
	int i = 0;
	while(i++ < SECTOR_SIZE)
	{
		block_read(swap_block, swap_index*SECTOR_SIZE + i, vaddr+ i*SECTOR_SIZE);
	}

	bitmap_flip(swap_map, swap_index);
}