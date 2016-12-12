#ifndef VM_SWAP_H
#define VM_SWAP_H

void swap_init();
size_t swap_out(void* vaddr);
void swap_in(size_t swap_index, void* vaddr);

#endif