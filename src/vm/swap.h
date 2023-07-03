#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <bitmap.h>
#include "devices/block.h"
#include "threads/vaddr.h"

#define SECTORS_PER_PAGE 8 // = PGSIZE / BLOCK_SECTOR_SIZE = 4096/512 = 8 

struct block *swap_block;
struct bitmap *swap_map;
/* swap_map: 0 for available, 1 for unavailable */

size_t swap_size;

void swap_init(void);

size_t swap_out(void *page);

void swap_in(size_t idx, void *page);

void swap_free(size_t idx);


#endif