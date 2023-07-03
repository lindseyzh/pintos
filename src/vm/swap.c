#include "vm/swap.h"

/* Swap initialization */
void swap_init(void){
    swap_block = block_get_role(BLOCK_SWAP);
    swap_size = block_size(swap_block) / SECTORS_PER_PAGE;
    swap_map = bitmap_create(swap_size);

    if(swap_block == NULL || swap_map == NULL){
        PANIC("Error in swap slots creation");
    }

    bitmap_set_all(swap_map, 1);
    /* swap_map: 1 for available, 0 for unavailable */
}

/* Swap out the page */
size_t swap_out(void *page){
    ASSERT (page >= PHYS_BASE);

    size_t i, idx = bitmap_scan_and_flip(swap_map, 0, 1, true);

    ASSERT(idx != BITMAP_ERROR)

    for(i = 0; i < SECTORS_PER_PAGE; i++){
        block_sector_t sector = idx * SECTORS_PER_PAGE + i;
        void* buffer = page + BLOCK_SECTOR_SIZE * i;
        block_write(swap_block, sector, buffer);
    }

    return idx;
}

void swap_in(size_t idx, void *page){
    ASSERT (page >= PHYS_BASE && idx <= swap_size);

    for(size_t i = 0; i < SECTORS_PER_PAGE; i++){
        block_sector_t sector = idx * SECTORS_PER_PAGE + i;
        void* buffer = page + BLOCK_SECTOR_SIZE * i;
        block_read(swap_block, sector, buffer);
    }
    bitmap_flip(swap_map, idx);
}

void swap_free(size_t idx){
    ASSERT (idx <= swap_size);
    bitmap_set(swap_map, idx, 1);
}
