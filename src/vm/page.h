#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <threads/thread.h>
#include "filesys/file.h"

#define PAGE_MAGIC 0xc0610feb

enum page_status{ALL_ZERO, IN_FRAME, IN_FILESYS, IN_SWAP};

struct supp_page_table_entry{
    struct hash_elem h_elem;
    
    void *upage;                /**< User page. */
    void *kpage;                /**< kernel page. */

    /* For pages from files */
    struct file* src_file;      /**< The source file(if any). */
    off_t offset;               /**< File offset. */
    uint32_t read_byte;         /**< The number of bytes read from file. */
    uint32_t zero_byte;         /**< The remaining bytes filled with zero. */
    size_t swap_idx;            /**< Swap index for swap slots tracking. */

    enum page_status page_stat; /**< The status of current page.*/
    
    bool writable;              /**< Is the page writable? */
    bool dirty;                 /**< Is the page dirty? */

    unsigned magic;             /**< Detects stack overflow. */
};


struct supp_page_table_entry* supp_pte_create(void);

bool supp_install_frame (struct thread *t, void *upage, 
            void *kpage, bool writable);

bool supp_install_page_zero (struct thread *t, void *upage);

bool supp_install_page_file (struct thread *t, void *upage, 
        struct file* src_file, off_t ofs, uint32_t read_bytes, 
        uint32_t zero_bytes, bool writable);

void supp_uninstall_page (struct thread *t, void *upage, 
        struct file* src_file, off_t offset, uint32_t bytes);

struct supp_page_table_entry *supp_page_to_spte(struct thread *t, void *upage);
bool supp_load_page(struct thread *t, void *upage);
bool supp_load_page_from_file(struct supp_page_table_entry *spte, 
                              void *kpage);

bool supp_update_in_eviction(struct thread *t, void *upage, 
                             size_t swap_idx, bool dirty);

void supp_page_set_pinned(struct thread *t, void *upage, bool pinned);

unsigned supp_hash_func (const struct hash_elem *e, void *aux UNUSED);
bool supp_less_func (const struct hash_elem *e1, const struct hash_elem *e2, 
                     void *aux UNUSED);
void supp_hash_destructor(struct hash_elem *e, void *aux UNUSED);

#endif
