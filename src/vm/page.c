#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/exception.h"
#include "userprog/syscall.h"
#include <list.h>
#include <stdlib.h>
#include <debug.h>
#include <string.h>

static bool is_supp_page_table_entry (struct supp_page_table_entry *spte);

/* Install upage in the supplementary page of thread t.
   Returns 1 on success, 0 on failure. */
bool 
supp_install_frame (struct thread *t, void *upage, 
                    void *kpage, bool writable){
    struct supp_page_table_entry *spte = (struct supp_page_table_entry*)
                            malloc(sizeof(struct supp_page_table_entry));
    spte->upage = upage;
    spte->kpage = kpage;
    spte->writable = writable;
    spte->page_stat = IN_FRAME;
    spte->dirty = 0;
    spte->swap_idx = -1; 
    spte->magic = PAGE_MAGIC;

    /* Try to insert. */
    bool success = (hash_insert(&t->supp_page_table, &spte->h_elem) == NULL);
    if(success)
        return 1;
    free(spte);
    return 0;
}

/* Install a page (initialized as zero) */
bool 
supp_install_page_zero (struct thread *t, void *upage){
    struct supp_page_table_entry *spte = (struct supp_page_table_entry*)
                            malloc(sizeof(struct supp_page_table_entry));
    spte->upage = upage;
    spte->kpage = NULL;
    spte->page_stat = ALL_ZERO;
    spte->dirty = 0;
    spte->magic = PAGE_MAGIC;

    /* Try to insert. */
    if(hash_insert(&t->supp_page_table, &spte->h_elem) != NULL){
        free(spte);
        return 0;
    }
    return 1;
}

/* Install a page (from file system) */
bool 
supp_install_page_file (struct thread *t, void *upage, 
        struct file* src_file, off_t offset, uint32_t read_bytes, 
        uint32_t zero_bytes, bool writable){
    struct supp_page_table_entry *spte = (struct supp_page_table_entry*)
                            malloc(sizeof(struct supp_page_table_entry));
    
    spte->upage = upage;
    spte->kpage = NULL; 
    spte->src_file = src_file;
    spte->offset = offset;
    spte->read_byte = read_bytes;
    spte->zero_byte = zero_bytes;
    spte->page_stat = IN_FILESYS;
    spte->writable = writable;
    spte->dirty = 0;
    spte->magic = PAGE_MAGIC;

    /* Try to insert. */
    if(hash_insert(&t->supp_page_table, &spte->h_elem) != NULL){
        return 0;
    }
    return 1;
}

/* Uninstall an installed page. */
void 
supp_uninstall_page (struct thread *t, void *upage, 
        struct file* src_file, off_t offset, uint32_t bytes){
    
    struct supp_page_table_entry *spte = supp_page_to_spte(t, upage);
    ASSERT(is_supp_page_table_entry(spte));
    bool dirty;

    switch(spte->page_stat){
        case IN_FRAME:
            /* Pin the kernel */
            frame_set_pinned(spte->kpage, 1);
            dirty = pagedir_is_dirty(t->pagedir, spte->upage) || 
                    pagedir_is_dirty(t->pagedir, spte->kpage) ||
                    spte->dirty;
            if(dirty){
                file_write_at(src_file, spte->upage, bytes, offset);
            }
            pagedir_clear_page(t->pagedir, spte->upage);
            frame_free(spte->kpage);
            break;

        case IN_FILESYS:
            /* Nothing to do. */
            break;

        case IN_SWAP:
            dirty = pagedir_is_dirty(t->pagedir, spte->upage) || 
                    spte->dirty;
            if(dirty){
                void *new_page = palloc_get_page(0);
                swap_in(spte->swap_idx, new_page);
                file_write_at(src_file, new_page, PGSIZE, offset);
                palloc_free_page(new_page);
                break;
            }
            swap_free(spte->swap_idx);
            break;
        
        default:
            NOT_REACHED();
    }

    hash_delete(&t->supp_page_table, &spte->h_elem);
}

/* Search the supplementary table of thread T for 
   the SPTE of UPAGE */
struct supp_page_table_entry *
supp_page_to_spte(struct thread *t, void *upage){
    struct supp_page_table_entry tmp;
    tmp.upage = upage;
    struct hash_elem *e = hash_find(&t->supp_page_table, &tmp.h_elem);
    return e == NULL ? 
           NULL : hash_entry(e, struct supp_page_table_entry, h_elem);
}

/* Load a page from the supp table of a thread. 
   Return 1 in success, 0 on failure (illegal access). */
bool 
supp_load_page(struct thread *t, void *upage){
    ASSERT(pg_ofs(upage) == 0);
    struct supp_page_table_entry *spte = supp_page_to_spte(t, upage);
    void *frame_page;
    bool writable = 1;

    /* If the page does not exist, return 0 */
    if(spte == NULL)
        return 0;

    /* If the page is already in frame, return 1 */
    if(spte->page_stat == IN_FRAME)
        return 1;

    /* Allocate a frame for the page */
    frame_page = frame_alloc(PAL_USER, upage);
    if(!frame_page) 
        return 0;

    ASSERT(is_supp_page_table_entry(spte));

    /* If the page is already in memory, 
       no need to load, return */
    switch(spte->page_stat){
        case ALL_ZERO:
            memset(frame_page, 0, PGSIZE);
            break;

        case IN_FILESYS:
            if(!supp_load_page_from_file(spte, frame_page)){
                frame_free(frame_page);
                return 0;
            }
            writable = spte->writable;
            break;

        case IN_SWAP:
            swap_in(spte->swap_idx, frame_page);
            break;
        
        default:
            NOT_REACHED();
    }
    

    /* Add the mapping to thread pagedir */
    if(!pagedir_set_page(t->pagedir, upage, frame_page, writable)){
        frame_free(frame_page);
        return 0;
    }

    spte->page_stat = IN_FRAME;
    spte->kpage = frame_page;
    pagedir_set_dirty(t->pagedir, frame_page, 0);

    frame_set_pinned(frame_page, 0);
    
    return 1;
}

/* Load a page from file system */
bool 
supp_load_page_from_file(struct supp_page_table_entry *spte, 
                              void *kpage){
    file_seek(spte->src_file, spte->offset);

    if(file_read(spte->src_file, kpage, spte->read_byte) != 
            (int32_t) spte->read_byte){
        return 0;
    }
    memset (kpage + spte->read_byte, 0, spte->zero_byte);
    return 1;
}

/* Update the information stored in supplementary page table
   when an eviction occurs. */
bool 
supp_update_in_eviction(struct thread *t, void *upage, 
                        size_t swap_idx, bool dirty){
    ASSERT(pg_ofs(upage) == 0);
    struct supp_page_table_entry *spte = supp_page_to_spte(t, upage);
    if(spte == NULL) return 0;
    
    spte->page_stat = IN_SWAP;
    spte->kpage = NULL;
    spte->swap_idx = swap_idx;
    spte->dirty = spte->dirty || dirty;
    return 1;
}

/* Pin a page if PINNED = 1, or unpin a page if PINNED = 0.*/
void 
supp_page_set_pinned(struct thread *t, void *upage, bool pinned){
    ASSERT(pg_ofs(upage) == 0);
    struct supp_page_table_entry *spte = supp_page_to_spte(t, upage);
    if(spte != NULL && spte->page_stat == IN_FRAME) {
        frame_set_pinned(spte->kpage, pinned);
    }
}

/* Returns true if spte is a valid supplementary page table entry. */
static bool
is_supp_page_table_entry (struct supp_page_table_entry *spte)
{
  return spte != NULL && spte->magic == PAGE_MAGIC;
}

/* Helper functions for hash map: hash function, comparing functioin
   and hash destructor. */
unsigned 
supp_hash_func (const struct hash_elem *e, void *aux UNUSED){
    struct supp_page_table_entry *s = 
            hash_entry(e, struct supp_page_table_entry, h_elem);
    return hash_bytes(&s->upage, sizeof(s->upage));
}

bool 
supp_less_func (const struct hash_elem *e1, const struct hash_elem *e2, void *aux UNUSED){
    struct supp_page_table_entry *s1 = 
            hash_entry(e1, struct supp_page_table_entry, h_elem);
    struct supp_page_table_entry *s2 = 
            hash_entry(e2, struct supp_page_table_entry, h_elem);
    return s1->upage < s2->upage;
}

void 
supp_hash_destructor(struct hash_elem *e, void *aux UNUSED){
    struct supp_page_table_entry *spte = 
        hash_entry(e, struct supp_page_table_entry, h_elem);
    if(spte->page_stat == IN_FRAME){
        frame_remove_entry(spte->kpage);
    }
    else if(spte->page_stat == IN_SWAP){
        swap_free(spte->swap_idx);
    }
    free(spte);
}

