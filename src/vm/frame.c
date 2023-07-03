#include <debug.h>
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

static bool is_frame_table_entry (struct frame_table_entry *fte);

/* Initialization of frame system. */
void 
frame_init(){
    lock_init(&frame_lock);
    hash_init(&frame_hash, frame_hash_func, frame_less_func, NULL);
}

/* Allocate a frame and return the pointer. */
void *
frame_alloc (enum palloc_flags flags, void *upage){
    lock_acquire(&frame_lock);
    
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(is_user_vaddr(upage));

    void *frame_page = palloc_get_page(PAL_USER | flags);
    struct thread *cur =thread_current();

    /** If there are not more space, evict a frame and retry */
    if(!frame_page){
        struct frame_table_entry *frame_to_evict = frame_pick_to_evict(cur);
        ASSERT(is_frame_table_entry(frame_to_evict));
        frame_evict(frame_to_evict);
        frame_page = palloc_get_page(PAL_USER | flags);
        ASSERT(frame_page != NULL);
    }

    struct frame_table_entry *fte = malloc(sizeof(struct frame_table_entry));

    if(!fte){
        lock_release(&frame_lock);
        return NULL;
    }

    fte->owner = cur;
    fte->upage = upage;
    fte->kpage = frame_page;
    fte->pinned = 1;
    fte->magic = FRAME_MAGIC;

    hash_insert(&frame_hash, &fte->elem);

    ASSERT(is_frame_table_entry(fte));

    lock_release(&frame_lock);
    return frame_page;
}

/* Remove a frame table entry without freeing the frame. */
void 
frame_remove_entry (void* kpage){
    lock_acquire(&frame_lock);
    frame_remove_entry_without_lock(kpage);
    lock_release(&frame_lock);
}

/* A version without lock to tackle some synchronization problems */
void 
frame_remove_entry_without_lock (void* kpage){
    ASSERT (is_kernel_vaddr(kpage));
    ASSERT (pg_ofs (kpage) == 0); 

    /** Get the frame table entry from the hash map */
    struct frame_table_entry tmp;
    tmp.kpage = kpage;
    struct hash_elem *e = hash_find(&frame_hash, &tmp.elem);

    if(!e){
        PANIC("The frame is not stored in the frame table.");
    }

    struct frame_table_entry *fte = 
        hash_entry(e, struct frame_table_entry, elem);
    
    ASSERT(is_frame_table_entry(fte));

    /** Remove the frame from frame_hash & frame_list */
    hash_delete(&frame_hash, &fte->elem);

    free(fte);
}


/* Remove a frame table entry and free the frame. */
void 
frame_free (void *kpage){
    lock_acquire(&frame_lock);
    frame_free_without_lock(kpage);
    lock_release(&frame_lock);
}

/* A version without lock to tackle some synchronization problems. */
void 
frame_free_without_lock (void *kpage){
    frame_remove_entry_without_lock(kpage);
    palloc_free_page(kpage);
}

/* Pin a frame if PINNED = 1, or unpin a frame if PINNED = 0. */
void 
frame_set_pinned (void* kpage, bool pinned){
    lock_acquire(&frame_lock);

    /** Get the frame table entry from the hash map */
    struct frame_table_entry tmp;
    tmp.kpage = kpage;
    struct hash_elem *e = hash_find(&frame_hash, &tmp.elem);

    if(!e){
        PANIC("The frame does not exist?");
    }

    struct frame_table_entry *fte = 
        hash_entry(e, struct frame_table_entry, elem);

    ASSERT(is_frame_table_entry(fte));

    fte->pinned = pinned;

    lock_release(&frame_lock);
}

/* Choose a frame to evict. Clock algorithm. */
struct frame_table_entry* frame_pick_to_evict(struct thread *t){
    size_t size = hash_size(&frame_hash);
    uint32_t* pagedir = t->pagedir;
    
    struct hash_iterator i;

    /* Clock algorithm */   

    /* Go through the frame table list. We will always find a
       evictable frame in no more than 2*size iterations (some frames may 
       be pinned).*/

    bool first_loop = 1;
LOOP:

    hash_first (&i, &frame_hash);
    while (hash_next (&i))
    {
        struct frame_table_entry *fte = 
            hash_entry (hash_cur (&i), struct frame_table_entry, elem);
        ASSERT(is_frame_table_entry(fte));

        /* If a frame is pinned, ignore it.  
           if the access bit is 1, reset it; 
           If the access bit is 0, choose the frame.*/
        if(!fte->pinned){
            if(!pagedir_is_accessed(pagedir, fte->upage))
                return fte;
            pagedir_set_accessed(pagedir, fte->upage, 0);
        }
    }

    if(first_loop){
        first_loop = 0;
        goto LOOP;
    }

    return NULL;
}

/* Evict a frame */
void 
frame_evict(struct frame_table_entry* frame_to_evict){
    struct thread *owner = frame_to_evict->owner;
    pagedir_clear_page(owner->pagedir, frame_to_evict->upage);
    size_t swap_idx = swap_out(frame_to_evict->kpage);
    bool dirty = pagedir_is_dirty(owner->pagedir, frame_to_evict->upage) || 
                 pagedir_is_dirty(owner->pagedir, frame_to_evict->kpage);
    supp_update_in_eviction(owner, frame_to_evict->upage, swap_idx, dirty);
    frame_free_without_lock(frame_to_evict->kpage);
}

/* Helper functions for hash map: hash function, comparing functioin
   and hash destructor. */
unsigned 
frame_hash_func (const struct hash_elem *e, void *aux UNUSED){
    struct frame_table_entry *f = 
            hash_entry(e, struct frame_table_entry, elem);
    return hash_bytes(&f->kpage, sizeof(f->kpage));
}

bool 
frame_less_func (const struct hash_elem *e1, const struct hash_elem *e2, void *aux UNUSED){
    struct frame_table_entry *f1 = 
            hash_entry(e1, struct frame_table_entry, elem);
    struct frame_table_entry *f2 = 
            hash_entry(e2, struct frame_table_entry, elem);
    return f1->kpage < f2->kpage;
}

static bool
is_frame_table_entry (struct frame_table_entry *fte)
{
  return fte != NULL && fte->magic == FRAME_MAGIC;
}


