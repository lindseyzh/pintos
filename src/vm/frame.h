#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include <hash.h>
#include "threads/synch.h"
#include "threads/palloc.h"

#define FRAME_MAGIC 0xcd7bae4c

struct hash frame_hash;
struct lock frame_lock;

struct frame_table_entry{
    struct thread *owner;       /**< The owner thread of the frame. */
    void *kpage, *upage;        /**< The kernel/user page. */
    struct hash_elem elem;    /**< Hash element. */
    bool pinned;                /**< Is the frame pinned? */
    unsigned magic;             /**< Detect stack overflow */ 
};

void frame_init(void);
void* frame_alloc (enum palloc_flags flags, void *upage);

void frame_remove_entry (void*);
void frame_remove_entry_without_lock (void*);

void frame_free (void *kpage);
void frame_free_without_lock (void *kpage);

void frame_set_pinned (void* kpage, bool pinned);

struct frame_table_entry* frame_pick_to_evict(struct thread *t);
void frame_evict(struct frame_table_entry *fte);

unsigned frame_hash_func (const struct hash_elem *e, void *aux UNUSED);
bool frame_less_func (const struct hash_elem *e1, const struct hash_elem *e2, void *aux UNUSED);


#endif

