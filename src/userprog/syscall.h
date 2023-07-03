#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "filesys/filesys.h"
#include "filesys/file.h"

typedef uint32_t mmapid_t;

/* Record the information in mmap */
struct mmap_entry{
    mmapid_t mmapid;        /**< mmap id. Identifies each mmap pair uniquely. */
    struct file* f;         /**< The file mapped from. */
    void *addr;             /**< The starting address of mmap. */
    size_t size;            /**< The size of mapped file. */
    struct list_elem elem;
};

void syscall_init (void);

bool munmap_without_syscall(mmapid_t mmapid);

unsigned char* get_esp_for_page_fault(void);

struct lock filesys_lock;       /**< A lock for the whole file system. */

#endif /**< userprog/syscall.h */


