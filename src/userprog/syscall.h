#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

struct lock filesys_lock;       /**< A lock for the whole file system. */

#endif /**< userprog/syscall.h */
