#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "threads/malloc.h"

/* Syscall handlers for different syscalls. */
static void syscall_handler (struct intr_frame *);
static void syscall_halt(struct intr_frame *);
static void syscall_exit(struct intr_frame *);
static void syscall_exec(struct intr_frame *);
static void syscall_wait(struct intr_frame *);
static void syscall_create(struct intr_frame *);
static void syscall_remove(struct intr_frame *);
static void syscall_open(struct intr_frame *);
static void syscall_filesize(struct intr_frame *);
static void syscall_read(struct intr_frame *);
static void syscall_write(struct intr_frame *);
static void syscall_seek(struct intr_frame *);
static void syscall_tell(struct intr_frame *);
static void syscall_close(struct intr_frame *);

/* Check the validity of a pointer from userprog. 
   The first one is an old version. */
static void *check_ptr(void *);
static void *check_ptr_more(void *);
inline bool check_pg_ptr(void *ptr);

/* Assistance function of user memeory accessing */
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

/* Kill the userprog and return -1 if needed.*/
static inline void exit_on_error();

/* Transfer a file descriptor into a pointer to struct file. 
   Return NULL if the file descriptor does not exit. */
static struct file_info *fd_to_file_info(int fd);

void
syscall_init (void) 
{
  /* File system lock initialization. */
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  /* Get the syscall_num. */
  int syscall_num = *(int *)check_ptr_more(f->esp); 
  // printf("syscall=%d",syscall_num);
  switch(syscall_num){
    case SYS_HALT:
      syscall_halt(f);
      break;
    case SYS_EXIT:
      syscall_exit(f);
      break;
    case SYS_EXEC:
      syscall_exec(f);
      break;
    case SYS_WAIT:
      syscall_wait(f);
      break;
    case SYS_CREATE:
      syscall_create(f);
      break;
    case SYS_REMOVE:
      syscall_remove(f);
      break;
    case SYS_OPEN:
      syscall_open(f);
      break;
    case SYS_FILESIZE:
      syscall_filesize(f);
      break;
    case SYS_READ:
      syscall_read(f);
      break;
    case SYS_WRITE:
      syscall_write(f);
      break;
    case SYS_SEEK:
      syscall_seek(f);
      break;
    case SYS_TELL:
      syscall_tell(f);
      break;
    case SYS_CLOSE:
      syscall_close(f);
      break;
    default:
      NOT_REACHED();
      break;
  }
}

/* 1. HALT*/
static void 
syscall_halt(struct intr_frame *f){
  shutdown_power_off();
}

/* 2. EXIT*/
static void 
syscall_exit(struct intr_frame *f){
  int exit_code = *(int *)check_ptr((void*)f->esp + sizeof(void *));
  /* exit code is on the top of the stack */
  thread_current()->exit_code = exit_code;
  thread_exit();
}

/* 3. EXEC*/
static void 
syscall_exec(struct intr_frame *f){
  char *cmdline = *(char **)check_ptr_more(f->esp + sizeof(void *));
  check_ptr_more(cmdline);
  f->eax = process_execute(cmdline);
}

/* 4. WAIT */
static void 
syscall_wait(struct intr_frame *f){
  int wait_pid = *(int *)check_ptr_more(f->esp + sizeof(void*));
  f->eax = process_wait(wait_pid);
}


/* 5. CREATE */
static void 
syscall_create(struct intr_frame *f){
  char *name = *(char **)check_ptr_more(f->esp + sizeof(void *));
  check_ptr_more(name);
  unsigned ini_size = 
        *(unsigned*)check_ptr_more(f->esp + sizeof(void *) * 2);

  lock_acquire(&filesys_lock);
  f->eax = filesys_create(name, ini_size);
  lock_release(&filesys_lock);
}

/* 6. REMOVE */
static void 
syscall_remove(struct intr_frame *f){
  char *name = *(char **)check_ptr_more(f->esp + sizeof(void *));
  check_ptr_more((void *)name);

  lock_acquire(&filesys_lock);
  f->eax = (uint32_t)filesys_remove(name);
  lock_release(&filesys_lock);
}

/* 7. OPEN */
static void 
syscall_open(struct intr_frame *f){
  char *name = *(char **)check_ptr_more(f->esp + sizeof(void *));
  check_ptr_more((void *)name);

  lock_acquire(&filesys_lock);
  struct file *open_file = filesys_open(name);
  lock_release(&filesys_lock);
  
  /* Set the return value as -1 if fails. */
  if(open_file == NULL){
    f->eax = -1;
    return;
  }

  /* Store the information of open file. */
  struct thread *cur = thread_current();
  struct file_info *fi = 
          (struct file_info *)malloc(sizeof(struct file_info));
  fi->f = open_file;
  fi->fd = cur->fd_num++;
  list_push_back(&cur->file_list, &fi->elem);
  f->eax = fi->fd;
}

/* 8. filesize*/
static void 
syscall_filesize(struct intr_frame *f){
  int fd = *(int *)check_ptr_more(f->esp + sizeof(void *));
  struct thread *cur = thread_current();

  struct file_info *fi = fd_to_file_info(fd);

  if(fi == NULL || fi->f == NULL) {
    f->eax = -1;
    return;
  }

  lock_acquire(&filesys_lock);
  f->eax = (uint32_t)file_length(fi->f);
  lock_release(&filesys_lock);
}

/* 9. read*/
static void 
syscall_read(struct intr_frame *f){
  int fd = *(int*)check_ptr_more(f->esp + sizeof(void*));
  void *buffer = *(void **)check_ptr_more(f->esp + 2 * sizeof(void*));
  unsigned size = *(unsigned *)check_ptr_more(f->esp + 3 * sizeof(void*));
  check_ptr_more(buffer);

  /* fd == STDIN: input_getc() */
  if(fd == STDIN_FILENO){ 
    uint8_t *b = (uint8_t *)buffer;
    for(int i = 0; i < size; i++)
      b[i] = input_getc();
    f->eax = size;
    return;
  }

  /* fd == STDOUT: terminate the process. */
  if(fd == STDOUT_FILENO){
    exit_on_error();
  }

  /* Other file descriptors: file_read() */
  struct file_info *fi = fd_to_file_info(fd);
  if(fi != NULL && fi->f != NULL){
    lock_acquire(&filesys_lock);
    f->eax = file_read(fi->f, buffer, size);
    lock_release(&filesys_lock);
    return;
  }

  /* Return -1 on failure. */
  f->eax = -1;
}

/* 10. write */
static void 
syscall_write(struct intr_frame *f){
  int fd = *(int*)check_ptr_more(f->esp + sizeof(void*));
  void *buffer = *(void**)check_ptr_more(f->esp + 2 * sizeof(void*));
  unsigned size = *(unsigned *)check_ptr_more(f->esp + 3 * sizeof(void*));
  check_ptr_more(buffer);

  /* If trying to write to STDIN, terminate */
  if(fd == STDIN_FILENO)
    exit_on_error();

  /* STDOUT: putbuf() */
  if(fd == STDOUT_FILENO){
    putbuf((char*)buffer, size);
    f->eax = size; // Return the number of chars
    return;
  }

  /* Other file descriptors: fild_write() */
  struct file_info *fi = fd_to_file_info(fd);
  if(fi != NULL){
    lock_acquire(&filesys_lock);
    f->eax = file_write(fi->f, buffer, size);
    lock_release(&filesys_lock);
    return;
  } 

  /* Return -1 on failure. */
  f->eax = -1;
}


/* 11. seek */
static void 
syscall_seek(struct intr_frame *f){
  int fd = *(int *)check_ptr_more(f->esp + sizeof(void *));
  unsigned pos = *(unsigned *)check_ptr_more(f->esp + 2 * sizeof(void*));
  struct file_info *fi = fd_to_file_info(fd);
  if(fi != NULL){
    lock_acquire(&filesys_lock);
    file_seek(fi->f, pos);
    lock_release(&filesys_lock);
  } 
}

/* 12. tell */
static void 
syscall_tell(struct intr_frame *f){
  int fd = *(int *)check_ptr_more(f->esp + sizeof(void *));
  struct file_info *fi = fd_to_file_info(fd);
  if(fi != NULL){
    lock_acquire(&filesys_lock);
    f->eax = file_tell(fi->f);    
    lock_release(&filesys_lock);
  }
  f->eax = -1;
}

/* 13. close */
static void 
syscall_close(struct intr_frame *f){
  int fd = *(int *)check_ptr_more(f->esp + sizeof(void *));
  struct file_info *fi = fd_to_file_info(fd);
  if(fi != NULL && fi->f != NULL){
    lock_acquire(&filesys_lock);
    file_close(fi->f);
    list_remove(&fi->elem);
    free(fi);
    lock_release(&filesys_lock);
  }
}

inline bool check_pg_ptr(void *ptr){
  return ptr && is_user_vaddr(ptr) && 
      pagedir_get_page(thread_current()->pagedir, ptr) != NULL;
}

/* Terminate the process when a fatal error occurs. */
static inline void 
exit_on_error(){
  if(lock_held_by_current_thread(&filesys_lock)){
    lock_release(&filesys_lock);
  }
  thread_current()->exit_code = -1;
  thread_exit();
  NOT_REACHED();
}

/* Two versions of check_ptr. */
/* Is the address safe to visit? */
static void *
check_ptr(void *ptr){
  /* Is the address legal? */
  if(ptr == NULL || !is_user_vaddr(ptr))
    exit_on_error();

  /* Is the address in the current thread page? */
  void *pgptr = pagedir_get_page(thread_current()->pagedir, ptr);
  if(pgptr == NULL)
    exit_on_error();
  
  /* Is the address readable?*/
  if(get_user((uint8_t *)ptr) == -1)
    exit_on_error();
  
  /* Everything checked. A safe pointer. */
  return ptr;
}

/* Check more addresses. */
static void *
check_ptr_more(void *ptr){
  /* Is the address legal? */
  if(ptr == NULL || !is_user_vaddr(ptr))
    exit_on_error();

  /* Is the address in the current thread page? */
  void *pgptr = pagedir_get_page(thread_current()->pagedir, ptr);
  if(pgptr == NULL)
    exit_on_error();
  
  /* Check more addresses. */
  uint8_t *ptrr = (uint8_t *)ptr;
  for(uint8_t i = 0; i < 4; i++){
    if(get_user(ptrr + i) == -1)
      exit_on_error();
  }

  /* Everything checked. A safe pointer. */
  return ptr;
}

/* Assisting functions */

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* Transfer a file descriptor into a pointer to file_info. */
static struct file_info *
fd_to_file_info(int fd){
  struct thread *cur = thread_current();
  struct list_elem *e;
  for(e = list_begin(&cur->file_list); e != list_end(&cur->file_list);
      e = list_next(e)){
    struct file_info *fi = list_entry(e, struct file_info, elem);
    if(fi->fd == fd)
      return fi;
  }
  return NULL;
}