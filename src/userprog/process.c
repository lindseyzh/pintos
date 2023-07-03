#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/** Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *cmdline) 
{
  char *cmd1, *cmd2, *tmp, *process_name;
  tid_t tid;
  struct thread *cur = thread_current();

  /* Make a copy of cmdline input.
     Otherwise there's a race between the caller and load(). */
  cmd1 = palloc_get_page (0);
  cmd2 = palloc_get_page (0);
  if (cmd1 == NULL || cmd2 == NULL)
    return TID_ERROR;
  strlcpy (cmd1, cmdline, PGSIZE);
  strlcpy (cmd2, cmdline, PGSIZE);

  /* Parse the cmdline. 
     Note: The function "strtok()" results in error because it is not reentrant. */
  process_name = strtok_r(cmd1, " ", &tmp); 

  /* Create a new thread to execute the process. */
  tid = thread_create (process_name, PRI_DEFAULT, start_process, cmd2);

  palloc_free_page (cmd1);

  /* Error checking. Free the pages to prevent memory leaking. */
  if (tid == TID_ERROR){
    return TID_ERROR;
  }

  /* Wait for its child. Return -1 if fails. */
  sema_down(&cur->sema_parent);

  /* Return -1 on failure. */
  if(!cur->exec_success)
    return -1;
  /* Reset the flag on success. */
  cur->exec_success = 0; 

  return tid;
}

/** A thread function that loads a user process and starts it
   running. */
static void
start_process (void *cmdline_)
{
  char *cmdline = cmdline_, *cur_arg, *save_ptr;
  char *cmdline_dup = palloc_get_page (0);
  strlcpy (cmdline_dup, cmdline, PGSIZE);

  int argc = 0; // The number of arguments
  void *argv[64];  // The value of arguments
  /* Note: cmdline is less than 128 bytes, so the number of
     arguments is less than 64 bytes. (A space is needed between 
     any two arguments)*/
  
  struct intr_frame if_;
  bool success;
  struct thread *cur = thread_current();

  /* Initialize interrupt frame and load the executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  char *process_name = strtok_r(cmdline, " ", &save_ptr);

  lock_acquire(&filesys_lock);
  success = load (process_name, &if_.eip, &if_.esp);
  lock_release(&filesys_lock); 

  /* If load failed, quit. */
  if (!success) {
    palloc_free_page(cmdline);
    palloc_free_page(cmdline_dup);

    /* Information update. */
    cur->myinfo->exited = 1;
    cur->exit_code = -1;

    /* Wake up the parent thread after setting the return value. */
    sema_up(&cur->parent->sema_parent);
    
    thread_exit ();
  }

  /* Arguments passing */

  /* %esp set to PHYS_BASE */
  if_.esp = PHYS_BASE;

  /* Parse the command line input into arguments and
     put them into the stack in right-to-left order. 
     Store the address in argv[] for later use. */
  cur_arg = strtok_r(cmdline_dup, " ", &save_ptr);
  while(cur_arg != NULL){
    int arg_len = strlen(cur_arg) + 1;
    if_.esp -= arg_len;
    argv[argc++] = if_.esp; // store the addr of args in argv
    memcpy(if_.esp, cur_arg, arg_len * sizeof(char));
    cur_arg = strtok_r(NULL, " ", &save_ptr);
  }

  /* Stack alignment */
  if_.esp -= ((uintptr_t)if_.esp) % 4;

  /* Push the pointers into the stack*/
  if_.esp -= sizeof(void *);
  *(uintptr_t *)if_.esp = (uintptr_t) 0; // a NULL pointer sentinel
  for(int i = argc - 1; i >= 0; i--){
    if_.esp -= sizeof(void *);
    memcpy(if_.esp, &argv[i], sizeof(void *));
  }

  /* Push argv (current %esp) and argc */
  if_.esp -= sizeof(void *);
  *(uintptr_t *)if_.esp = (uintptr_t)if_.esp + sizeof(void*);
  if_.esp -= sizeof(void *); 
  *(int *)if_.esp = argc;

  /* Push 0 as a fake return address */
  if_.esp -= sizeof(void *);
  *(uintptr_t *)if_.esp = (uintptr_t) 0; 

  /* Check if there is any stack overflow. */
  if(!thread_check_magic())
    thread_exit();

  /* Deny writing of the exec file*/
  lock_acquire(&filesys_lock);
  struct file *f = filesys_open(process_name);
  file_deny_write(f);
  lock_release(&filesys_lock);
  cur->cur_exec_file = f;

  palloc_free_page(cmdline);
  palloc_free_page(cmdline_dup);

  /* Load success. Wake up the waiting parent. */
  cur->parent->exec_success = 1;
  sema_up(&cur->parent->sema_parent);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/** Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.
 */
int
process_wait (tid_t child_tid) 
{
  struct thread *cur = thread_current();
  struct list_elem *e;

  /* Search the child list for the child*/
  for(e = list_begin(&cur->child_list); e != list_end(&cur->child_list); 
      e = list_next(e)){
    struct child_info *c = list_entry(e, struct child_info, elem);

    if(c->tid == child_tid){
      /* If the child has been waited on, return -1. */
      if(c->waited)
        return -1;
      c->waited = 1;

      /* If the child is alive and never waited on, wait on it. */
      if(!c->exited){
          sema_down(&c->sema_child); // waiting for the child
          return c->exit_code;
      }

      /* If the child has exited, return the exit code. */
      return c->exit_code;
    }
  }
  return -1;
}

/** Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  printf ("%s: exit(%d)\n", cur->name, cur->exit_code);
  uint32_t *pd;

  /* For lab 3 */
  /* Unmap the pages */
  while(!list_empty(&cur->mmap_list)){
    struct list_elem *e = list_begin (&cur->mmap_list);
    struct mmap_entry *mmap_e = list_entry(e, struct mmap_entry, elem);
    munmap_without_syscall(mmap_e->mmapid);
  }

  /* Destroy the supplementary page table */
  hash_destroy(&cur->supp_page_table, supp_hash_destructor);

  /* For Lab 2: Close the executable of current thread.*/
  lock_acquire(&filesys_lock);
  if(cur->cur_exec_file)
    file_allow_write(cur->cur_exec_file);
  file_close(cur->cur_exec_file);
  lock_release(&filesys_lock);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/** Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/** We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/** ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/** For use with ELF types in printf(). */
#define PE32Wx PRIx32   /**< Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /**< Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /**< Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /**< Print Elf32_Half in hexadecimal. */

/** Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/** Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/** Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /**< Ignore. */
#define PT_LOAD    1            /**< Loadable segment. */
#define PT_DYNAMIC 2            /**< Dynamic linking info. */
#define PT_INTERP  3            /**< Name of dynamic loader. */
#define PT_NOTE    4            /**< Auxiliary info. */
#define PT_SHLIB   5            /**< Reserved. */
#define PT_PHDR    6            /**< Program header table. */
#define PT_STACK   0x6474e551   /**< Stack segment. */

/** Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /**< Executable. */
#define PF_W 2          /**< Writable. */
#define PF_R 4          /**< Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/** Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();

  /* Lab 3: supplementary page table initialization */
  hash_init(&t->supp_page_table, supp_hash_func, supp_less_func, NULL);

  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */

  /* Note: the file should not be closed here!!! in lab 3 */
  // file_close (file);
  return success;
}

/** load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/** Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/** Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
        We will read PAGE_READ_BYTES bytes from FILE
        and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Load */
      struct thread *cur = thread_current();

      ASSERT (pagedir_get_page(cur->pagedir, upage) == NULL); 

      if(!supp_install_page_file(cur, upage, file, ofs, page_read_bytes, 
            page_zero_bytes, writable)){
        return 0;
      }

      /* Old version before lab 3*/
      // /* Get a page of memory. */
      // // uint8_t *kpage = palloc_get_page (PAL_USER);
      // uint8_t *kpage = frame_alloc (PAL_USER, upage);

      // if (kpage == NULL)
      //   return false;

      // /* Load this page. */
      // if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
      //   {
      //     frame_free (kpage);
      //     return false; 
      //   }
      // memset (kpage + page_read_bytes, 0, page_zero_bytes);

      // /* Add the page to the process's address space. */
      // if (!install_page (upage, kpage, writable)) 
      //   {
      //     frame_free (kpage);
      //     return false; 
      //   }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;

      /* Added in Lab 3 */
      ofs += PGSIZE;
    }
  return true;
}

/** Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = frame_alloc (PAL_USER | PAL_ZERO, PHYS_BASE - PGSIZE);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        frame_free (kpage);
    }
  return success;
}

/** Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  bool ans = (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable))
          && supp_install_frame(t, upage, kpage, writable);
  if(ans){
    frame_set_pinned(kpage, 0);
    return true;
  }
  return false;
}
