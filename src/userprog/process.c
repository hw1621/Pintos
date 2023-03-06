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
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/sharing.h"

#define MAX_ARGC 128
#define PUSH_TO_STACK(esp, content) esp -= 4; *(int *) esp = content; 
static thread_func start_process NO_RETURN;
static bool setup_stack (void **esp);
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy1, *fn_copy2;
  tid_t tid;
  
  /* Make two copies of FILE_NAME, one is for process_name 
     and another one is for start_process()
     Otherwise there's a race between the caller and load(). */
  fn_copy1 = palloc_get_page (0);
  if (fn_copy1 == NULL)
    return TID_ERROR;
 
  fn_copy2 = palloc_get_page (0);
  if (fn_copy2 == NULL) {
    palloc_free_page (fn_copy1); 
    return TID_ERROR;
  }
    
  strlcpy (fn_copy1, file_name, PGSIZE);
  strlcpy (fn_copy2, file_name, PGSIZE);

  /* Create a new thread to execute FILE_NAME. */
  char *save_ptr;
  char *process_name = strtok_r (fn_copy1, " ", &save_ptr);
  
  tid = thread_create (process_name, PRI_DEFAULT, start_process, fn_copy2);
  palloc_free_page (fn_copy1); 
  if (tid == TID_ERROR){
    palloc_free_page (fn_copy2); 
    return tid;
  }

  /* Sema down the parent process, to load and wait for the child thread */
  sema_down (&thread_current ()->sema_execute);
  if (!thread_current ()->execute_success) 
   return TID_ERROR;

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct thread *cur = thread_current ();
  /* Since we have passed a copy from process_execute(), we can modify file_name.
     But we still need two copies, one for file name, 
     another one for file name and arguments */
  char *fn_copy = palloc_get_page (0);
  strlcpy (fn_copy, file_name, PGSIZE);

  struct intr_frame if_;
  bool success;
  char *token, *save_ptr;
  char *process_name = strtok_r (file_name, " ", &save_ptr);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (process_name, &if_.eip, &if_.esp);
  if (!setup_stack (&if_.esp))
    success = false;

  if (success) {
    /* Set up the stack */
    int argc = 0;
    void* argv[MAX_ARGC]; /* Assume we will have at most 128 arguments */
    /* Let the stack pointer be at the user virtual address space */
    if_.esp = PHYS_BASE;
    /* The necessary stack space left for a null pointer, 
       a pointer to the first pointer, number of arg, 
       return address which all need 4 space*/
    /* Push the arguments onto the stack, in reverse order */
    int remain_stack_space = PGSIZE;
    for (token = strtok_r (fn_copy, " ", &save_ptr); token != NULL; 
                           token = strtok_r (NULL, " ", &save_ptr)) {                    
      size_t arg_length = strlen (token) + 1; /* need to keep a space for \0 */
      /* Judge whether stack overflow will happen, if yes, thread_exit() */
      remain_stack_space -= (arg_length + 4);
      if (argc >= MAX_ARGC || remain_stack_space < 0 ) {
        cur->parent_thread->execute_success = false;
        sema_up (&cur->parent_thread->sema_execute);
        thread_exit ();
      }  
      if_.esp -= arg_length;
      memcpy (if_.esp, token, arg_length);
      argv[argc++] = if_.esp;
    }

    /* Round the stack pointer down to a multiple of 4 */
    uintptr_t round_value = (uintptr_t) if_.esp; /* Pointer can't do modulo directly */
    if (round_value % 4 != 0)
      round_value -= round_value % 4;
    if_.esp = (void *) round_value;
    /* Push a null pointer sentinel (0) */
    PUSH_TO_STACK (if_.esp, 0);
    /* Push pointers to the arguments, in reverse order */
    for (int i = argc - 1; i >= 0; i--) {
      PUSH_TO_STACK (if_.esp, (int) argv[i]);
    }
    PUSH_TO_STACK (if_.esp, (int) if_.esp + 4);   /* Push a pointer to the ﬁrst pointer */
    PUSH_TO_STACK (if_.esp, (int) argc);          /* Push the number of arguments */
    PUSH_TO_STACK (if_.esp, 0);                   /* Push a fake return address (0) */

    /* Record the exec_status of the parent thread's success and sema up parent's semaphore */
    cur->parent_thread->execute_success = true;
    sema_up (&cur->parent_thread->sema_execute);
  }

  palloc_free_page (process_name);
  palloc_free_page (fn_copy); 

  /* If load failed, quit. */
  if (!success) {
    cur->parent_thread->execute_success = false;
    sema_up (&cur->parent_thread->sema_execute);
    thread_exit ();
  } 

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status. 
 * If it was terminated by the kernel (i.e. killed due to an exception), 
 * returns -1.  
 * If TID is invalid or if it was not a child of the calling process, or if 
 * process_wait() has already been successfully called for the given TID, 
 * returns -1 immediately, without waiting.
 * 
 * This function will be implemented in task 2.
 * For now, it does nothing. */
int
process_wait (tid_t child_tid) 
{ 
  struct thread *cur = thread_current ();
  struct list proc_list = cur->child_proc_list;
  struct list_elem *elem_i;
  struct child_process *child_t = NULL;
  if (list_empty (&cur->child_proc_list) || child_tid == TID_ERROR) {
    return -1;
  }
  
  // get child processs exit status by child_tid
  for (elem_i = list_begin (&proc_list); 
       elem_i != list_end (&proc_list); elem_i = list_next (elem_i)) {
    child_t = list_entry (elem_i, struct child_process, child_elem);
    if (child_t->child_tid == child_tid) {
      list_remove (elem_i);
      // check whether the child process has been waited (finished)
      if (!child_t->is_finished) {
        // Not been waited yet, so wait for child process
        sema_down (&child_t->parent_wait);
        // The child process has now finished
        child_t->is_finished = true;
      }
      return child_t->exit_status;
    }
  }
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  
  struct list *map_list = &cur->mapped_file_fd_list;
  struct list_elem *e;
  while (!list_empty (map_list)) {
    e = list_front (map_list);
    struct map_descriptor *map_d = list_entry (e, struct map_descriptor, elem);
    syscall_mumap (map_d->id);
  }
  if (!lock_held_by_current_thread (&filesys_lock))
    lock_acquire (&filesys_lock);
  // Try tp close the executable file if no longer required
  free_supl_page_table (&cur->supl_table);
  file_close (cur->executable_file);
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
  // Close and free all the file pointers left in the process's fd_list
  for (struct list_elem *elem_i = list_begin (&cur->fd_list); elem_i != list_end (&cur->fd_list);) {
    struct file_descriptor *fd_i = list_entry (elem_i, struct file_descriptor, fd_elem);
    file_close (fd_i->file);
    struct list_elem *elem_next = list_next (elem_i);
    list_remove (elem_i);
    free (fd_i);
    elem_i = elem_next;
  }
  lock_release (&filesys_lock);

  // Free all the struct child_process in the child_proc_list of the current process whose thread has finished
  if (cur->child_proc_entry->exit_status < 0) {
    cur->child_proc_entry->exit_status = -1;
  }
  for (struct list_elem *elem_i = list_begin (&cur->child_proc_list); 
    elem_i != list_end (&cur->child_proc_list);) {
    struct child_process *child_t = list_entry (elem_i, struct child_process, child_elem);
    if (child_t->is_finished) {
      struct list_elem *elem_next = list_next (elem_i);
      list_remove (elem_i);
      free (child_t);
      elem_i = elem_next;
    }
  }
  
#ifdef VM
#endif  


  printf ("%s: exit(%d)\n", cur->name, cur->child_proc_entry->exit_status);
  // The child process has finished, sema up the parent process waiting for it.
  cur->child_proc_entry->is_finished = true;
  sema_up (&cur->child_proc_entry->parent_wait);
}

/* Sets up the CPU for running user code in the current
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

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
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

/* Program header.  See [ELF1] 2-2 to 2-4.
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

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
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
  lock_acquire (&filesys_lock);
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) {
    printf("Fail to create pagedir\n");
    goto done;
  }
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  
  file_deny_write (file);
  t->executable_file = file;

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


  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  lock_release (&filesys_lock);
  return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
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

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocatiotn error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  struct thread *cur = thread_current ();
  off_t file_pos = ofs;
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
#ifdef VM
      if (page_zero_bytes == PGSIZE) {
        if (!supl_insert_zero_page(&cur->supl_table, upage)) return false;
      } else {
        // Store the relevant information in supl page table for lasy load of executable file
        if (!supl_insert_page_from_filesys (&cur->supl_table, upage, page_read_bytes, file_pos, file, writable)) {
        printf("Insert page error\n");
        return false;
        }
      }
#else
      /* Check if virtual page already allocated */
      struct thread *t = thread_current ();
      uint8_t *kpage = pagedir_get_page (t->pagedir, upage);
      
      if (kpage == NULL){
        
        /* Get a new page of memory. */
        kpage = palloc_get_page (PAL_USER);
        if (kpage == NULL) {
          return false;
        }
        
        /* Add the page to the process's address space. */
        if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }     
        
      } else {
        
        /* Check if writable flag for the page should be updated */
        if (writable && !pagedir_is_writable (t->pagedir, upage)){
          pagedir_set_writable (t->pagedir, upage, writable); 
        }
        
      }

      /* Load data into the page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes){
        return false; 
      }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);
#endif

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      file_pos += page_read_bytes;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *frame;
  bool success = false;

  frame = frame_allocate_page ((PHYS_BASE - PGSIZE), (PAL_USER | PAL_ZERO));
  if (frame != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, frame, true);
      if (success)
        *esp = PHYS_BASE;
      else
        free_frame_addr (frame);  
    }
  supl_insert_page_on_frame (&thread_current()->supl_table, ((uint8_t *) PHYS_BASE) - PGSIZE, frame);
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address FRAME to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   FRAME should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *frame, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, frame, writable));
}
