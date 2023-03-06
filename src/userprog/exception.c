#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/sharing.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "devices/swap.h"

#define IN_PAGE_TABLE(ADDR) (pagedir_get_page(cur->pagedir, ADDR) || supl_lookup_page(&cur->supl_table, ADDR))


/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill, "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill, "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill, "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  
         Shouldn't happen.  Panic the kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      PANIC ("Kernel bug - this shouldn't be possible!");
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to task 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
    accessed to cause the fault.  It may point to code or to
    data.  It is not necessarily the address of the instruction
    that caused the fault (that's f->eip).
    See [IA32-v2a] "MOV--Move to/from Control Registers" and
    [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
    (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
    be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;


#ifdef VM

  struct thread *cur = thread_current ();
  // Find the page where the fault_addr is located in
  void* fault_page = (void*) pg_round_down (fault_addr); 

  // Check if the fault addr is null; if the fault addr lies within kernel virtual memory;
  // if the page is trying to write to read only page
  if ((fault_addr == NULL) || !is_user_vaddr (fault_addr) || (write && !not_present))
  {
    syscall_exit (-1);
  }

  // find the entry in the supl_table of current thread
  struct supl_table_entry *entry = supl_lookup_page (&cur->supl_table, fault_page);
  if (entry == NULL) {
    // Check if page fault requires stack growth
    void *esp = f->esp == NULL ? cur->stack : f->esp;
    if (esp != NULL && (!IN_PAGE_TABLE(esp) || (fault_addr < esp && esp - fault_addr <= 32))) {
      stack_growth (fault_page, esp);
      // Finish handling stack growth
      return;
    } else {
      syscall_exit (-1);
    }
  }

  // Obtain a frame to store the page
  void *frame = frame_allocate_page (fault_page, PAL_USER);

  // Fetch the data into the frame
  void *upage = entry->upage;
  bool writable = true;
  switch (entry->status)
  {
    case ALL_ZERO:
    {
      // check if successfully install page to pagedir
      if (!install_page (upage, frame, writable)) 
      {
        free_frame_addr (frame);
        printf ("Install all-zero page failed!\n");
        syscall_exit (-1);
      }

      // fetch all zero page into frame
      memset (frame, 0, PGSIZE);
      entry->info.frame.shared = false;
      break;
    }

    case SWAP:
    {
      // check if successfully install page to pagedir
      if (!install_page (upage, frame, writable)) 
      {
        free_frame_addr (frame);
        syscall_exit (-1);
      }

      // swap in page from dist to frame
      size_t slot = entry->info.swap.slot;
      swap_in (frame, slot);
      entry->info.frame.shared = false;
      break;
    }
  
    case IN_FILESYS:
    {
      bool writable = entry->info.filesys.writable;
      struct file *file = entry->info.filesys.file;
      uint32_t read_bytes = entry->info.filesys.read_bytes;
      uint32_t zero_bytes = entry->info.filesys.zero_bytes;
      off_t file_pos = entry->info.filesys.file_pos;
      
      // Check whether there is a share entry contains the same file 
      // already stored in the sharing list. If so, increment the share num
      // and update the frame_info shared status of the current supl page table entry
      struct sharing_file_entry *share_entry;
      share_entry = sharing_file_lookup (file, file_pos);
      if (share_entry && !writable) {
        free_frame_addr (frame);
        if (install_page (upage, share_entry->frame, false)) 
        {
          frame = share_entry->frame;
          entry->info.frame.shared = true;
          share_entry->share_num += 1;
          break;
        } else {
          printf ("Install shared page failed!\n");
          syscall_exit (-1);
        }
      }
     
      /* Add the page to the process's page table. */
      if (!install_page (upage, frame, writable)) 
      {
        free_frame_addr (frame);
        printf ("Install filesys page failed!\n");
        syscall_exit (-1);
      }
        
      /* Check if writable flag for the page should be updated */
      if (writable && !pagedir_is_writable (cur->pagedir, upage)) {
        pagedir_set_writable (cur->pagedir, upage, writable); 
      }

      /* Load data into the page. */
      if (file_read_at (file, frame, read_bytes, file_pos) != (int) read_bytes) {
        printf ("File loading error\n");
        syscall_exit (-1);
      }
      memset (frame + read_bytes, 0, zero_bytes);

      /* Check whether the frame is read-only, if so, the frame that stores data from the file will be marked as shared.
      Insert the shared file into sharing list */
      if (!writable) {
        entry->info.frame.shared = true;
        insert_sharing_frame (file, file_pos, frame);
        frame_set_shared (frame);
      } else {     
        entry->info.frame.shared = false;
      }
      break;
    }

    default:
      PANIC ("%d Faulting page %p has unexpected status %d with frame %p", cur->tid, fault_page, entry->status, entry->info.frame.addr);
      break;
  }
  entry->info.frame.addr = frame;
  entry->status = ON_FRAME;

#else
  printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");
  kill (f);

#endif
}

