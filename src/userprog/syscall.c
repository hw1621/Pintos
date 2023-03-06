#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "lib/stdio.h"
#include "vm/page.h"
#include "vm/frame.h"

/* initialize a list of 13 functions to store syscall handler functions */
static void (*syscall_functions[NOF]) (uint32_t *, uint32_t *);

void halt (uint32_t *esp, uint32_t *eax);
void exit (uint32_t *esp, uint32_t *eax);
void exec (uint32_t *esp, uint32_t *eax);
void wait (uint32_t *esp, uint32_t *eax);
void create (uint32_t *esp, uint32_t *eax);
void remove (uint32_t *esp, uint32_t *eax);
void open (uint32_t *esp, uint32_t *eax);
void filesize (uint32_t *esp, uint32_t *eax);
void read (uint32_t *esp, uint32_t *eax);
void write (uint32_t *esp, uint32_t *eax);
void seek (uint32_t *esp, uint32_t *eax);
void tell (uint32_t *esp, uint32_t *eax);
void close (uint32_t *esp, uint32_t *eax);
void mmap (uint32_t *esp, uint32_t *eax);
void munmap (uint32_t *esp, uint32_t *eax);


struct file *find_file (int, struct list *);
struct map_descriptor *find_mapping_descriptor (mapid_t, struct list *);
void is_valid_ptr (const void *ptr);
void is_valid_ptr_size (const void *ptr, unsigned);
void syscall_exit (int status);
static void syscall_handler (struct intr_frame *);

/* verify whether the user pointer is mapped, exit with status -1 if not*/
void
is_valid_ptr (const void *ptr)
{ 
  struct thread *cur = thread_current();
  if (!(ptr != NULL && is_user_vaddr (ptr) && (pagedir_get_page (cur->pagedir,  ptr) || supl_lookup_page (&cur->supl_table, ptr))))
  {
    syscall_exit (-1);
  }
}

void
is_valid_ptr_size (const void *ptr, unsigned size)
{
  is_valid_ptr (ptr);
  unsigned checked_size = 0;
  while (((unsigned) ptr + checked_size + size) / PGSIZE > ((unsigned) ptr + checked_size) / PGSIZE) {
      is_valid_ptr (ptr + size);
      checked_size += PGSIZE;
      size -= PGSIZE;
  }
  if (!is_user_vaddr (ptr + checked_size + size)) {
    syscall_exit (-1);
  }
}

/* Find a struct file_destriptor with matched int fd from a list, return NULL if not found */
struct file *find_file (int fd_id, struct list* fd_list) {
  lock_acquire (&filesys_lock);
  for (struct list_elem *elem_i = list_begin (fd_list); 
       elem_i != list_end (fd_list); elem_i = list_next (elem_i)) {
    struct file_descriptor *fd_i = list_entry (elem_i, struct file_descriptor, fd_elem);
    if (fd_i->fd_id == fd_id) {
      lock_release (&filesys_lock);
      return fd_i->file;
    }
  }
  lock_release (&filesys_lock);
  return NULL;
}

struct map_descriptor *
find_mapping_descriptor (mapid_t mapping, struct list *mapping_list) {
  lock_acquire (&filesys_lock);
  for (struct list_elem *e = list_begin (mapping_list); e != list_end (mapping_list); e = list_next (e)) {
    struct map_descriptor *map_d = list_entry (e, struct map_descriptor, elem);
    if (map_d->id == mapping) {
      lock_release (&filesys_lock);
      return map_d;
    }
  }
  lock_release (&filesys_lock);
  return NULL;
}

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

/* assigning handler functions to syscall_functions according to their system call number */
  syscall_functions[SYS_HALT] = &halt;
  syscall_functions[SYS_EXIT] = &exit;
  syscall_functions[SYS_EXEC] = &exec;
  syscall_functions[SYS_WAIT] = &wait;
  syscall_functions[SYS_CREATE] = &create;
  syscall_functions[SYS_REMOVE] = &remove;
  syscall_functions[SYS_OPEN] = &open;
  syscall_functions[SYS_FILESIZE] = &filesize;
  syscall_functions[SYS_READ] = &read;
  syscall_functions[SYS_WRITE] = &write;
  syscall_functions[SYS_SEEK] = &seek;
  syscall_functions[SYS_TELL] = &tell;
  syscall_functions[SYS_CLOSE] = &close;
  syscall_functions[SYS_MMAP] = &mmap;
  syscall_functions[SYS_MUNMAP] = &munmap;
}

static void
syscall_handler (struct intr_frame *f)
{
  uint32_t *esp = f->esp;
  uint32_t *eax = &f->eax;

  is_valid_ptr(esp);
  int syscall_number = *(esp);
  if (syscall_number > SYS_MUNMAP || syscall_number < SYS_HALT) {
    syscall_exit(-1);
  }

  /* call handler function in list syscall_functions with corresponding syscall_number */
  syscall_functions[syscall_number] (esp, eax);
}

/* using argument passed in as status, no need to access frame */
void 
syscall_exit (int status) {
  struct thread *cur = thread_current ();
  cur->child_proc_entry->exit_status = status;
  thread_exit ();
}

void 
halt (uint32_t *esp UNUSED, uint32_t *eax UNUSED) {
  shutdown_power_off ();
}

void 
exit (uint32_t *esp, uint32_t *eax UNUSED) {
  is_valid_ptr (esp + 1);
  syscall_exit (*(esp + 1));
}

void
exec (uint32_t *esp, uint32_t *eax) {
  is_valid_ptr (esp + 1);
  const char *cmd_line = (char *) *(esp + 1);
  is_valid_ptr (cmd_line);

  *eax = process_execute (cmd_line);
}

void
wait (uint32_t *esp, uint32_t *eax) {
  is_valid_ptr (esp + 1);
  tid_t tid = *(esp + 1);

  *eax = process_wait (tid);
}

void
create (uint32_t *esp, uint32_t *eax) {
  is_valid_ptr (esp + 1);
  is_valid_ptr (esp + 2);
  const char *file = (char *) *(esp + 1);
  is_valid_ptr (file);
  unsigned initial_size = *(esp + 2);

  lock_acquire (&filesys_lock);
  *eax = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
}

void
remove (uint32_t *esp, uint32_t *eax) {
  is_valid_ptr (esp + 1);
  const char *file = (char *) *(esp + 1);
  is_valid_ptr (file);

  lock_acquire (&filesys_lock);
  *eax = filesys_remove (file);
  lock_release (&filesys_lock);
}

void
open (uint32_t *esp, uint32_t *eax) {
  is_valid_ptr (esp + 1);
  const char *file_name = (char *) *(esp + 1);
  is_valid_ptr (file_name);

  struct file *opened_file;
  int status = -1;
  lock_acquire (&filesys_lock);
  opened_file = filesys_open (file_name);
  if (opened_file != NULL) {
    struct thread *cur = thread_current ();
    struct file_descriptor *new_fd = malloc (sizeof(struct file_descriptor));
    if (new_fd == NULL) {
      *eax = -1;
    }
    new_fd->file = opened_file;
    int new_fd_id = 2;
    for (struct list_elem *elem_i = list_begin (&cur->fd_list);
         elem_i != list_end (&cur->fd_list); elem_i = list_next (elem_i)) {
      struct file_descriptor *fd_i = list_entry (elem_i, struct file_descriptor, fd_elem);
      if (fd_i->fd_id >= new_fd_id) {
        new_fd_id = fd_i->fd_id + 1;
      }
    }
    new_fd->fd_id = new_fd_id;
    status = new_fd_id;
    list_push_back (&cur->fd_list, &new_fd->fd_elem);
  }
  lock_release (&filesys_lock);

  *eax = status;
}

void
filesize (uint32_t *esp, uint32_t *eax) {
  is_valid_ptr (esp + 1);
  int fd = *(esp + 1);

  struct file *f = find_file (fd, &thread_current ()->fd_list);
  if (f == NULL) {
    syscall_exit (-1);
  }
  lock_acquire (&filesys_lock);
  *eax = file_length (f);
  lock_release (&filesys_lock);
}

void
read (uint32_t *esp, uint32_t *eax) {
  is_valid_ptr (esp + 1);
  is_valid_ptr (esp + 3);
  int fd = *(esp + 1);
  unsigned size_ = *(esp + 3);
  is_valid_ptr_size ((void *) *(esp + 2), size_);
  
  uint8_t *buffer = (uint8_t *) *(esp + 2);
  off_t size = size_;
  int bytes_read = 0;
  if (fd == STDIN_FILENO) {
    for (bytes_read = 0; bytes_read < size; bytes_read++) {
      if (buffer >= (uint8_t *) PHYS_BASE) {
        buffer[bytes_read] = input_getc ();
      }
    }
    *eax = bytes_read;
  } else {
    struct file* file = find_file (fd, &thread_current ()->fd_list);
    if (file != NULL) {
      lock_acquire (&filesys_lock);
      bytes_read = file_read (file, buffer, size);
      lock_release (&filesys_lock);
    } else {
      *eax = -1;
    }
    *eax = bytes_read;  
  } 
}

void
write (uint32_t *esp, uint32_t *eax) {
  is_valid_ptr (esp + 1);
  is_valid_ptr (esp + 3);
  int fd = *(esp + 1);
  unsigned size = *(esp + 3);
  
  if (fd == STDIN_FILENO) {
    syscall_exit (-1);
  } else {
    is_valid_ptr_size ((void *) *(esp + 2), size);
  }

  void *buffer = (void*) *(esp + 2);
  int bytes_written = 0;
  if (fd == STDOUT_FILENO) {
    putbuf (buffer, size);
    bytes_written = size;
  } else {
    struct file *file_found = find_file (fd, &thread_current ()->fd_list);
    if (file_found == NULL) {
      syscall_exit (-1);
    }
    lock_acquire (&filesys_lock);
    bytes_written = file_write (file_found, buffer, size);
    lock_release (&filesys_lock);
  }

  *eax = bytes_written;
} 

void
seek (uint32_t *esp, uint32_t *eax UNUSED) {
  is_valid_ptr (esp + 1);
  is_valid_ptr (esp + 2);
  int fd = *(esp + 1);
  unsigned position = *(esp + 2);

  struct file *file_found = find_file (fd, &thread_current ()->fd_list);
  if (file_found == NULL) {
    syscall_exit (-1);
  }
  lock_acquire (&filesys_lock);
  file_seek (file_found, position);
  lock_release (&filesys_lock);
}

void
tell (uint32_t *esp, uint32_t *eax) {
  is_valid_ptr (esp + 1);
  int fd = *(esp + 1);

  struct file *file_found = find_file (fd, &thread_current ()->fd_list);
  if (file_found == NULL) {
    syscall_exit (-1);
  }
  lock_acquire (&filesys_lock);
  unsigned position = file_tell (file_found);
  lock_release (&filesys_lock);

  *eax = position;
}

void
close (uint32_t *esp, uint32_t *eax UNUSED) {
  is_valid_ptr (esp + 1);
  int fd = *(esp + 1);
  
  struct list *fd_list = &thread_current ()->fd_list;
  lock_acquire (&filesys_lock);
  for (struct list_elem *e = list_begin (fd_list); e != list_end (fd_list);
                                                   e = list_next (e)) {
    struct file_descriptor *fd_i = list_entry(e, struct file_descriptor, fd_elem);
    if (fd_i->fd_id == fd) {
      list_remove (&fd_i->fd_elem);
      file_close (fd_i->file);
      free (fd_i);
      break;
    }
  }
  lock_release (&filesys_lock);
}

void
mmap (uint32_t *esp, uint32_t *eax) {
  is_valid_ptr (esp + 1);
  is_valid_ptr (esp + 2);
  int fd = *(esp + 1);
  void *addr = *(esp + 2);

  if (addr == NULL || addr == 0x0 || pg_ofs (addr) != 0) {
    *eax = -1;
    return;
  }
  
  if (fd == 0 || fd == 1) {
    *eax = -1;
    return;
  }

  struct thread* cur = thread_current ();
  struct file *map_file;
  // filesys_lock is acquired inside find_file function and release after finishing
  struct file *open_file = find_file (fd, &cur->fd_list);
  if (open_file == NULL) {
    *eax = -1;
    return;
  }
  lock_acquire (&filesys_lock);
  map_file = file_reopen (open_file);
  if (map_file == NULL) {
    lock_release (&filesys_lock);
    *eax = -1;
    return;
  }  
  uint32_t length = file_length (map_file);
  if (length == 0) {
    lock_release (&filesys_lock);
    *eax = -1;
    return;
  }

  // check whether the space left for mapping page is enough 
  uint32_t ofs = 0;
  while (ofs < length) {
    if (supl_lookup_page (&cur->supl_table, addr + ofs) != NULL) {  
      lock_release (&filesys_lock);
      *eax = -1;
      return;
    } 
    ofs += PGSIZE;
  }

  // Do the mapping, store the relevent information of file into supl page table 
  // by using the function supl_insert_page_from_filesys()
  for (ofs = 0; ofs < length; ofs += PGSIZE) {
    void *uaddr = addr + ofs;
    // If the newly allocated page plus current position ofs exceeds the length of file, then only read the bytes 
    // from ofs to the end of the file. The rest bytes are zeroes.
    // Otherwise, it hasn't reached the end of file, so read PGSIZE bytes from ofs.
    off_t read_page_size = ofs + PGSIZE > length ? (length - ofs) : PGSIZE;
    supl_insert_page_from_filesys (&cur->supl_table, uaddr, read_page_size, ofs, map_file, true);
  }
  
  mapid_t map_id = 1;
  struct map_descriptor *map_d = malloc(sizeof(struct map_descriptor));
  if (!list_empty (&cur->mapped_file_fd_list)) {
    map_id = list_entry (list_back (&cur->mapped_file_fd_list), struct map_descriptor, elem)->id + 1;
  }
  map_d->id = map_id;
  map_d->size = length;
  map_d->addr = addr;
  map_d->file = map_file;
  list_push_back (&cur->mapped_file_fd_list, &map_d->elem);

  lock_release (&filesys_lock);
  *eax = map_id;
}

void syscall_mumap (mapid_t mapping) {
  struct thread *cur = thread_current ();
  struct map_descriptor *map_d = find_mapping_descriptor (mapping, &cur->mapped_file_fd_list);
  if (map_d == NULL) syscall_exit (-1);

  lock_acquire (&filesys_lock);
  void *start_addr = map_d->addr;
  struct file *mapped_file = map_d->file; 
  size_t file_length = map_d->size;

  size_t ofs;
  for (ofs = 0; ofs < file_length; ofs += PGSIZE) {
    void* uaddr = ofs + start_addr;
    off_t read_page_size = ofs + PGSIZE < file_length ? PGSIZE : file_length - ofs;
    struct supl_table_entry *supl_entry = supl_lookup_page (&cur->supl_table, uaddr);
    if (supl_entry == NULL) {
      lock_release (&filesys_lock);
      syscall_exit (-1);
    }
    bool is_dirty;
    is_dirty = pagedir_is_dirty (cur->pagedir, supl_entry->upage);
    if (supl_entry->status == ON_FRAME && is_dirty) {
      file_write_at (mapped_file, supl_entry->upage, read_page_size, ofs);
    }
  }
  list_remove (&map_d->elem);
  file_close (map_d->file);
  free (map_d);
  lock_release (&filesys_lock);
}

void
munmap (uint32_t *esp, uint32_t *eax UNUSED) {
  is_valid_ptr (esp + 1);
  mapid_t mapping = *(esp + 1);
  syscall_mumap (mapping);

}




