#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdio.h>
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "lib/kernel/hash.h"
#include "filesys/filesys.h"

/* Page status that indicates whether the page in all-zero, on swap slot, on frame(memory) or in file system */
enum page_status {
  ALL_ZERO,
  SWAP,
  ON_FRAME,
  IN_FILESYS
};

/* store the information needed for file in file system to be loaded to frame */
struct filsys_info {
  struct file* file;
  bool writable;
  uint32_t read_bytes;
  uint32_t zero_bytes;
  off_t file_pos;
};

/* store the information of file on frame */
struct frame_info {
  void* addr;                    /* the address of this page on frame */
  bool shared;                   /* whether this page is shared between multiple pages or not */
};

/* store the information of file in swap block */
struct swap_info {
  size_t slot;                   /* the positon of page in swap block */
};

/* we use a union to store different sets of information for pages in different statuses */
union supl_info {
  struct filsys_info filesys;
  struct frame_info frame;
  struct swap_info swap;
};

struct supl_table_entry
 {
    void *upage;
    struct hash_elem elem;
    enum page_status status;

    union supl_info info;
 };

void supl_table_init (struct hash *);
bool supl_insert_page_on_frame (struct hash*, void *, void *);
bool supl_insert_zero_page (struct hash *, void *);
void supl_set_page_swap (struct hash *, void *, size_t);
bool supl_insert_page_from_filesys (struct hash*, void*, uint32_t, off_t, struct file*, bool);
struct supl_table_entry* supl_lookup_page (struct hash *, const void *);
void free_supl_page_table (struct hash *);

#endif