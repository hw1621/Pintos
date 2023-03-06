#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"
#include "threads/palloc.h"


struct frame_table_entry
  {
    void *frame;                     /* Kernel page, mapped to physical address */
    void *upage;                     /* User (Virtual Memory) Address, pointer to page */
    bool shared;                     /* True if the frame is shared between multiple processer, otherwise not*/
    struct thread *t;                /* Owner thread of the upage. */
    struct hash_elem hash_elem;      /* Hash elem for hash table */
    struct list_elem list_elem;      /* list elem for evict list */
    bool reference;                  /* Whether the entry has been referenced recently */
  };

void frame_init (void);
void* frame_allocate_page (void *, enum palloc_flags);
void free_frame_entry (struct frame_table_entry *);
void free_frame_addr (void *);
void stack_growth (void *, void *);
void frame_set_shared (void *);
#endif