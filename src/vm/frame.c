#include "vm/frame.h"

#include <stdio.h>
#include <bitmap.h>
#include "devices/swap.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "vm/page.h"

/* Macros defined for stack growth */
#define STACK_MAX 1 << 23               /* Maximum bytes of user stack */
#define STACK_MAX_CHECK(STACK_ADDR) if ((uint8_t *) PHYS_BASE - STACK_ADDR >= STACK_MAX) syscall_exit(-1);

static struct hash frame_table;             /* Frame_table implemented as hash table */
static struct lock frame_table_lock;        /* Lock for frame table system, used when insert and delete new element */
static struct list evict_list;              /* The list of frame_table_entry used for eviction */

struct frame_table_entry *frame_hash_lookup (struct hash *, void *);
unsigned frame_hash_func (const struct hash_elem *, void *);
bool frame_less_func (const struct hash_elem *, const struct hash_elem *, void *);
bool frame_table_evict (void);
struct map_descriptor * find_mmp_frame (void *, struct list *);
struct frame_table_entry *find_evict_fifo (void);
struct frame_table_entry *find_evict_ref (void);

void
frame_init () {
  hash_init (&frame_table, frame_hash_func, frame_less_func, NULL);
  list_init (&evict_list);
  lock_init (&frame_table_lock);
}

/* Get a page in main memory to store upage, insert the corresponding information in frame table*/
void *
frame_allocate_page (void * upage, enum palloc_flags flag){

  lock_acquire (&frame_table_lock);

	void * frame = palloc_get_page (flag);

	/* There is no more free memory, we need to free some */
	if (frame == NULL) {
		if (!frame_table_evict()) {
      syscall_exit (-1);
    }
    frame = palloc_get_page (flag);
	}
   
	/* We succesfully allocated space for the page */
	if (frame != NULL) {
		struct frame_table_entry *frame_entry = malloc (sizeof (struct frame_table_entry));
		frame_entry -> frame = frame;
		frame_entry -> upage = upage;
		frame_entry -> t     = thread_current ();
    frame_entry -> shared= false;
    frame_entry -> reference = false;

		hash_insert (&frame_table, &frame_entry -> hash_elem);
    list_push_back (&evict_list, &frame_entry->list_elem);
	}
  lock_release (&frame_table_lock);
	return frame;
}

/* Free the entry and remove the entry from frame table */
void 
free_frame_entry (struct frame_table_entry *entry) {
	hash_delete (&frame_table, &entry->hash_elem);
	free (entry);
}

/* Free the given frame and delete the entry in frame table */
void
free_frame_addr (void *frame) {
  // Lock the block only when hasn't got the locked already
  bool out_locked = lock_held_by_current_thread (&frame_table_lock);
  if (!out_locked)
    lock_acquire (&frame_table_lock);
	struct frame_table_entry *entry;
  // Find the corresponding entry from table and delete/free everything
	entry = frame_hash_lookup (&frame_table, frame);
  ASSERT (entry != NULL);
	palloc_free_page (frame);
	hash_delete (&frame_table, &entry->hash_elem);
  if (entry->list_elem.prev) {
    list_remove (&entry->list_elem);
  }
	free (entry);
  if (!out_locked)
    lock_release (&frame_table_lock);
}

unsigned 
frame_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
  struct frame_table_entry *entry = hash_entry(e, struct frame_table_entry, hash_elem);
  return hash_bytes (&entry->frame, sizeof entry->frame );
}

bool 
frame_less_func (const struct hash_elem *e1, const struct hash_elem *e2, void *aux UNUSED)
{
  struct frame_table_entry *a_entry = hash_entry (e1, struct frame_table_entry, hash_elem);
  struct frame_table_entry *b_entry = hash_entry (e2, struct frame_table_entry, hash_elem);
  return a_entry->frame < b_entry->frame;
}

/* Set a frame entry to be shared */
void
frame_set_shared (void *frame) {
  struct frame_table_entry *entry = frame_hash_lookup (&frame_table, frame);
  ASSERT (entry != NULL);
  entry->shared = true;
}

/* A helper function to find an entry in table by frame */
struct frame_table_entry *
frame_hash_lookup (struct hash *hash, void *frame)
{
	struct frame_table_entry portrait;
	struct hash_elem *e;

	portrait.frame = frame;
	e = hash_find (hash, &portrait.hash_elem);
	return e != NULL ? hash_entry (e, struct frame_table_entry, hash_elem) : NULL;
}

/* Stack growth function */
void
stack_growth (void *fault_addr, void *esp) {
  struct thread *cur = thread_current();
  uint8_t *stack_head = PHYS_BASE - PGSIZE;
  // Determine til which depth of the stack has been assigned
  while (pagedir_get_page(cur->pagedir, stack_head) || supl_lookup_page (&cur->supl_table, stack_head)) {
    stack_head -= PGSIZE;
    STACK_MAX_CHECK (stack_head);
  } 
  // Then grow the rest towards esp
  void *frame;
  while ((uint32_t*) stack_head >= (uint32_t*) pg_round_down (esp)) {
    frame = frame_allocate_page (stack_head, (PAL_USER | PAL_ZERO));
    if (frame != NULL) 
      {
        bool success = install_page (stack_head, frame, true);
        if (!success) {
          free_frame_addr (frame);
          PANIC ("Stack growth unable: error while installing page");
        }
      }
    supl_insert_page_on_frame (&cur->supl_table, stack_head, frame);
    stack_head -= PGSIZE;
    STACK_MAX_CHECK (stack_head);
  }
  // Grow towards the fault address if needed
  while ((uint32_t *) stack_head >= (uint32_t *) fault_addr) {
    frame = frame_allocate_page (stack_head, (PAL_USER | PAL_ZERO));
    if (frame != NULL) 
      {
        bool success = install_page (stack_head, frame, true);
        if (!success) {
          free_frame_addr (frame);
          PANIC ("Stack growth unable: error while installing page");
        }
      }
    supl_insert_page_on_frame (&cur->supl_table, stack_head, frame);
    stack_head -= PGSIZE;
    STACK_MAX_CHECK (stack_head);
  }
  // Finish handling stack growth
}

/* Evict a single frame from the table, return success or not */
bool
frame_table_evict () {
  struct frame_table_entry *entry = find_evict_ref ();
  if (entry == NULL) {
    PANIC ("Fail to find frame to evict!");
  }
  // Determine if the frame is an mmp frame
  struct map_descriptor *mmp_entry = find_mmp_frame (entry->upage, &entry->t->mapped_file_fd_list);
  if (mmp_entry) {
    // If so, write it back to the file and set the entry to be read back from file when referenced again
    struct file *mmp_file = mmp_entry->file;
    off_t ofs = (uint8_t*)entry->upage - (uint8_t*)mmp_entry->addr;
    bool out_locked = lock_held_by_current_thread (&filesys_lock);
    if (!out_locked)
      lock_acquire (&filesys_lock);
    file_write_at (mmp_file, entry->frame, PGSIZE, ofs);
    if (!out_locked)
      lock_release (&filesys_lock);
    pagedir_clear_page (entry->t->pagedir, entry->upage);
    supl_insert_page_from_filesys (&entry->t->supl_table, entry->upage, PGSIZE, ofs, mmp_file, true);
  } else {
    // If not mmp, using the given function to swap it to a swap slot
    size_t slot = swap_out (entry->frame);
    if (slot == BITMAP_ERROR) {
      return false;
    }
    pagedir_clear_page (entry->t->pagedir, entry->upage);
    supl_set_page_swap (&entry->t->supl_table, entry->upage, slot);
  }
  free_frame_addr (entry->frame);
  return true;
}

/* Determine if upage is a memory mapped page in the mapping list, return the pointer to the entry if yes, return null if no */
struct map_descriptor *
find_mmp_frame (void *upage, struct list *mapping_list) {
  for (struct list_elem *e = list_begin (mapping_list); e != list_end (mapping_list); e = list_next (e)) {
    struct map_descriptor *map_d = list_entry (e, struct map_descriptor, elem);
    // If the given page is in between the starting address and the end address, then it is a mmp page
    if (upage >= map_d->addr && upage <= (uint8_t*)map_d->addr + map_d->size) {
      return map_d;
    }
  }
  return NULL;
}

/* Using First-In-First-Out to find a frame to be evicted */
struct frame_table_entry *find_evict_fifo () {
  // Since all allocated frame are pushed back to the list, using pop front will find the oldest frame
  struct frame_table_entry *entry = list_entry (list_pop_front (&evict_list), struct frame_table_entry, list_elem);
  entry->list_elem.prev = NULL;
  // Skip shared frame, for only segments from executable are shared
  while (entry->shared) {
    entry = list_entry (list_pop_front (&evict_list), struct frame_table_entry, list_elem);
    entry->list_elem.prev = NULL;
  }
  return entry;
}

/* Using a modified reference bit method to find a frame to be evicted */
struct frame_table_entry *find_evict_ref () {
  // Traverse the list from beginning
  for (struct list_elem *e = list_begin (&evict_list); e != list_end (&evict_list); e = list_next (e)) {
    struct frame_table_entry *entry = list_entry (e, struct frame_table_entry, list_elem);
    if (!entry->shared) {
      // If the frame has either be accessed or modified, set the reference bit to 1 regardlessly
      entry->reference = entry->reference || pagedir_is_accessed (entry->t->pagedir, entry->upage) || pagedir_is_dirty (entry->t->pagedir, entry->upage);
      // Return the frame if its reference bit is 1, set the bit to 1 if it is 0 originally
      if (entry->reference) {
        list_remove (e);
        entry->list_elem.prev = NULL;
        return entry;
      } else {
        entry->reference = true;
      }
    }
  }
  // If failed to find a frame during this run, then do it again
  return find_evict_ref ();
}