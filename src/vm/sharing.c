#include "vm/sharing.h"

#include <stdio.h>
#include "threads/synch.h"
#include "filesys/file.h"
#include "vm/page.h"
#include "vm/frame.h"


static struct list sharing_table;
static struct lock sharing_lock;

/* Initialize sharing table and lock */
void
sharing_init () {
  list_init (&sharing_table);
  lock_init (&sharing_lock);
}

/* Add a new shared frame to the table */
void
insert_sharing_frame (struct file *file, off_t file_pos, void *frame) {
  lock_acquire (&sharing_lock);
  struct sharing_file_entry *entry = malloc (sizeof(struct sharing_file_entry));
  entry->file = file;
  entry->file_pos = file_pos;
  entry->share_num = 1;
  entry->frame = frame;
  list_push_back (&sharing_table, &entry->elem);
  lock_release (&sharing_lock);
}

/* Try to free a frame and delete the entry if no one else is using it */
void
close_sharing_frame (void *frame) {
  lock_acquire (&sharing_lock);
  struct sharing_file_entry *entry = NULL;
  struct list_elem *e;
  for ( e = list_begin (&sharing_table); e != list_end (&sharing_table); e = list_next (e)) {
    entry = list_entry (e, struct sharing_file_entry, elem);
    if (entry->frame == frame) {
      //printf ("Shared frame %p share num %d->%d\n", frame, entry->share_num, entry->share_num - 1);
      entry->share_num -= 1;
      if (entry->share_num <= 0) {
        list_remove (&entry->elem);
        free_frame_addr (frame);
        free (entry);
      }
      lock_release (&sharing_lock);
      return;
    }
  }
  lock_release (&sharing_lock);
  PANIC ("Fail to find sharing frame %p", frame);
  
}

/* Find the table entry with the same file and offset */
struct sharing_file_entry *
sharing_file_lookup (struct file *file, off_t file_pos) {
  bool locked_out = lock_held_by_current_thread (&sharing_lock);
  if (!locked_out) {
    lock_acquire (&sharing_lock);
  }
  struct sharing_file_entry *entry = NULL;
  struct list_elem *e;
  for ( e = list_begin (&sharing_table); e != list_end (&sharing_table); e = list_next (e)) {
    entry = list_entry (e, struct sharing_file_entry, elem);
    if (file_compare (entry->file, file) && entry->file_pos == file_pos) {
      if (!locked_out) {
        lock_release (&sharing_lock);
      }
      return entry;
    }
  }
  if (!locked_out) {
    lock_release (&sharing_lock);
  }
  return NULL;
}
