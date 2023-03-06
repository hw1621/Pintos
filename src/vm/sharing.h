#ifndef VM_SHARING_H
#define VM_SHARING_H

#include "lib/kernel/list.h"
#include "filesys/off_t.h"

struct sharing_file_entry {
  struct file *file;         /* The file that is shared by multiple processes */
  off_t file_pos;            /* Offset of the file */
  void *frame;               /* The frame allocated to store the data of file */
  int share_num;             /* The number of times the file is referenced */

  struct list_elem elem;     /* Hash elem for hash table */
};

void sharing_init (void);
void insert_sharing_frame (struct file *, off_t, void *);
void close_sharing_frame (void *);
struct sharing_file_entry *sharing_file_lookup (struct file *, off_t);

#endif