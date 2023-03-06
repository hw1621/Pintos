#include "vm/page.h"
#include "vm/frame.h"
#include "threads/vaddr.h"
#include "vm/sharing.h"
#include "vm/page.h"
#include "devices/swap.h"

unsigned spage_hash_func (const struct hash_elem *, void *);
bool spage_less_func (const struct hash_elem *, const struct hash_elem *, void *);
void hash_destroy_func (struct hash_elem *, void *);
void hash_detach_func (struct hash_elem *, void *);

void 
supl_table_init (struct hash *table) {
  hash_init (table, spage_hash_func, spage_less_func, NULL);
}

/* Insert a page into supl page table that is currently on the frame */
bool
supl_insert_page_on_frame (struct hash* table, void* upage, void* frame) {
  struct supl_table_entry *entry = malloc (sizeof(struct supl_table_entry));
  entry->info.frame.addr = frame;
  entry->info.frame.shared = false;
  entry->upage = upage;
  entry->status = ON_FRAME;
  
  struct hash_elem *e;
  e = hash_insert (table, &entry->elem);
  return e == NULL;
}

/* Insert a page into supl page table that will load from file */
bool
supl_insert_page_from_filesys (struct hash *table, void *upage, uint32_t read_bytes, off_t file_pos, 
                     struct file* file, bool writable)
{ 
  struct supl_table_entry *entry = malloc (sizeof(struct supl_table_entry));
  entry->info.filesys.file = file;
  entry->info.filesys.read_bytes = read_bytes;
  entry->info.filesys.zero_bytes = PGSIZE - read_bytes;
  entry->info.filesys.file_pos = file_pos;
  entry->info.filesys.writable = writable;
  entry->upage = upage;
  entry->status = IN_FILESYS;

  struct hash_elem *e;
  e = hash_insert (table, &entry->elem);
  if (e != NULL) {
    free (entry);
    entry = hash_entry (e, struct supl_table_entry, elem);
    entry->info.filesys.read_bytes = read_bytes;
    entry->info.filesys.zero_bytes = PGSIZE - read_bytes;
    entry->info.filesys.file = file;
    entry->info.filesys.file_pos = file_pos;
    entry->info.filesys.writable = writable;
    entry->status = IN_FILESYS;
  }
  return true;
}

/* Insert a new page of type all zeros on the supplemental page table.*/
bool
supl_insert_zero_page (struct hash *table, void *upage) {
  struct supl_table_entry *entry = malloc (sizeof(struct supl_table_entry));
  entry->upage = upage;
  entry->status = ALL_ZERO;
  
  struct hash_elem *e;
  e = hash_insert (table, &entry->elem);
  return e == NULL;
}

/* Set status of entry for upage in supl_table to ON_SWAP, store slot in info.swap_info.slot*/
void
supl_set_page_swap (struct hash *table, void *upage, size_t slot){
  struct supl_table_entry *entry = supl_lookup_page(table, upage);
  ASSERT (entry != NULL)
  entry->status = SWAP;
  entry->info.swap.slot = slot;
}

/* Find the corresponding supl_table entry based on the UPAGE*/
struct supl_table_entry*
supl_lookup_page (struct hash *table, const void *upage) {
  // Since only find the corresponding page no need to 
  // store the supl_table_entry struct
  struct supl_table_entry entry;
  entry.upage = pg_round_down (upage);
  struct hash_elem *e;
  e = hash_find (table, &entry.elem);
  return e == NULL ? NULL : hash_entry (e, struct supl_table_entry, elem);
}

/* Destroy the whole supl page table */
void
free_supl_page_table (struct hash* table) {
  ASSERT (table != NULL);
  hash_destroy (table, hash_destroy_func);
}

bool 
spage_less_func (const struct hash_elem *e1, const struct hash_elem *e2, void *aux UNUSED)
{
  struct supl_table_entry *a_entry = hash_entry (e1, struct supl_table_entry, elem);
  struct supl_table_entry *b_entry = hash_entry (e2, struct supl_table_entry, elem);
  return a_entry->upage < b_entry->upage;
}

unsigned 
spage_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
  struct supl_table_entry *entry = hash_entry (e, struct supl_table_entry, elem);
  return hash_bytes (&entry->upage, sizeof (entry->upage));
}

void
hash_destroy_func (struct hash_elem *e, void *aux UNUSED) {
  struct supl_table_entry *entry = hash_entry (e, struct supl_table_entry, elem);
  ASSERT (entry != NULL);
  struct thread *cur = thread_current ();
  if (entry->status == ON_FRAME && entry->info.frame.addr != NULL) {
    pagedir_clear_page (cur->pagedir, entry->upage);
    if (entry->info.frame.shared) {
      //printf ("%d Freeing shared frame %p upage %p\n", cur->tid, entry->info.frame.addr, entry->upage);
      close_sharing_frame (entry->info.frame.addr);
    } else {
      free_frame_addr (entry->info.frame.addr);
    }
  } else if (entry->status == SWAP) {
    swap_free (entry->info.swap.slot);
  }
  free (entry);
}
