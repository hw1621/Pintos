#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/synch.h"
#include "fixed-point.h"
#include "lib/kernel/hash.h"

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
typedef int pid_t;
typedef int mapid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* Thread nices. */
#define NICE_MIN -20                    /* Lowest nice value. */
#define NICE_INIT 0                     /* Initial nice value. */
#define NICE_MAX 20                     /* Highest nice value. */

/* Thread init recent_cpu. */
#define RECENT_CPU_INIT 0               /* Initial Recent_cpu value. */

#define TIMER_FREQ 100

/* Struct of an element of child process list. */
struct child_process {                         
   int child_tid;                    /* id of child process(thread). */
   int exit_status;                  /* Exit status of the child_process. */
   struct list_elem child_elem;      /* Element of child process. */
   struct semaphore parent_wait;     /* Used to block parent process to wait for child */
   bool is_finished;                 /* Whether the child process is finished */
};

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    struct list_elem allelem;           /* List element for all threads list. */
    int original_priority;              /* Store the original priority that the thread have */
    struct list lock_list;              /* Store the locks that the thread hold */
    struct thread *priority_donated_to; /* Point to the thread that current thread donates its priority to */
    int nice;                           /* Nice value. */
    fp recent_cpu;                      /* Recent CPU value. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
    struct file *executable_file;       /* The executable file loaded by the thread. */
    struct list child_proc_list;        /* List of child process. */
    struct list fd_list;                /* List of fds. */
    struct thread *parent_thread;       /* Pointer of parent_thread. */
    struct child_process *child_proc_entry; /* Pointer entry to its child_process */
    struct semaphore sema_execute;      /* Use to control child thread, finish parent waiting for child */
    bool execute_success;               /* See whehter the child thread execute successfully */
#endif

#ifdef VM
    struct hash supl_table;             /* Supplemental page table per process */
    struct list mapped_file_fd_list;    /* List of memory mapped files */
#endif    
    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };


struct file_descriptor {
    int fd_id;
    struct file *file;
    struct list_elem fd_elem;
};

struct map_descriptor {
   mapid_t id;            // mapid of the mapping
   struct file *file;     // Pointer to the mapped file
   void *addr;            // Starting vaddress of the mapping
   struct list_elem elem; // List element
   uint32_t size;         // Size of the mapping in bytes
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);
size_t threads_ready (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);
int find_max_priority (int init_priority);

int thread_get_nice (void);
void thread_set_nice (int);

int thread_get_recent_cpu (void);
fp thread_get_accurate_recent_cpu (void);
void thread_set_recent_cpu (fp);
int thread_get_load_avg (void);

bool priority_compare (const struct list_elem *, 
                       const struct list_elem *, void * aux);

void calculate_priority (struct thread *t, void *aux);
void calculate_recent_cpu (struct thread *t, void *aux);
void calculate_load_avg (void);
void calculate_recent_cpu_and_priority (struct thread* t, void* aux);

#endif /* threads/thread.h */
