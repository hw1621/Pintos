#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/thread.h"
#define NOF 15 /*number of system call functions*/

void syscall_init (void);
void syscall_exit (int);

#ifdef VM
void syscall_mumap (mapid_t);
#endif

#endif /* userprog/syscall.h */
