#ifndef PROC_H
#define PROC_H

#include "riscv.h"
#include "types.h"
#include "queue.h"

#define NPROC (512)
#define FD_BUFFER_SIZE (16)
#define MAX_SYSCALL_NUM (500)
#define DEFAULT_PRIORITY 16
#define BIG_STRIDE 0x7FFFFFFF 

typedef enum {
    TaskStatusRunning = 2,
} TaskStatus;

struct file;

// Saved registers for kernel context switches.
struct context {
	uint64 ra;
	uint64 sp;

	// callee-saved
	uint64 s0;
	uint64 s1;
	uint64 s2;
	uint64 s3;
	uint64 s4;
	uint64 s5;
	uint64 s6;
	uint64 s7;
	uint64 s8;
	uint64 s9;
	uint64 s10;
	uint64 s11;
};

enum procstate { UNUSED, USED, SLEEPING, RUNNABLE, RUNNING, ZOMBIE };

struct TaskInfo {
    TaskStatus status;
    unsigned int syscall_times[MAX_SYSCALL_NUM];
    int time;
};

// Per-process state
struct proc {
	enum procstate state; // Process state
	int pid; // Process ID
	pagetable_t pagetable; // User page table
	uint64 ustack; // Virtual address of kernel stack
	uint64 kstack; // Virtual address of kernel stack
	struct trapframe *trapframe; // data page for trampoline.S
	struct context context; // swtch() here to run process
	uint64 max_page;
	struct proc *parent; // Parent process
	uint64 exit_code;
	struct file *files[FD_BUFFER_SIZE]; // File descriptor table
	uint64 start_time;                  // Chapter 3: Process start time
	unsigned int syscall_times[MAX_SYSCALL_NUM]; // Chapter 3: Syscall tracking
	int priority;     // Chapter 5: Process priority
    uint64 stride;    // Chapter 5: Current stride value 
    uint64 pass;      // Chapter 5: Pass value 
};

int cpuid();
struct proc *curr_proc();
void exit(int);
void proc_init();
void scheduler() __attribute__((noreturn));
void sched();
void yield();
int fork();
int exec(char *, char **);  // Chapter 6: Updated exec with argv support
int wait(int, int *);
void add_task(struct proc *);
struct proc *pop_task();
struct proc *allocproc();
int fdalloc(struct file *);        // Chapter 6: File descriptor allocation
int init_stdio(struct proc *);     // Chapter 6: Initialize stdio
int push_argv(struct proc *, char **); // Chapter 6: Argument handling
// swtch.S
void swtch(struct context *, struct context *);

#endif // PROC_H