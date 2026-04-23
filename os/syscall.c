#include "syscall.h"
#include "console.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "vm.h"

void freeproc(struct proc *p);
struct proc *allocproc(void);
struct proc *curr_proc(void);
uint64 sys_mmap(uint64 start, uint64 len, int port, int flag, int fd);

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d str = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

uint64 sys_read(int fd, uint64 va, uint64 len)
{
	debugf("sys_read fd = %d str = %x, len = %d", fd, va, len);
	if (fd != STDIN)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	for (int i = 0; i < len; ++i) {
		int c = consgetc();
		str[i] = c;
	}
	copyout(p->pagetable, va, str, len);
	return len;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}
uint64 sys_mmap(uint64 start, uint64 len, int port, int flag, int fd)
{
    if (len == 0) return start;  // Return start address for 0-length requests

    if ((port & ~0x7) != 0) return -1; 
    if ((port & 0x7) == 0)  return -1;
    if (len > 1024ULL * 1024 * 1024) return -1;

    struct proc *p = curr_proc();
    len = PGROUNDUP(len);

    // If start is 0, choose a suitable address
    if (start == 0) {
        start = 0x60000000;  // Choose a reasonable virtual address
    }

    // Ensure start is page-aligned
    if (start % PGSIZE != 0) return -1;

    //check if page is mapped
    for (uint64 addr = start; addr < start + len; addr += PGSIZE) {
        if (walkaddr(p->pagetable, addr) != 0) {
            return -1;
        }
    }

    int pte_flags = PTE_U; // user port
    if (port & 1) pte_flags |= PTE_R;
    if (port & 2) pte_flags |= PTE_W;
    if (port & 4) pte_flags |= PTE_X;

    for (uint64 addr = start; addr < start + len; addr += PGSIZE) {
        void *pa = kalloc();
        if (pa == 0) return -1;
        memset(pa, 0, PGSIZE);
        if (mappages(p->pagetable, addr, PGSIZE, (uint64)pa, pte_flags) != 0) {
            kfree(pa);
            return -1;
        }
    }

    return start; 
}

uint64 sys_munmap(uint64 start, uint64 len)
{
    if (len == 0) return 0;
    if (start % PGSIZE != 0) return -1;

    struct proc *p = curr_proc();
    len = PGROUNDUP(len);
    uint64 npages = len / PGSIZE;

    // Check every page mapped
    for (uint64 addr = start; addr < start + len; addr += PGSIZE) {
        if (walkaddr(p->pagetable, addr) == 0) {
            return -1;  
        }
    }

    uvmunmap(p->pagetable, start, npages, 1);
    return 0;
}

uint64 sys_gettimeofday(uint64 val, int _tz)
{
    uint64 phys_addr = useraddr(curr_proc()->pagetable, (uint64)val);
    if (phys_addr == 0) {
        return -1;  
    }
    
    //TimeVal *phys_val = (TimeVal *)phys_addr;
	struct proc *p = curr_proc();
	uint64 cycle = get_cycle();
	TimeVal t;
	t.sec = cycle / CPU_FREQ;
	t.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	copyout(p->pagetable, val, (char *)&t, sizeof(TimeVal));
	return 0;
}

uint64 sys_getpid()
{
	return curr_proc()->pid;
}

uint64 sys_getppid()
{
	struct proc *p = curr_proc();
	return p->parent == NULL ? IDLE_PID : p->parent->pid;
}

uint64 sys_clone()
{
	debugf("fork!\n");
	return fork();
}

uint64 sys_exec(uint64 va)
{
	struct proc *p = curr_proc();
	char name[200];
	copyinstr(p->pagetable, name, va, 200);
	debugf("sys_exec %s\n", name);
	return exec(name);
}

uint64 sys_wait(int pid, uint64 va)
{
	struct proc *p = curr_proc();
	int *code = (int *)useraddr(p->pagetable, va);
	return wait(pid, code);
}

int sys_task_info(struct TaskInfo *ti)
{
    struct proc *p = curr_proc();
    
    uint64 phys_addr = useraddr(p->pagetable, (uint64)ti);
    if (phys_addr == 0) {
        return -1;  // Invalid address
    }
    
    struct TaskInfo *phys_ti = (struct TaskInfo *)phys_addr;
    
    phys_ti->status = TaskStatusRunning;
    
    for (int i = 0; i < MAX_SYSCALL_NUM; i++) {
        phys_ti->syscall_times[i] = p->syscall_times[i];
    }
    
    uint64 current_time = get_cycle() / (CPU_FREQ / 1000);
    phys_ti->time = (int)(current_time - p->start_time);
    
    return 0;
}
uint64 sys_spawn(uint64 va)
{
    struct proc *p = curr_proc();
    char name[200];
    copyinstr(p->pagetable, name, va, 200);
    
    // Create new process
    struct proc *np = allocproc();
    if (np == 0) {
        return -1;  // Process allocation failed
    }
    
    // Set up new process
    np->parent = p;
    np->state = USED;
    
    // Load program
    int id = get_id_by_name(name);
    if (id < 0) {
        freeproc(np);
        return -1;  // Invalid program name
    }
    
    loader(id, np);
    np->state = RUNNABLE;
    
    return np->pid;
}

uint64 sys_set_priority(long long prio)
{
    if (prio < 2) {
        return -1;  // Priority must be >= 2
    }
    
    struct proc *p = curr_proc();
    p->priority = (int)prio;
    p->pass = BIG_STRIDE / p->priority;  // Recalculate pass value
    
    return prio;
}


extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
    if (id >= 0 && id < MAX_SYSCALL_NUM) {
    curr_proc()->syscall_times[id]++;
	}
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_read:
		ret = sys_read(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday(args[0], args[1]);
		break;
	case SYS_getpid:
		ret = sys_getpid();
		break;
    case SYS_task_info:
    ret = sys_task_info((struct TaskInfo *)args[0]);
    break;
	case SYS_getppid:
		ret = sys_getppid();
		break;
	case SYS_clone: // SYS_fork
		ret = sys_clone();
		break;
	case SYS_execve:
		ret = sys_exec(args[0]);
		break;
	case SYS_wait4:
		ret = sys_wait(args[0], args[1]);
		break;
	case SYS_spawn:
		ret = sys_spawn(args[0]);
		break;
    case SYS_mmap:
    ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
    break;
	case SYS_munmap:
    ret = sys_munmap(args[0], args[1]);
    break;
    // case SYS_spawn:
    // ret = sys_spawn(args[0]);
    // break;
    case SYS_setpriority:
    ret = sys_set_priority(args[0]);
    break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
