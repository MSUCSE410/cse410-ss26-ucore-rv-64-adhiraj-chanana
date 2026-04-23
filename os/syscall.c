#include "syscall.h"
#include "console.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "vm.h"
#include "file.h"
#include "fs.h"

void freeproc(struct proc *p);
struct proc *allocproc(void);
struct proc *curr_proc(void);

uint64 console_write(uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	tracef("write size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return len;
}

uint64 console_read(uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	tracef("read size = %d", len);
	for (int i = 0; i < len; ++i) {
		int c = consgetc();
		str[i] = c;
	}
	copyout(p->pagetable, va, str, len);
	return len;
}

uint64 sys_write(int fd, uint64 va, uint64 len)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d\n", fd);
		return -1;
	}
	switch (f->type) {
	case FD_STDIO:
		return console_write(va, len);
	case FD_INODE:
		return inodewrite(f, va, len);
	default:
		panic("unknown file type %d\n", f->type);
	}
}

uint64 sys_read(int fd, uint64 va, uint64 len)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d\n", fd);
		return -1;
	}
	switch (f->type) {
	case FD_STDIO:
		return console_read(va, len);
	case FD_INODE:
		return inoderead(f, va, len);
	default:
		panic("unknown file type %d\n", f->type);
	}
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

uint64 sys_gettimeofday(uint64 val, int _tz)
{
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
	debugf("fork!");
	return fork();
}

static inline uint64 fetchaddr(pagetable_t pagetable, uint64 va)
{
	uint64 *addr = (uint64 *)useraddr(pagetable, va);
	return *addr;
}

uint64 sys_exec(uint64 path, uint64 uargv)
{
	struct proc *p = curr_proc();
	char name[MAX_STR_LEN];
	copyinstr(p->pagetable, name, path, MAX_STR_LEN);
	uint64 arg;
	static char strpool[MAX_ARG_NUM][MAX_STR_LEN];
	char *argv[MAX_ARG_NUM];
	int i;
	for (i = 0; uargv && (arg = fetchaddr(p->pagetable, uargv));
	     uargv += sizeof(char *), i++) {
		copyinstr(p->pagetable, (char *)strpool[i], arg, MAX_STR_LEN);
		argv[i] = (char *)strpool[i];
	}
	argv[i] = NULL;
	return exec(name, (char **)argv);
}

uint64 sys_wait(int pid, uint64 va)
{
	struct proc *p = curr_proc();
	int *code = (int *)useraddr(p->pagetable, va);
	return wait(pid, code);
}

uint64 sys_openat(uint64 va, uint64 omode, uint64 _flags)
{
	struct proc *p = curr_proc();
	char path[200];
	copyinstr(p->pagetable, path, va, 200);
	return fileopen(path, omode);
}

uint64 sys_close(int fd)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d", fd);
		return -1;
	}
	fileclose(f);
	p->files[fd] = 0;
	return 0;
}

int sys_task_info(struct TaskInfo *ti)
{
	struct proc *p = curr_proc();

	uint64 phys_addr = useraddr(p->pagetable, (uint64)ti);
	if (phys_addr == 0) {
		return -1;
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

uint64 sys_spawn(uint64 va)
{
	struct proc *p = curr_proc();
	char name[200];
	copyinstr(p->pagetable, name, va, 200);

	struct proc *np = allocproc();
	if (np == 0) {
		return -1;
	}

	np->parent = p;
	np->state = USED;

	struct inode *ip = namei(name);
	if (ip == 0) {
		freeproc(np);
		return -1;
	}

	bin_loader(ip, np);
	iput(ip);
	for (int i = 0; i < FD_BUFFER_SIZE; i++) {
    np->files[i] = p->files[i];
    if (np->files[i]) {
        np->files[i]->ref++;
    }
}
	np->state = RUNNABLE;

	return np->pid;
}

uint64 sys_set_priority(long long prio)
{
	if (prio < 2) {
		return -1;
	}

	struct proc *p = curr_proc();
	p->priority = (int)prio;
	p->pass = BIG_STRIDE / p->priority;

	return prio;
}

int sys_linkat(int olddirfd, uint64 oldpath, int newdirfd, uint64 newpath, uint64 flags)
{
	struct proc *p = curr_proc();
	char oldname[200], newname[200];
	copyinstr(p->pagetable, oldname, oldpath, 200);
	copyinstr(p->pagetable, newname, newpath, 200);

	// Error: linking a file to the same name
	if (strncmp(oldname, newname, 200) == 0) {
		return -1;
	}

	// Look up the inode for the old file
	struct inode *ip = namei(oldname);
	if (ip == 0) {
		return -1;
	}

	// Increment hard link count and sync to disk
	ip->nlink++;
	iupdate(ip);

	// Flat filesystem: all files live in root dir, create new dirent there
	struct inode *dp = root_dir();
	if (dirlink(dp, newname, ip->inum) < 0) {
		ip->nlink--;
		iupdate(ip);
		iput(ip);
		iput(dp);
		return -1;
	}

	iput(dp);
	iput(ip);
	return 0;
}

int sys_unlinkat(int dirfd, uint64 name, uint64 flags)
{
	struct proc *p = curr_proc();
	char path[200];
	copyinstr(p->pagetable, path, name, 200);

	// Find the dirent in root dir and get its offset
	struct inode *dp = root_dir();
	uint off;
	struct inode *ip = dirlookup(dp, path, &off);
	if (ip == 0) {
		iput(dp);
		return -1;  // File does not exist
	}

	// Zero out the dirent entry on disk
	struct dirent de;
	memset(&de, 0, sizeof(de));
	if (writei(dp, 0, (uint64)&de, off, sizeof(de)) != sizeof(de)) {
		iput(ip);
		iput(dp);
		return -1;
	}
	iput(dp);

	// Decrement link count and sync to disk
	// iput() will free inode+data when nlink reaches 0 and ref drops to 0
	ip->nlink--;

	if (ip->nlink == 0) {
		itrunc(ip);   // 🔥 frees blocks immediately
	}

	iupdate(ip);
	iput(ip);
	return 0;
}

int sys_fstat(int fd, uint64 stat)
{
	if (fd < 0 || fd >= FD_BUFFER_SIZE)
		return -1;

	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		return -1;
	}

	// Validate the user virtual address
	if (useraddr(p->pagetable, stat) == 0) {
		return -1;
	}

	ivalid(f->ip);

	// Build the Stat struct and copy to user space
	// struct Stat { uint64 dev, uint64 ino, uint32 mode, uint32 nlink, uint64 pad[7] }
	uint64 st_dev   = 0;
	uint64 st_ino   = f->ip->inum;
	uint32 st_mode  = (f->ip->type == T_DIR) ? 0x040000 : 0x100000;
	uint32 st_nlink = f->ip->nlink;

	copyout(p->pagetable, stat,                    (char *)&st_dev,   sizeof(uint64));
	copyout(p->pagetable, stat + sizeof(uint64),   (char *)&st_ino,   sizeof(uint64));
	copyout(p->pagetable, stat + 2*sizeof(uint64), (char *)&st_mode,  sizeof(uint32));
	copyout(p->pagetable, stat + 2*sizeof(uint64) + sizeof(uint32), (char *)&st_nlink, sizeof(uint32));

	return 0;
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
	case SYS_openat:
		ret = sys_openat(args[0], args[1], args[2]);
		break;
	case SYS_close:
		ret = sys_close(args[0]);
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
	case SYS_getppid:
		ret = sys_getppid();
		break;
	case SYS_clone: // SYS_fork
		ret = sys_clone();
		break;
	case SYS_execve:
		ret = sys_exec(args[0], args[1]);
		break;
	case SYS_wait4:
		ret = sys_wait(args[0], args[1]);
		break;
	case SYS_fstat:
		ret = sys_fstat(args[0], args[1]);
		break;
	case SYS_linkat:
		ret = sys_linkat(args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_unlinkat:
		ret = sys_unlinkat(args[0], args[1], args[2]);
		break;
	case SYS_spawn:
		ret = sys_spawn(args[0]);
		break;
	case SYS_task_info:
		ret = sys_task_info((struct TaskInfo *)args[0]);
		break;
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;
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