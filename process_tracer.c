#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <asm/syscall_wrapper.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/init_task.h>
#include <linux/init.h>
#include <linux/kernel.h>

#define __NR_ftrace 336

void **syscall_table;
void *real_ftrace;

struct task_struct *findtask = &init_task;	//task_struct find
struct task_struct *leader = &init_task;	//task_struct leader find
struct list_head *list;				//list head of task_struct
struct task_struct *tmp;			//save task_struct
struct task_struct *cur;			//current task_struct
struct task_struct *pa;				//parent task_struct

int child_count=0;				//count child process
int sibling_count=0;				//count sibling process

asmlinkage pid_t process_tracer(pid_t trace_task);		//process_tracer define
__SYSCALL_DEFINEx(1, process_tracer, pid_t, trace_task)		//syscall define
{	
	//find process
	do{
		if(findtask->pid==trace_task){break;}
		findtask = next_task(findtask);			//next process
	}
	while((findtask->pid!=init_task.pid));

	//find group leader
	do{
		if(leader->pid==findtask->tgid){break;}
		leader = next_task(leader);			//next process
	}
	while((leader->pid!=init_task.pid));

	//parent
	pa=findtask->real_parent;

	printk(" [OSLab.]##### TASK INFORMATION of ''[%d] %s'' #####\n",findtask->pid,findtask->comm);
	
	//state
	if(findtask->state==0x0000){printk(" [OSLab.]- task state : Running or ready\n");}
	else if(findtask->state==0x0001){printk(" [OSLab.]- task state : Wait\n");}
	else if(findtask->state==0x0002){printk(" [OSLab.]- task state : Wait with ignoring all signal\n");}
	else if(findtask->state==0x0004){printk(" [OSLab.]- task state : Stopped\n");}
	else if(findtask->exit_state==0x0020){printk(" [OSLab.]- task state : Zombie process\n");}
	else if(findtask->exit_state==0x0010){printk(" [OSLab.]- task state : Dead\n");}
	else {printk(" [OSLab.]- task state : etc.\n");}

	//group 
	printk(" [OSLab.]- Process Group Leader : [%d] %s \n",leader->pid, leader->comm);

	//context switch
	printk(" [OSLab.]- Number of context switches : %ld \n",findtask->nivcsw+findtask->nivcsw);

	//fork
	printk(" [OSLab.]- Number of calling fork() : %d \n",findtask->fork_num);

	//parent
	printk(" [OSLab.]- it's parent process : [%d] %s \n",pa->pid, pa->comm);

	//sibling process	
	printk(" [OSLab.]- it's sibling process(es) :\n");
	list_for_each(list,&pa->children){		//children of parent process
		tmp=list_entry(list,struct task_struct, sibling);	//siblimg of children
		if((tmp->real_parent->pid==findtask->real_parent->pid)&&tmp!=findtask){
			printk(" [OSLab.]    > [%d] %s \n",tmp->pid,tmp->comm);
			sibling_count+=1;
		}
	}
	if(sibling_count!=0){printk(" [OSLab.]    > This process has %d sibling process(es)\n",sibling_count);}
	else{printk(" [OSLab.]    > It has no sibling.\n");}

	//child process	
	printk(" [OSLab.]- it's child process(es) :\n");
	list_for_each(list,&findtask->children){		//list is children head of findtast
		tmp=list_entry(list,struct task_struct, sibling);	//access sibling of list
		printk(" [OSLab.]    > [%d] %s \n",tmp->pid,tmp->comm);	
		child_count+=1;
	}
	if(child_count!=0){printk(" [OSLab.]    > This process has %d child process(es)\n",child_count);}
	else{printk(" [OSLab.]    > It has no child.\n");}

	printk(" [OSLab.]##### END OF INFORMATION #####\n");
	child_count=0;
	sibling_count=0;

	return 0;
}

void make_rw(void *addr)
{
	//Grant read write permission
	unsigned int level;
	pte_t *pte = lookup_address((u64)addr,&level);

	if(pte->pte &~ _PAGE_RW){pte->pte |= _PAGE_RW;}
}

void make_ro(void *addr)
{
	//Revoke read and write permission
	unsigned int level;
	pte_t *pte = lookup_address((u64)addr, &level);

	pte->pte = pte->pte &~ _PAGE_RW;
}

static int __init hooking_init(void)
{
	//change to new syscall
	syscall_table=(void**) kallsyms_lookup_name("sys_call_table");
	make_rw(syscall_table);

	real_ftrace = syscall_table[__NR_ftrace];	//save original
	syscall_table[__NR_ftrace] =__x64_sysprocess_tracer;	//set new syscall

	return 0;
}

static void __exit hooking_exit(void)
{
	//revert to original syscall
	syscall_table[__NR_ftrace]=real_ftrace;		//set original

	make_ro(syscall_table);				//Revoke read and write permission
}

module_init(hooking_init);	//kernel module init
module_exit(hooking_exit);	//kernel module exit
MODULE_LICENSE("GPL");

