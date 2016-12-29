/*
 * Detect Hung Task
 *
 * kernel/hung_task.c - kernel thread for detecting tasks stuck in D state
 *
 */

#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/nmi.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/lockdep.h>
#include <linux/export.h>
#include <linux/sysctl.h>
#include <linux/utsname.h>
#include <linux/oom.h>
#include <trace/events/sched.h>

/*
 * The number of tasks checked:
 */
int __read_mostly sysctl_hung_task_check_count = PID_MAX_LIMIT;

/*
 * Limit number of tasks checked in a batch.
 *
 * This value controls the preemptibility of khungtaskd since preemption
 * is disabled during the critical section. It also controls the size of
 * the RCU grace period. So it needs to be upper-bound.
 */
#define HUNG_TASK_BATCHING 1024

/*
 * Zero means infinite timeout - no checking done:
 */
unsigned long __read_mostly sysctl_hung_task_timeout_secs = CONFIG_DEFAULT_HUNG_TASK_TIMEOUT;

int __read_mostly sysctl_hung_task_warnings = 10;

static int __read_mostly did_panic;

static struct task_struct *watchdog_task;

/*
 * Should we panic (and reboot, if panic_timeout= is set) when a
 * hung task is detected:
 */
unsigned int __read_mostly sysctl_hung_task_panic =
				CONFIG_BOOTPARAM_HUNG_TASK_PANIC_VALUE;

static int __init hung_task_panic_setup(char *str)
{
	int rc = kstrtouint(str, 0, &sysctl_hung_task_panic);

	if (rc)
		return rc;
	return 1;
}
__setup("hung_task_panic=", hung_task_panic_setup);

static int
hung_task_panic(struct notifier_block *this, unsigned long event, void *ptr)
{
	did_panic = 1;

	return NOTIFY_DONE;
}

static struct notifier_block panic_block = {
	.notifier_call = hung_task_panic,
};

#ifdef CONFIG_DETECT_MEMALLOC_STALL_TASK
/*
 * Zero means infinite timeout - no checking done:
 */
unsigned long __read_mostly sysctl_memalloc_task_timeout_secs =
	CONFIG_DEFAULT_MEMALLOC_TASK_TIMEOUT;
static struct memalloc_info memalloc; /* Filled by is_stalling_task(). */

static long memalloc_timeout_jiffies(unsigned long last_checked, long timeout)
{
	/* timeout of 0 will disable the watchdog */
	return timeout ? last_checked - jiffies + timeout * HZ :
		MAX_SCHEDULE_TIMEOUT;
}

/**
 * is_stalling_task - Check and copy a task's memalloc variable.
 *
 * @task:   A task to check.
 * @expire: Timeout in jiffies.
 *
 * Returns true if a task is stalling, false otherwise.
 */
static bool is_stalling_task(const struct task_struct *task,
			     const unsigned long expire)
{
	const struct memalloc_info *m = &task->memalloc;

	if (!m->valid)
		return false;
	memalloc.sequence = m->sequence;
	memalloc.start = m->start;
	memalloc.order = m->order;
	memalloc.gfp = m->gfp;
	return time_after_eq(expire, memalloc.start);
}

/*
 * check_memalloc_stalling_tasks - Check for memory allocation stalls.
 *
 * @timeout: Timeout in jiffies.
 *
 * Returns number of stalling tasks.
 *
 * This function is marked as "noinline" in order to allow inserting dynamic
 * probes (e.g. printing more information as needed using SystemTap, calling
 * panic() if this function returned non 0 value).
 */
static noinline int check_memalloc_stalling_tasks(unsigned long timeout)
{
	char buf[256];
	struct task_struct *g, *p;
	unsigned long now;
	unsigned long expire;
	unsigned int sigkill_pending = 0;
	unsigned int exiting_tasks = 0;
	unsigned int memdie_pending = 0;
	unsigned int stalling_tasks = 0;

	cond_resched();
	now = jiffies;
	/*
	 * Report tasks that stalled for more than half of timeout duration
	 * because such tasks might be correlated with tasks that already
	 * stalled for full timeout duration.
	 */
	expire = now - timeout * (HZ / 2);
	/* Count stalling tasks, dying and victim tasks. */
	preempt_disable();
	rcu_read_lock();
	for_each_process_thread(g, p) {
		u8 type = 0;

		if (test_tsk_thread_flag(p, TIF_MEMDIE)) {
			type |= 1;
			memdie_pending++;
		}
		if (fatal_signal_pending(p)) {
			type |= 2;
			sigkill_pending++;
		}
		if ((p->flags & PF_EXITING) && p->state != TASK_DEAD) {
			type |= 8;
			exiting_tasks++;
		}
		if (is_stalling_task(p, expire)) {
			type |= 4;
			stalling_tasks++;
		}
		if (p->flags & PF_KSWAPD)
			type |= 128;
		p->memalloc.type = type;
	}
	rcu_read_unlock();
	preempt_enable();
	if (!stalling_tasks)
		return 0;
	cond_resched();
	/* Report stalling tasks, dying and victim tasks. */
	pr_warn("MemAlloc-Info: stalling=%u dying=%u exiting=%u victim=%u oom_count=%u\n",
		stalling_tasks, sigkill_pending, exiting_tasks, memdie_pending,
		out_of_memory_count);
	cond_resched();
	sigkill_pending = 0;
	exiting_tasks = 0;
	memdie_pending = 0;
	stalling_tasks = 0;
	preempt_disable();
	rcu_read_lock();
 restart_report:
	for_each_process_thread(g, p) {
		bool can_cont;
		u8 type;

		if (likely(!p->memalloc.type))
			continue;
		p->memalloc.type = 0;
		/* Recheck in case state changed meanwhile. */
		type = 0;
		if (test_tsk_thread_flag(p, TIF_MEMDIE)) {
			type |= 1;
			memdie_pending++;
		}
		if (fatal_signal_pending(p)) {
			type |= 2;
			sigkill_pending++;
		}
		if ((p->flags & PF_EXITING) && p->state != TASK_DEAD) {
			type |= 8;
			exiting_tasks++;
		}
		if (is_stalling_task(p, expire)) {
			type |= 4;
			stalling_tasks++;
			snprintf(buf, sizeof(buf),
				 " seq=%u gfp=0x%x(%pGg) order=%u delay=%lu",
				 memalloc.sequence, memalloc.gfp,
				 &memalloc.gfp,
				 memalloc.order, now - memalloc.start);
		} else {
			buf[0] = '\0';
		}
		if (p->flags & PF_KSWAPD)
			type |= 128;
		if (unlikely(!type))
			continue;
		/*
		 * Victim tasks get pending SIGKILL removed before arriving at
		 * do_exit(). Therefore, print " exiting" instead for " dying".
		 */
		pr_warn("MemAlloc: %s(%u) flags=0x%x switches=%lu%s%s%s%s%s\n",
			p->comm, p->pid, p->flags, p->nvcsw + p->nivcsw, buf,
			(p->state & TASK_UNINTERRUPTIBLE) ?
			" uninterruptible" : "",
			(type & 8) ? " exiting" : "",
			(type & 2) ? " dying" : "",
			(type & 1) ? " victim" : "");
		sched_show_task(p);
		/*
		 * Since there could be thousands of tasks to report, we always
		 * call cond_resched() after each report, in order to avoid RCU
		 * stalls.
		 *
		 * Since not yet reported tasks have p->memalloc.type > 0, we
		 * can simply restart this loop in case "g" or "p" went away.
		 */
		get_task_struct(g);
		get_task_struct(p);
		rcu_read_unlock();
		preempt_enable_no_resched();
		/*
		 * TODO: Try to wait for a while (e.g. sleep until usage of
		 * printk() buffer becomes less than 75%) in order to avoid
		 * dropping messages.
		 */
		cond_resched();
		preempt_disable();
		rcu_read_lock();
		can_cont = pid_alive(g) && pid_alive(p);
		put_task_struct(p);
		put_task_struct(g);
		if (!can_cont)
			goto restart_report;
	}
	rcu_read_unlock();
	preempt_enable_no_resched();
	cond_resched();
	/* Show memory information. (SysRq-m) */
	show_mem(0);
	/* Show workqueue state. */
	show_workqueue_state();
	/* Show lock information. (SysRq-d) */
	debug_show_all_locks();
	pr_warn("MemAlloc-Info: stalling=%u dying=%u exiting=%u victim=%u oom_count=%u\n",
		stalling_tasks, sigkill_pending, exiting_tasks, memdie_pending,
		out_of_memory_count);
	return stalling_tasks;
}
#endif /* CONFIG_DETECT_MEMALLOC_STALL_TASK */

static void check_hung_task(struct task_struct *t, unsigned long timeout)
{
	unsigned long switch_count = t->nvcsw + t->nivcsw;

	/*
	 * Ensure the task is not frozen.
	 * Also, skip vfork and any other user process that freezer should skip.
	 */
	if (unlikely(t->flags & (PF_FROZEN | PF_FREEZER_SKIP)))
	    return;

	/*
	 * When a freshly created task is scheduled once, changes its state to
	 * TASK_UNINTERRUPTIBLE without having ever been switched out once, it
	 * musn't be checked.
	 */
	if (unlikely(!switch_count))
		return;

	if (switch_count != t->last_switch_count) {
		t->last_switch_count = switch_count;
		return;
	}

	trace_sched_process_hang(t);

	if (!sysctl_hung_task_warnings && !sysctl_hung_task_panic)
		return;

	/*
	 * Ok, the task did not get scheduled for more than 2 minutes,
	 * complain:
	 */
	if (sysctl_hung_task_warnings) {
		sysctl_hung_task_warnings--;
		pr_err("INFO: task %s:%d blocked for more than %ld seconds.\n",
			t->comm, t->pid, timeout);
		pr_err("      %s %s %.*s\n",
			print_tainted(), init_utsname()->release,
			(int)strcspn(init_utsname()->version, " "),
			init_utsname()->version);
		pr_err("\"echo 0 > /proc/sys/kernel/hung_task_timeout_secs\""
			" disables this message.\n");
		sched_show_task(t);
		debug_show_all_locks();
	}

	touch_nmi_watchdog();

	if (sysctl_hung_task_panic) {
		trigger_all_cpu_backtrace();
		panic("hung_task: blocked tasks");
	}
}

/*
 * To avoid extending the RCU grace period for an unbounded amount of time,
 * periodically exit the critical section and enter a new one.
 *
 * For preemptible RCU it is sufficient to call rcu_read_unlock in order
 * to exit the grace period. For classic RCU, a reschedule is required.
 */
static bool rcu_lock_break(struct task_struct *g, struct task_struct *t)
{
	bool can_cont;

	get_task_struct(g);
	get_task_struct(t);
	rcu_read_unlock();
	cond_resched();
	rcu_read_lock();
	can_cont = pid_alive(g) && pid_alive(t);
	put_task_struct(t);
	put_task_struct(g);

	return can_cont;
}

/*
 * Check whether a TASK_UNINTERRUPTIBLE does not get woken up for
 * a really long time (120 seconds). If that happens, print out
 * a warning.
 */
static void check_hung_uninterruptible_tasks(unsigned long timeout)
{
	int max_count = sysctl_hung_task_check_count;
	int batch_count = HUNG_TASK_BATCHING;
	struct task_struct *g, *t;

	/*
	 * If the system crashed already then all bets are off,
	 * do not report extra hung tasks:
	 */
	if (test_taint(TAINT_DIE) || did_panic)
		return;

	rcu_read_lock();
	for_each_process_thread(g, t) {
		if (!max_count--)
			goto unlock;
		if (!--batch_count) {
			batch_count = HUNG_TASK_BATCHING;
			if (!rcu_lock_break(g, t))
				goto unlock;
		}
		/* use "==" to skip the TASK_KILLABLE tasks waiting on NFS */
		if (t->state == TASK_UNINTERRUPTIBLE)
			check_hung_task(t, timeout);
	}
 unlock:
	rcu_read_unlock();
}

static long hung_timeout_jiffies(unsigned long last_checked,
				 unsigned long timeout)
{
	/* timeout of 0 will disable the watchdog */
	return timeout ? last_checked - jiffies + timeout * HZ :
		MAX_SCHEDULE_TIMEOUT;
}

/*
 * Process updating of timeout sysctl
 */
int proc_dohung_task_timeout_secs(struct ctl_table *table, int write,
				  void __user *buffer,
				  size_t *lenp, loff_t *ppos)
{
	int ret;

	ret = proc_doulongvec_minmax(table, write, buffer, lenp, ppos);

	if (ret || !write)
		goto out;

	wake_up_process(watchdog_task);

 out:
	return ret;
}

static atomic_t reset_hung_task = ATOMIC_INIT(0);

void reset_hung_task_detector(void)
{
	atomic_set(&reset_hung_task, 1);
}
EXPORT_SYMBOL_GPL(reset_hung_task_detector);

/*
 * kthread which checks for tasks stuck in D state
 */
static int watchdog(void *dummy)
{
	unsigned long hung_last_checked = jiffies;
#ifdef CONFIG_DETECT_MEMALLOC_STALL_TASK
	unsigned long stall_last_checked = hung_last_checked;
#endif

	set_user_nice(current, 0);

	for ( ; ; ) {
		unsigned long timeout = sysctl_hung_task_timeout_secs;
		long t = hung_timeout_jiffies(hung_last_checked, timeout);
#ifdef CONFIG_DETECT_MEMALLOC_STALL_TASK
		unsigned long timeout2 = sysctl_memalloc_task_timeout_secs;
		long t2 = memalloc_timeout_jiffies(stall_last_checked,
						   timeout2);

		if (t2 <= 0) {
			if (memalloc_maybe_stalling())
				check_memalloc_stalling_tasks(timeout2);
			stall_last_checked = jiffies;
			continue;
		}
#else
		long t2 = t;
#endif
		if (t <= 0) {
			if (!atomic_xchg(&reset_hung_task, 0))
				check_hung_uninterruptible_tasks(timeout);
			hung_last_checked = jiffies;
			continue;
		}
		schedule_timeout_interruptible(min(t, t2));
	}

	return 0;
}

static int __init hung_task_init(void)
{
	atomic_notifier_chain_register(&panic_notifier_list, &panic_block);
	watchdog_task = kthread_run(watchdog, NULL, "khungtaskd");

	return 0;
}
subsys_initcall(hung_task_init);
