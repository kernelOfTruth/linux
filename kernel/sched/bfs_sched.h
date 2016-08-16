#include <linux/sched.h>
#include <linux/cpuidle.h>
#include <linux/stop_machine.h>

#ifndef BFS_SCHED_H
#define BFS_SCHED_H

struct rq;
/*
 * choose task function type definination
 */
typedef
struct task_struct *
(*SCHED_CHOOSE_TASK_FUNC)(struct rq *rq, struct task_struct *prev,
			  bool preempt, unsigned long **pswitch_count);

/*
 * This is the main, per-CPU runqueue data structure.
 * This data should only be modified by the local cpu.
 */
struct rq {
	/* runqueue lock: */
	raw_spinlock_t lock;

	struct task_struct *curr, *idle, *stop;
	struct task_struct *try_preempt_tsk;
	struct task_struct *preempt_task;
	struct mm_struct *prev_mm;

	/* choose task func */
	SCHED_CHOOSE_TASK_FUNC choose_task_func;

	/* whether hold grq.lock in schedule() */
	bool grq_locked;

	/* switch count */
	u64 nr_switches;

	/* Stored data about rq->curr to work outside grq lock */
	u64 rq_deadline;
	unsigned int rq_policy;
	int rq_time_slice;
	u64 rq_last_ran;
	int rq_prio;
	bool rq_running; /* There is a task running */
#ifdef CONFIG_SMT_NICE
	struct mm_struct *rq_mm;
	int rq_smt_bias; /* Policy/nice level bias across smt siblings */
#endif
	/* Accurate timekeeping data */
	u64 timekeep_clock;
	unsigned long user_pc, nice_pc, irq_pc, softirq_pc, system_pc,
		iowait_pc, idle_pc;
	atomic_t nr_iowait;

	/* rq cached counters */
	unsigned long nr_running;
	long nr_uninterruptible;

#ifdef CONFIG_SMP
	int cpu;		/* cpu of this runqueue */
	bool online;
	bool scaling; /* This CPU is managed by a scaling CPU freq governor */
	int schedulable;
	struct task_struct *sticky_task;

	struct root_domain *rd;
	struct sched_domain *sd;
	int *cpu_locality; /* CPU relative cache distance */
#endif /* CONFIG_SMP */
#ifdef CONFIG_IRQ_TIME_ACCOUNTING
	u64 prev_irq_time;
#endif /* CONFIG_IRQ_TIME_ACCOUNTING */
#ifdef CONFIG_PARAVIRT
	u64 prev_steal_time;
#endif /* CONFIG_PARAVIRT */
#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
	u64 prev_steal_time_rq;
#endif /* CONFIG_PARAVIRT_TIME_ACCOUNTING */

	u64 clock, last_tick;
	u64 clock_task;
	bool dither;

#ifdef CONFIG_SCHEDSTATS

	/* latency stats */
	struct sched_info rq_sched_info;
	unsigned long long rq_cpu_time;
	/* could above be rq->cfs_rq.exec_clock + rq->rt_rq.rt_runtime ? */

	/* sys_sched_yield() stats */
	unsigned int yld_count;

	/* schedule() stats */
	unsigned int sched_switch;
	unsigned int sched_count;
	unsigned int sched_goidle;

	/* try_to_wake_up() stats */
	unsigned int ttwu_count;
	unsigned int ttwu_local;
#endif /* CONFIG_SCHEDSTATS */
#ifdef CONFIG_CPU_IDLE
	/* Must be inspected within a rcu lock section */
	struct cpuidle_state *idle_state;
#endif
};

#ifdef CONFIG_SMP
struct rq *cpu_rq(int cpu);
#endif

#ifndef CONFIG_SMP
extern struct rq *uprq;
#define cpu_rq(cpu)	(uprq)
#define this_rq()	(uprq)
#define raw_rq()	(uprq)
#define task_rq(p)	(uprq)
#define cpu_curr(cpu)	((uprq)->curr)
#else /* CONFIG_SMP */
DECLARE_PER_CPU_SHARED_ALIGNED(struct rq, runqueues);
#define cpu_rq(cpu)		(&per_cpu(runqueues, (cpu)))
#define this_rq()		this_cpu_ptr(&runqueues)
#define raw_rq()		raw_cpu_ptr(&runqueues)
#define task_rq(p)		cpu_rq(task_cpu(p))
#define cpu_curr(cpu)		(cpu_rq(cpu)->curr)

#if defined(CONFIG_SCHED_DEBUG) && defined(CONFIG_SYSCTL)
void register_sched_domain_sysctl(void);
void unregister_sched_domain_sysctl(void);
#else
static inline void register_sched_domain_sysctl(void)
{
}
static inline void unregister_sched_domain_sysctl(void)
{
}
#endif

#endif /* CONFIG_SMP */

static inline u64 __rq_clock_broken(struct rq *rq)
{
	return READ_ONCE(rq->clock);
}

static inline u64 rq_clock(struct rq *rq)
{
	lockdep_assert_held(&rq->lock);
	return rq->clock;
}

static inline u64 rq_clock_task(struct rq *rq)
{
	lockdep_assert_held(&rq->lock);
	return rq->clock_task;
}

extern struct mutex sched_domains_mutex;
extern struct static_key_false sched_schedstats;

#define rcu_dereference_check_sched_domain(p) \
	rcu_dereference_check((p), \
			      lockdep_is_held(&sched_domains_mutex))

/*
 * The domain tree (rq->sd) is protected by RCU's quiescent state transition.
 * See detach_destroy_domains: synchronize_sched for details.
 *
 * The domain tree of any CPU may only be accessed from within
 * preempt-disabled sections.
 */
#define for_each_domain(cpu, __sd) \
	for (__sd = rcu_dereference_check_sched_domain(cpu_rq(cpu)->sd); __sd; __sd = __sd->parent)

static inline void sched_ttwu_pending(void) { }

static inline int task_on_rq_queued(struct task_struct *p)
{
	return p->on_rq;
}

#ifdef CONFIG_CPU_IDLE
static inline void idle_set_state(struct rq *rq,
				  struct cpuidle_state *idle_state)
{
	rq->idle_state = idle_state;
}

static inline struct cpuidle_state *idle_get_state(struct rq *rq)
{
	WARN_ON(!rcu_read_lock_held());
	return rq->idle_state;
}
#else
static inline void idle_set_state(struct rq *rq,
				  struct cpuidle_state *idle_state)
{
}

static inline struct cpuidle_state *idle_get_state(struct rq *rq)
{
	return NULL;
}
#endif

#ifdef CONFIG_CPU_FREQ
DECLARE_PER_CPU(struct update_util_data *, cpufreq_update_util_data);

static inline void cpufreq_trigger(u64 time, unsigned long util)
{
       struct update_util_data *data;

       data = rcu_dereference_sched(*this_cpu_ptr(&cpufreq_update_util_data));
       if (data)
               data->func(data, time, util, 0);
}
#else
static inline void cpufreq_trigger(u64 time, unsigned long util)
{
}
#endif /* CONFIG_CPU_FREQ */

#ifdef arch_scale_freq_capacity
#ifndef arch_scale_freq_invariant
#define arch_scale_freq_invariant()	(true)
#endif
#else /* arch_scale_freq_capacity */
#define arch_scale_freq_invariant()	(false)
#endif

static inline void account_reset_rq(struct rq *rq)
{
#ifdef CONFIG_IRQ_TIME_ACCOUNTING
	rq->prev_irq_time = 0;
#endif
#ifdef CONFIG_PARAVIRT
	rq->prev_steal_time = 0;
#endif
#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
	rq->prev_steal_time_rq = 0;
#endif
}

#endif /* BFS_SCHED_H */
