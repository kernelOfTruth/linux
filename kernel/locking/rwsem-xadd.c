/* rwsem.c: R/W semaphores: contention handling functions
 *
 * Written by David Howells (dhowells@redhat.com).
 * Derived from arch/i386/kernel/semaphore.c
 *
 * Writer lock-stealing by Alex Shi <alex.shi@intel.com>
 * and Michel Lespinasse <walken@google.com>
 *
 * Optimistic spinning by Tim Chen <tim.c.chen@intel.com>
 * and Davidlohr Bueso <davidlohr@hp.com>. Based on mutexes.
 */
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/sched/rt.h>

#include "mcs_spinlock.h"

/*
 * Guide to the rw_semaphore's count field for common values.
 * (32-bit case illustrated, similar for 64-bit)
 *
 * 0x0000000X	(1) X readers active or attempting lock, no writer waiting
 *		    X = #active_readers + #readers attempting to lock
 *		    (X*ACTIVE_BIAS)
 *
 * 0x00000000	rwsem is unlocked, and no one is waiting for the lock or
 *		attempting to read lock or write lock.
 *
 * 0xffff000X	(1) X readers active or attempting lock, with waiters for lock
 *		    X = #active readers + # readers attempting lock
 *		    (X*ACTIVE_BIAS + WAITING_BIAS)
 *		(2) 1 writer attempting lock, no waiters for lock
 *		    X-1 = #active readers + #readers attempting lock
 *		    ((X-1)*ACTIVE_BIAS + ACTIVE_WRITE_BIAS)
 *		(3) 1 writer active, no waiters for lock
 *		    X-1 = #active readers + #readers attempting lock
 *		    ((X-1)*ACTIVE_BIAS + ACTIVE_WRITE_BIAS)
 *
 * 0xffff0001	(1) 1 reader active or attempting lock, waiters for lock
 *		    (WAITING_BIAS + ACTIVE_BIAS)
 *		(2) 1 writer active or attempting lock, no waiters for lock
 *		    (ACTIVE_WRITE_BIAS)
 *
 * 0xffff0000	(1) There are writers or readers queued but none active
 *		    or in the process of attempting lock.
 *		    (WAITING_BIAS)
 *		Note: writer can attempt to steal lock for this count by adding
 *		ACTIVE_WRITE_BIAS in cmpxchg and checking the old count
 *
 * 0xfffe0001	(1) 1 writer active, or attempting lock. Waiters on queue.
 *		    (ACTIVE_WRITE_BIAS + WAITING_BIAS)
 *
 * Note: Readers attempt to lock by adding ACTIVE_BIAS in down_read and checking
 *	 the count becomes more than 0 for successful lock acquisition,
 *	 i.e. the case where there are only readers or nobody has lock.
 *	 (1st and 2nd case above).
 *
 *	 Writers attempt to lock by adding ACTIVE_WRITE_BIAS in down_write and
 *	 checking the count becomes ACTIVE_WRITE_BIAS for successful lock
 *	 acquisition (i.e. nobody else has lock or attempts lock).  If
 *	 unsuccessful, in rwsem_down_write_failed, we'll check to see if there
 *	 are only waiters but none active (5th case above), and attempt to
 *	 steal the lock.
 *
 */

/*
 * Initialize an rwsem:
 */
void __init_rwsem(struct rw_semaphore *sem, const char *name,
		  struct lock_class_key *key)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	/*
	 * Make sure we are not reinitializing a held semaphore:
	 */
	debug_check_no_locks_freed((void *)sem, sizeof(*sem));
	lockdep_init_map(&sem->dep_map, name, key, 0);
#endif
	sem->count = RWSEM_UNLOCKED_VALUE;
	raw_spin_lock_init(&sem->wait_lock);
	INIT_LIST_HEAD(&sem->wait_list);
#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
	sem->owner = NULL;
	osq_lock_init(&sem->osq);
#endif
}

EXPORT_SYMBOL(__init_rwsem);

enum rwsem_waiter_type {
	RWSEM_WAITING_FOR_WRITE,
	RWSEM_WAITING_FOR_READ
};

struct rwsem_waiter {
	struct list_head list;
	struct task_struct *task;
	enum rwsem_waiter_type type;
};

enum rwsem_wake_type {
	RWSEM_WAKE_ANY,		/* Wake whatever's at head of wait list */
	RWSEM_WAKE_READERS,	/* Wake readers only */
	RWSEM_WAKE_READ_OWNED	/* Waker thread holds the read lock */
};

#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
/*
 * return true if there is an active writer by checking the owner field which
 * should be set if there is one.
 */
static inline bool rwsem_has_active_writer(struct rw_semaphore *sem)
{
	struct task_struct *owner = ACCESS_ONCE(sem->owner);

	return owner != NULL;
}

/*
 * Return true if the rwsem has active spinner
 */
static inline bool rwsem_has_spinner(struct rw_semaphore *sem)
{
	return osq_is_locked(&sem->osq);
}
#else /* CONFIG_RWSEM_SPIN_ON_OWNER */
static inline bool rwsem_has_active_writer(struct rw_semaphore *sem)
{
	return false;	/* Assume it has no active writer */
}

static inline bool rwsem_has_spinner(struct rw_semaphore *sem)
{
	return false;
}
#endif /* CONFIG_RWSEM_SPIN_ON_OWNER */

/*
 * handle the lock release when processes blocked on it that can now run
 * - if we come here from up_xxxx(), then:
 *   - the 'active part' of count (&0x0000ffff) reached 0 (but may have changed)
 *   - the 'waiting part' of count (&0xffff0000) is -ve (and will still be so)
 * - there must be someone on the queue
 * - the spinlock must be held by the caller
 * - woken process blocks are discarded from the list after having task zeroed
 * - writers are only woken if downgrading is false
 */
static struct rw_semaphore *
__rwsem_do_wake(struct rw_semaphore *sem, enum rwsem_wake_type wake_type)
{
	struct rwsem_waiter *waiter;
	struct task_struct *tsk;
	struct list_head *next;
	long oldcount, woken, loop, adjustment;

	/*
	 * Abort the wakeup operation if there is an active writer as the
	 * lock was stolen. up_write() should have cleared the owner field
	 * before calling this function. If that field is now set, there must
	 * be an active writer present.
	 */
	if (rwsem_has_active_writer(sem))
		goto out;

	waiter = list_entry(sem->wait_list.next, struct rwsem_waiter, list);
	if (waiter->type == RWSEM_WAITING_FOR_WRITE) {
		if (wake_type == RWSEM_WAKE_ANY)
			/* Wake writer at the front of the queue, but do not
			 * grant it the lock yet as we want other writers
			 * to be able to steal it.  Readers, on the other hand,
			 * will block as they will notice the queued writer.
			 */
			wake_up_process(waiter->task);
		goto out;
	}

	/* Writers might steal the lock before we grant it to the next reader.
	 * We prefer to do the first reader grant before counting readers
	 * so we can bail out early if a writer stole the lock.
	 */
	adjustment = 0;
	if (wake_type != RWSEM_WAKE_READ_OWNED) {
		adjustment = RWSEM_ACTIVE_READ_BIAS;
 try_reader_grant:
		oldcount = rwsem_atomic_update(adjustment, sem) - adjustment;
		if (unlikely(oldcount < RWSEM_WAITING_BIAS)) {
			/* A writer stole the lock. Undo our reader grant. */
			if (rwsem_atomic_update(-adjustment, sem) &
						RWSEM_ACTIVE_MASK)
				goto out;
			/* Last active locker left. Retry waking readers. */
			goto try_reader_grant;
		}
	}

	/* Grant an infinite number of read locks to the readers at the front
	 * of the queue.  Note we increment the 'active part' of the count by
	 * the number of readers before waking any processes up.
	 */
	woken = 0;
	do {
		woken++;

		if (waiter->list.next == &sem->wait_list)
			break;

		waiter = list_entry(waiter->list.next,
					struct rwsem_waiter, list);

	} while (waiter->type != RWSEM_WAITING_FOR_WRITE);

	adjustment = woken * RWSEM_ACTIVE_READ_BIAS - adjustment;
	if (waiter->type != RWSEM_WAITING_FOR_WRITE)
		/* hit end of list above */
		adjustment -= RWSEM_WAITING_BIAS;

	if (adjustment)
		rwsem_atomic_add(adjustment, sem);

	next = sem->wait_list.next;
	loop = woken;
	do {
		waiter = list_entry(next, struct rwsem_waiter, list);
		next = waiter->list.next;
		tsk = waiter->task;
		smp_mb();
		waiter->task = NULL;
		wake_up_process(tsk);
		put_task_struct(tsk);
	} while (--loop);

	sem->wait_list.next = next;
	next->prev = &sem->wait_list;

 out:
	return sem;
}

static inline bool rwsem_try_write_lock(long count, struct rw_semaphore *sem)
{
	if (!(count & RWSEM_ACTIVE_MASK)) {
		/* try acquiring the write lock */
		if (sem->count == RWSEM_WAITING_BIAS &&
		    cmpxchg(&sem->count, RWSEM_WAITING_BIAS,
			    RWSEM_ACTIVE_WRITE_BIAS) == RWSEM_WAITING_BIAS) {
			if (!list_is_singular(&sem->wait_list))
				rwsem_atomic_update(RWSEM_WAITING_BIAS, sem);
			return true;
		}
	}
	return false;
}

#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
/*
 * Thresholds for optimistic spinning on readers
 *
 * This is the threshold for the number of spins that happens before the
 * spinner gives up when the owner field is NULL.
 */
#define SPIN_READ_THRESHOLD	64

/*
 * Try to acquire write lock before the writer has been put on wait queue.
 */
static inline bool rwsem_try_write_lock_unqueued(struct rw_semaphore *sem)
{
	long old, count = ACCESS_ONCE(sem->count);

	while (true) {
		if (!(count == 0 || count == RWSEM_WAITING_BIAS))
			return false;

		old = cmpxchg(&sem->count, count, count + RWSEM_ACTIVE_WRITE_BIAS);
		if (old == count)
			return true;

		count = old;
	}
}

/*
 * Try to acquire read lock
 *
 * There is ambiguity when RWSEM_WAITING_BIAS < count < 0 as a writer may
 * be active instead of having waiters. So we need to recheck the count
 * under wait_lock to be sure.
 */
static inline bool rwsem_try_read_lock_unqueued(struct rw_semaphore *sem)
{
	long old, count = ACCESS_ONCE(sem->count);
	bool taken = false;	/* True if lock taken */

	while (!taken) {
		if (count < RWSEM_WAITING_BIAS)
			break;	/* Have writer and waiter */

		old = count;
		if (count >= 0 || count == RWSEM_WAITING_BIAS) {
			count = cmpxchg(&sem->count, old,
					old + RWSEM_ACTIVE_READ_BIAS);
			if (count == old) {
				/* Got the read lock */
				taken = true;
				/*
				 * Try to wake up readers if lock is free
				 */
				if ((count == RWSEM_WAITING_BIAS) &&
				    raw_spin_trylock_irq(&sem->wait_lock)) {
					if (!list_empty(&sem->wait_list))
						goto wake_readers;
					raw_spin_unlock_irq(&sem->wait_lock);
				}
			}
		} else if (!rwsem_has_active_writer(sem)) {
			long threshold;

			/*
			 * RWSEM_WAITING_BIAS < count < 0
			 */
			raw_spin_lock_irq(&sem->wait_lock);
			threshold = list_empty(&sem->wait_list)
				  ? 0 : RWSEM_WAITING_BIAS;
			count = ACCESS_ONCE(sem->count);
			if (count < threshold) {
				raw_spin_unlock_irq(&sem->wait_lock);
				break;
			}
			old   = count;
			count = cmpxchg(&sem->count, old,
					old + RWSEM_ACTIVE_READ_BIAS);
			if (count == old) {
				taken = true;
				/*
				 * Wake up pending readers, if any,
				 * while holding the lock.
				 */
				if (threshold)
					goto wake_readers;
			}
			raw_spin_unlock_irq(&sem->wait_lock);
		} else {
			break;
		}
	}
	return taken;

wake_readers:
	__rwsem_do_wake(sem, RWSEM_WAKE_READ_OWNED);
	raw_spin_unlock_irq(&sem->wait_lock);
	return true;

}

/*
 * The defval argument controls whether true or false is returned
 * when the owner field is NULL.
 */
static inline bool
rwsem_can_spin_on_owner(struct rw_semaphore *sem, bool defval)
{
	struct task_struct *owner;
	bool on_cpu = defval;

	if (need_resched())
		return false;

	rcu_read_lock();
	owner = ACCESS_ONCE(sem->owner);
	if (owner)
		on_cpu = owner->on_cpu;
	rcu_read_unlock();

	/*
	 * If sem->owner is not set, yet we have just recently entered the
	 * slowpath, then there is a possibility reader(s) may have the lock.
	 * To be safe, avoid spinning in these situations.
	 */
	return on_cpu;
}

static inline bool owner_running(struct rw_semaphore *sem,
				 struct task_struct *owner)
{
	if (sem->owner != owner)
		return false;

	/*
	 * Ensure we emit the owner->on_cpu, dereference _after_ checking
	 * sem->owner still matches owner, if that fails, owner might
	 * point to free()d memory, if it still matches, the rcu_read_lock()
	 * ensures the memory stays valid.
	 */
	barrier();

	return owner->on_cpu;
}

static noinline
bool rwsem_spin_on_owner(struct rw_semaphore *sem, struct task_struct *owner)
{
	rcu_read_lock();
	while (owner_running(sem, owner)) {
		if (need_resched())
			break;

		arch_mutex_cpu_relax();
	}
	rcu_read_unlock();

	/*
	 * We break out the loop above on need_resched() or when the
	 * owner changed, which is a sign for heavy contention. Return
	 * success only when sem->owner is NULL.
	 */
	return sem->owner == NULL;
}

/*
 * With active writer, spinning is done by checking if that writer is on
 * CPU. With active readers, there is no easy way to determine if all of
 * them are active. So it falls back to spin a certain number of times
 * (SPIN_READ_THRESHOLD) before giving up. The threshold is relatively
 * small with the expectation that readers are quick. For slow readers,
 * the spinners will still fall back to sleep. On the other hand, it won't
 * waste too many cycles when the lock owning readers are not running.
 */
static bool rwsem_optimistic_spin(struct rw_semaphore *sem,
				  enum rwsem_waiter_type type)
{
	struct task_struct *owner;
	bool taken = false;
	int  spincnt = 0;

	/* sem->wait_lock should not be held when doing optimistic spinning */
	if (!rwsem_can_spin_on_owner(sem, true))
		return false;

	preempt_disable();

	if (!osq_lock(&sem->osq))
		goto done;

	while (true) {
		owner = ACCESS_ONCE(sem->owner);
		if (!owner) {
			/*
			 * Give up spinning if spincnt reaches the threshold.
			 */
			if (spincnt++ >= SPIN_READ_THRESHOLD)
				break;
		} else if (!rwsem_spin_on_owner(sem, owner)) {
			break;
		} else {
			/* Reset count when owner is defined */
			spincnt = 0;
		}

		taken = (type == RWSEM_WAITING_FOR_WRITE)
		      ? rwsem_try_write_lock_unqueued(sem)
		      : rwsem_try_read_lock_unqueued(sem);
		if (taken)
			break;

		/*
		 * When there's no owner, we might have preempted between the
		 * owner acquiring the lock and setting the owner field. If
		 * we're an RT task that will live-lock because we won't let
		 * the owner complete.
		 */
		if (!owner && (need_resched() || rt_task(current)))
			break;

		/*
		 * The cpu_relax() call is a compiler barrier which forces
		 * everything in this loop to be re-loaded. We don't need
		 * memory barriers as we'll eventually observe the right
		 * values at the cost of a few extra spins.
		 */
		arch_mutex_cpu_relax();
	}
	osq_unlock(&sem->osq);
done:
	preempt_enable();
	return taken;
}

#else
static bool rwsem_optimistic_spin(struct rw_semaphore *sem,
				  enum rwsem_waiter_type type)
{
	return false;
}

static inline bool
rwsem_can_spin_on_owner(struct rw_semaphore *sem, bool default)
{
	return false;
}
#endif

/*
 * Wait for the read lock to be granted
 */
__visible
struct rw_semaphore __sched * rwsem_down_read_failed(struct rw_semaphore *sem)
{
	long count, adjustment = 0;
	struct rwsem_waiter waiter;
	struct task_struct *tsk = current;

	/* undo read bias from down_read operation, stop active locking */
	count = rwsem_atomic_update(-RWSEM_ACTIVE_READ_BIAS, sem);

	/* do optimistic spinning and steal lock if possible */
	if (rwsem_optimistic_spin(sem, RWSEM_WAITING_FOR_READ))
		return sem;

	/*
	 * Optimistic spinning failed, proceed to the slowpath
	 * and block until we can acquire the sem.
	 */
	waiter.task = tsk;
	waiter.type = RWSEM_WAITING_FOR_READ;
	get_task_struct(tsk);

	raw_spin_lock_irq(&sem->wait_lock);
	if (list_empty(&sem->wait_list))
		adjustment += RWSEM_WAITING_BIAS;
	list_add_tail(&waiter.list, &sem->wait_list);

	/* we're now waiting on the lock */
	if (adjustment)
		count = rwsem_atomic_update(adjustment, sem);
	else
		count = ACCESS_ONCE(sem->count);

	/* If there are no active locks, wake the front queued process(es).
	 *
	 * If there are no writers and we are first in the queue,
	 * wake our own waiter to join the existing active readers !
	 */
	if (count == RWSEM_WAITING_BIAS ||
	   (count >  RWSEM_WAITING_BIAS && adjustment))
		sem = __rwsem_do_wake(sem, RWSEM_WAKE_ANY);

	raw_spin_unlock_irq(&sem->wait_lock);

	/* wait to be given the lock */
	while (true) {
		set_task_state(tsk, TASK_UNINTERRUPTIBLE);
		if (!waiter.task)
			break;
		schedule();
	}

	tsk->state = TASK_RUNNING;

	return sem;
}

/*
 * Wait until we successfully acquire the write lock
 */
__visible
struct rw_semaphore __sched *rwsem_down_write_failed(struct rw_semaphore *sem)
{
	long count;
	bool waiting; /* any queued threads before us */
	bool respin;
	struct rwsem_waiter waiter;

	/* undo write bias from down_write operation, stop active locking */
	count = rwsem_atomic_update(-RWSEM_ACTIVE_WRITE_BIAS, sem);

optspin:
	/* do optimistic spinning and steal lock if possible */
	if (rwsem_optimistic_spin(sem, RWSEM_WAITING_FOR_WRITE))
		return sem;

	/*
	 * Optimistic spinning failed, proceed to the slowpath
	 * and block until we can acquire the sem.
	 */
	waiter.task = current;
	waiter.type = RWSEM_WAITING_FOR_WRITE;

	raw_spin_lock_irq(&sem->wait_lock);

	/* account for this before adding a new element to the list */
	waiting = !list_empty(&sem->wait_list);

	list_add_tail(&waiter.list, &sem->wait_list);

	/* we're now waiting on the lock, but no longer actively locking */
	if (waiting) {
		count = ACCESS_ONCE(sem->count);

		/*
		 * If there were already threads queued before us and there are
		 * no active writers, the lock must be read owned; so we try to
		 * wake any read locks that were queued ahead of us.
		 */
		if (count > RWSEM_WAITING_BIAS)
			sem = __rwsem_do_wake(sem, RWSEM_WAKE_READERS);

	} else
		count = rwsem_atomic_update(RWSEM_WAITING_BIAS, sem);

	/* wait until we successfully acquire the lock */
	set_current_state(TASK_UNINTERRUPTIBLE);
	respin = false;
	while (!respin) {
		if (rwsem_try_write_lock(count, sem))
			break;
		raw_spin_unlock_irq(&sem->wait_lock);

		/*
		 * Block until there are no active lockers or optimistic
		 * spinning is possible.
		 */
		while (true) {
			schedule();
			set_current_state(TASK_UNINTERRUPTIBLE);
			count = ACCESS_ONCE(sem->count);
			if (!(count & RWSEM_ACTIVE_MASK))
				break;
			/*
			 * Go back to optimistic spinning if the lock
			 * owner is really running and there are spinners.
			 * If there is no spinner, the task is already at
			 * the head of the queue or the lock owner (maybe
			 * readers) may not be actually running.
			 */
			if (rwsem_has_spinner(sem) &&
			    rwsem_can_spin_on_owner(sem, false)) {
				respin = true;
				break;
			}
		}

		raw_spin_lock_irq(&sem->wait_lock);
	}
	__set_current_state(TASK_RUNNING);

	list_del(&waiter.list);
	if (respin && list_empty(&sem->wait_list))
		rwsem_atomic_update(-RWSEM_WAITING_BIAS, sem);
	raw_spin_unlock_irq(&sem->wait_lock);
	if (respin)
		goto optspin;

	return sem;
}

/*
 * handle waking up a waiter on the semaphore
 * - up_read/up_write has decremented the active part of count if we come here
 */
__visible
struct rw_semaphore *rwsem_wake(struct rw_semaphore *sem)
{
	unsigned long flags;

	/*
	 * If a spinner is present, it is not necessary to do the wakeup.
	 * Try to do wakeup when the trylock succeeds to avoid potential
	 * spinlock contention which may introduce too much delay in the
	 * unlock operation.
	 *
	 * In case the spinner is just going to break out of the loop, it
	 * will still do a trylock in rwsem_down_write_failed() before
	 * sleeping, or call __rwsem_do_wake() in rwsem_down_read_failed()
	 * if it detects a free lock. In either cases, we won't have the
	 * situation that the lock is free and no task is woken up from the
	 * waiting queue.
	 */
	if (rwsem_has_spinner(sem)) {
		if (!raw_spin_trylock_irqsave(&sem->wait_lock, flags))
			return sem;
	} else {
		raw_spin_lock_irqsave(&sem->wait_lock, flags);
	}

	/* do nothing if list empty */
	if (!list_empty(&sem->wait_list))
		sem = __rwsem_do_wake(sem, RWSEM_WAKE_ANY);

	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);

	return sem;
}

/*
 * downgrade a write lock into a read lock
 * - caller incremented waiting part of count and discovered it still negative
 * - just wake up any readers at the front of the queue
 */
__visible
struct rw_semaphore *rwsem_downgrade_wake(struct rw_semaphore *sem)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	/* do nothing if list empty */
	if (!list_empty(&sem->wait_list))
		sem = __rwsem_do_wake(sem, RWSEM_WAKE_READ_OWNED);

	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);

	return sem;
}

EXPORT_SYMBOL(rwsem_down_read_failed);
EXPORT_SYMBOL(rwsem_down_write_failed);
EXPORT_SYMBOL(rwsem_wake);
EXPORT_SYMBOL(rwsem_downgrade_wake);
