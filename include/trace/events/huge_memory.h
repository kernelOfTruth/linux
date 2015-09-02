#undef TRACE_SYSTEM
#define TRACE_SYSTEM huge_memory

#if !defined(__HUGE_MEMORY_H) || defined(TRACE_HEADER_MULTI_READ)
#define __HUGE_MEMORY_H

#include  <linux/tracepoint.h>

TRACE_EVENT(mm_khugepaged_scan_pmd,

	TP_PROTO(struct mm_struct *mm, unsigned long vm_start, bool writable,
		bool referenced, int none_or_zero, int collapse, int unmapped),

	TP_ARGS(mm, vm_start, writable, referenced, none_or_zero, collapse, unmapped),

	TP_STRUCT__entry(
		__field(struct mm_struct *, mm)
		__field(unsigned long, vm_start)
		__field(bool, writable)
		__field(bool, referenced)
		__field(int, none_or_zero)
		__field(int, collapse)
		__field(int, unmapped)
	),

	TP_fast_assign(
		__entry->mm = mm;
		__entry->vm_start = vm_start;
		__entry->writable = writable;
		__entry->referenced = referenced;
		__entry->none_or_zero = none_or_zero;
		__entry->collapse = collapse;
		__entry->unmapped = unmapped;
	),

	TP_printk("mm=%p, vm_start=%04lx, writable=%d, referenced=%d, none_or_zero=%d, collapse=%d, unmapped=%d",
		__entry->mm,
		__entry->vm_start,
		__entry->writable,
		__entry->referenced,
		__entry->none_or_zero,
		__entry->collapse,
		__entry->unmapped)
);

TRACE_EVENT(mm_collapse_huge_page,

	TP_PROTO(struct mm_struct *mm, unsigned long vm_start, int isolated),

	TP_ARGS(mm, vm_start, isolated),

	TP_STRUCT__entry(
		__field(struct mm_struct *, mm)
		__field(unsigned long, vm_start)
		__field(int, isolated)
	),

	TP_fast_assign(
		__entry->mm = mm;
		__entry->vm_start = vm_start;
		__entry->isolated = isolated;
	),

	TP_printk("mm=%p, vm_start=%04lx, isolated=%d",
		__entry->mm,
		__entry->vm_start,
		__entry->isolated)
);

TRACE_EVENT(mm_collapse_huge_page_isolate,

	TP_PROTO(unsigned long vm_start, int none_or_zero,
		bool referenced, bool  writable),

	TP_ARGS(vm_start, none_or_zero, referenced, writable),

	TP_STRUCT__entry(
		__field(unsigned long, vm_start)
		__field(int, none_or_zero)
		__field(bool, referenced)
		__field(bool, writable)
	),

	TP_fast_assign(
		__entry->vm_start = vm_start;
		__entry->none_or_zero = none_or_zero;
		__entry->referenced = referenced;
		__entry->writable = writable;
	),

	TP_printk("vm_start=%04lx, none_or_zero=%d, referenced=%d, writable=%d",
		__entry->vm_start,
		__entry->none_or_zero,
		__entry->referenced,
		__entry->writable)
);

TRACE_EVENT(mm_collapse_huge_page_swapin,

	TP_PROTO(struct mm_struct *mm, unsigned long vm_start, int swap_pte),

	TP_ARGS(mm, vm_start, swap_pte),

	TP_STRUCT__entry(
		__field(struct mm_struct *, mm)
		__field(unsigned long, vm_start)
		__field(int, swap_pte)
	),

	TP_fast_assign(
		__entry->mm = mm;
		__entry->vm_start = vm_start;
		__entry->swap_pte = swap_pte;
	),

	TP_printk("mm=%p, vm_start=%04lx, swap_pte=%d",
		__entry->mm,
		__entry->vm_start,
		__entry->swap_pte)
);

#endif /* __HUGE_MEMORY_H */
#include <trace/define_trace.h>
