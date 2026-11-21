use std::cell::UnsafeCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::Thread;

use crate::error::VzError;

static PARALLELISM_CACHE: OnceLock<usize> = OnceLock::new();
static WORKER_POOL: OnceLock<WorkerPool> = OnceLock::new();

/// Returns cached `available_parallelism` (`>= 1`), avoiding repeated OS affinity queries.
#[inline]
pub(crate) fn cached_parallelism() -> usize {
    *PARALLELISM_CACHE.get_or_init(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .max(1)
    })
}

/// Computes bounded worker thread count so low-core CPUs and small workloads never pay
/// thread-spawn or synchronization overhead.
#[inline]
pub(crate) fn adaptive_workers(
    work_units: usize,
    total_bytes: usize,
    min_bytes_per_worker: usize,
) -> usize {
    if work_units < 2 {
        return 1;
    }
    let threshold = min_bytes_per_worker.max(1);
    if total_bytes < threshold.saturating_mul(2) {
        return 1;
    }
    cached_parallelism()
        .min(work_units)
        .min(total_bytes / threshold)
        .max(1)
}

#[repr(align(64))]
struct WorkerSlot {
    cmd_epoch: AtomicU64,
    job_fn: UnsafeCell<Option<unsafe fn(*const ())>>,
    job_ctx: UnsafeCell<*const ()>,
}

// SAFETY: `job_fn` and `job_ctx` are written exclusively by the coordinator holding `WorkerPool::in_use`
// prior to publishing a new `cmd_epoch` with `Release`, and read by the worker only after observing
// that `cmd_epoch` with `Acquire` and before decrementing `remaining_workers` with `Release`.
unsafe impl Send for WorkerSlot {}
unsafe impl Sync for WorkerSlot {}

struct WorkerPool {
    slots: Box<[Arc<WorkerSlot>]>,
    threads: Box<[Thread]>,
    in_use: AtomicBool,
    epoch: AtomicU64,
}

impl WorkerPool {
    fn new(worker_count: usize) -> Self {
        let mut slots = Vec::with_capacity(worker_count);
        let mut threads = Vec::with_capacity(worker_count);

        for idx in 0..worker_count {
            let slot = Arc::new(WorkerSlot {
                cmd_epoch: AtomicU64::new(0),
                job_fn: UnsafeCell::new(None),
                job_ctx: UnsafeCell::new(core::ptr::null()),
            });
            let slot_worker = Arc::clone(&slot);
            let spawn_res = std::thread::Builder::new()
                .name(format!("vz-worker-{idx}"))
                .spawn(move || worker_loop(slot_worker));
            match spawn_res {
                Ok(handle) => {
                    threads.push(handle.thread().clone());
                    slots.push(slot);
                }
                Err(_) => break,
            }
        }

        Self {
            slots: slots.into_boxed_slice(),
            threads: threads.into_boxed_slice(),
            in_use: AtomicBool::new(false),
            epoch: AtomicU64::new(0),
        }
    }
}

fn worker_loop(slot: Arc<WorkerSlot>) {
    let mut last_epoch = 0u64;
    loop {
        let mut epoch = slot.cmd_epoch.load(Ordering::Acquire);
        if epoch == last_epoch {
            for _ in 0..64 {
                core::hint::spin_loop();
                epoch = slot.cmd_epoch.load(Ordering::Acquire);
                if epoch != last_epoch {
                    break;
                }
            }
            while epoch == last_epoch {
                std::thread::park();
                epoch = slot.cmd_epoch.load(Ordering::Acquire);
            }
        }
        last_epoch = epoch;

        // SAFETY: The coordinator holds `in_use`, wrote `job_fn` and `job_ctx` before
        // `cmd_epoch.store(epoch, Release)`, and waits for `remaining_workers == 0` before
        // touching this slot again or dropping `JobContext`.
        let (job_fn, job_ctx) = unsafe { (*slot.job_fn.get(), *slot.job_ctx.get()) };
        if let Some(func) = job_fn {
            unsafe { func(job_ctx) };
        }
    }
}

#[inline]
fn worker_pool() -> &'static WorkerPool {
    WORKER_POOL.get_or_init(|| {
        let count = cached_parallelism().saturating_sub(1).min(63);
        WorkerPool::new(count)
    })
}

type InputSlot<T> = UnsafeCell<Option<T>>;
type OutputSlot<R> = UnsafeCell<Option<Result<R, VzError>>>;

struct JobContext<'a, T, R, F> {
    next_idx: AtomicUsize,
    remaining_workers: AtomicUsize,
    caller_thread: Thread,
    len: usize,
    f: &'a F,
    inputs: Box<[InputSlot<T>]>,
    outputs: Box<[OutputSlot<R>]>,
}

// SAFETY: Each index `0..len` is claimed by at most one thread via `next_idx.fetch_add(1, Relaxed)`,
// giving that thread exclusive access to `inputs[idx]` and `outputs[idx]`. Remaining fields use
// atomic synchronization or require `F: Sync` and `Thread: Sync`.
unsafe impl<T: Send, R: Send, F: Sync> Sync for JobContext<'_, T, R, F> {}

struct PoolGuard<'a> {
    pool: &'static WorkerPool,
    remaining: &'a AtomicUsize,
}

impl Drop for PoolGuard<'_> {
    fn drop(&mut self) {
        while self.remaining.load(Ordering::Acquire) != 0 {
            for _ in 0..64 {
                core::hint::spin_loop();
                if self.remaining.load(Ordering::Acquire) == 0 {
                    break;
                }
            }
            if self.remaining.load(Ordering::Acquire) == 0 {
                break;
            }
            std::thread::park();
        }
        self.pool.in_use.store(false, Ordering::Release);
    }
}

fn execute_work_stealing<T: Send, R: Send, F: Fn(T) -> Result<R, VzError> + Sync>(
    ctx: &JobContext<'_, T, R, F>,
) {
    loop {
        let idx = ctx.next_idx.fetch_add(1, Ordering::Relaxed);
        if idx >= ctx.len {
            break;
        }
        // SAFETY: `idx < ctx.len` was uniquely claimed by this thread.
        let item_opt = unsafe { (*ctx.inputs[idx].get()).take() };
        let res = match item_opt {
            Some(item) => match catch_unwind(AssertUnwindSafe(|| (ctx.f)(item))) {
                Ok(r) => r,
                Err(_) => Err(VzError::IoError),
            },
            None => Err(VzError::IoError),
        };
        // SAFETY: Only this thread ever writes `outputs[idx]` before `remaining_workers` hits 0.
        unsafe {
            *ctx.outputs[idx].get() = Some(res);
        }
    }
}

unsafe fn worker_trampoline<T: Send, R: Send, F: Fn(T) -> Result<R, VzError> + Sync>(
    ctx_ptr: *const (),
) {
    // SAFETY: Coordinator guarantees `ctx_ptr` points to a live `JobContext<T, R, F>` until
    // `remaining_workers` reaches zero.
    let ctx = unsafe { &*ctx_ptr.cast::<JobContext<'_, T, R, F>>() };
    // Clone `Thread` handle before decrementing `remaining_workers` so `unpark()` never touches `ctx`.
    let caller = ctx.caller_thread.clone();
    let remaining = &ctx.remaining_workers;
    let _ = catch_unwind(AssertUnwindSafe(|| {
        execute_work_stealing(ctx);
    }));
    if remaining.fetch_sub(1, Ordering::Release) == 1 {
        caller.unpark();
    }
}

fn run_inline<T, R, F>(items: Vec<T>, f: &F) -> Result<Vec<R>, VzError>
where
    F: Fn(T) -> Result<R, VzError>,
{
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let res = match catch_unwind(AssertUnwindSafe(|| f(item))) {
            Ok(r) => r,
            Err(_) => Err(VzError::IoError),
        };
        out.push(res?);
    }
    Ok(out)
}

/// Applies fallible closure `f` across `items` using up to `max_workers` threads (including caller)
/// from the persistent worker pool, preserving output order.
///
/// Falls back cleanly to inline execution for trivial work, single-core hosts, nested calls, or
/// concurrent callers without thread spawning or deadlocks.
pub(crate) fn par_try_map<T, R, F>(
    items: Vec<T>,
    max_workers: usize,
    f: F,
) -> Result<Vec<R>, VzError>
where
    T: Send,
    R: Send,
    F: Fn(T) -> Result<R, VzError> + Sync,
{
    let len = items.len();
    if len <= 1 || max_workers <= 1 || cached_parallelism() <= 1 {
        return run_inline(items, &f);
    }

    let pool = worker_pool();
    if pool.slots.is_empty()
        || pool
            .in_use
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
    {
        return run_inline(items, &f);
    }

    let helper_count = max_workers.min(len).saturating_sub(1).min(pool.slots.len());
    if helper_count == 0 {
        pool.in_use.store(false, Ordering::Release);
        return run_inline(items, &f);
    }

    let prev_epoch = pool.epoch.load(Ordering::Relaxed);
    let mut next_epoch = prev_epoch.wrapping_add(1);
    if next_epoch == 0 {
        next_epoch = 1;
    }
    pool.epoch.store(next_epoch, Ordering::Relaxed);

    let inputs: Box<[InputSlot<T>]> = items
        .into_iter()
        .map(|it| UnsafeCell::new(Some(it)))
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let outputs: Box<[OutputSlot<R>]> = (0..len)
        .map(|_| UnsafeCell::new(None))
        .collect::<Vec<_>>()
        .into_boxed_slice();

    // Declare `ctx` strictly before `_guard` inside the dispatch scope so `_guard` is always
    // dropped first (waits for all helpers and releases `pool.in_use`), even on panic/unwind.
    let ctx = JobContext {
        next_idx: AtomicUsize::new(0),
        remaining_workers: AtomicUsize::new(helper_count),
        caller_thread: std::thread::current(),
        len,
        f: &f,
        inputs,
        outputs,
    };

    {
        let _guard = PoolGuard {
            pool,
            remaining: &ctx.remaining_workers,
        };
        let ctx_ptr = (&ctx as *const JobContext<'_, T, R, F>).cast::<()>();
        for i in 0..helper_count {
            let slot = &pool.slots[i];
            // SAFETY: We hold `pool.in_use`; worker `i` is idle until `cmd_epoch` advances.
            unsafe {
                *slot.job_fn.get() = Some(worker_trampoline::<T, R, F>);
                *slot.job_ctx.get() = ctx_ptr;
            }
            slot.cmd_epoch.store(next_epoch, Ordering::Release);
            pool.threads[i].unpark();
        }
        execute_work_stealing(&ctx);
    }

    let mut out = Vec::with_capacity(len);
    for slot in &ctx.outputs {
        // SAFETY: All helpers finished and `_guard` dropped before reading `outputs`.
        let cell_val = unsafe { (*slot.get()).take() };
        match cell_val {
            Some(Ok(v)) => out.push(v),
            Some(Err(e)) => return Err(e),
            None => return Err(VzError::IoError),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    static POOL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_par_try_map_ordering_and_trivial_cases() {
        let _guard = POOL_TEST_LOCK.lock().unwrap();
        let empty: Vec<usize> = par_try_map(Vec::<usize>::new(), 8, |x| Ok(x * 2)).unwrap();
        assert!(empty.is_empty());

        let single = par_try_map(vec![21usize], 8, |x| Ok(x * 2)).unwrap();
        assert_eq!(single, vec![42]);

        let input: Vec<usize> = (0..128).collect();
        let output = par_try_map(input, 8, |x| Ok(x * 3 + 1)).unwrap();
        let expected: Vec<usize> = (0..128).map(|x| x * 3 + 1).collect();
        assert_eq!(output, expected);
    }

    #[test]
    fn test_par_try_map_borrowed_mut_slices_and_error_propagation() {
        let _guard = POOL_TEST_LOCK.lock().unwrap();
        let mut bufs = vec![vec![0u8; 64]; 16];
        let refs: Vec<(usize, &mut [u8])> =
            bufs.iter_mut().map(Vec::as_mut_slice).enumerate().collect();
        par_try_map(refs, 4, |(idx, slice)| {
            slice.fill(idx as u8);
            Ok(())
        })
        .unwrap();
        for (idx, b) in bufs.iter().enumerate() {
            assert!(b.iter().all(|&v| v == idx as u8));
        }

        let err = par_try_map((0usize..32).collect(), 4, |i| {
            if i == 17 {
                Err(VzError::BadFormat)
            } else {
                Ok(i)
            }
        });
        assert_eq!(err, Err(VzError::BadFormat));
    }

    #[test]
    fn test_par_try_map_nested_and_concurrent_callers_no_deadlock() {
        let _guard = POOL_TEST_LOCK.lock().unwrap();
        let outer: Vec<Vec<usize>> = par_try_map((0usize..8).collect(), 4, |g| {
            let inner_items: Vec<usize> = (0..8).map(|i| g * 10 + i).collect();
            par_try_map(inner_items, 4, |x| Ok(x + 1))
        })
        .unwrap();
        for (g, row) in outer.iter().enumerate() {
            let expected: Vec<usize> = (0..8).map(|i| g * 10 + i + 1).collect();
            assert_eq!(row, &expected);
        }

        let results: Vec<Vec<usize>> = std::thread::scope(|s| {
            let handles: Vec<_> = (0usize..6)
                .map(|t| {
                    s.spawn(move || {
                        let items: Vec<usize> = (0..64).map(|i| t * 1000 + i).collect();
                        par_try_map(items, 4, |x| Ok(x * 2)).unwrap()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        for (t, row) in results.iter().enumerate() {
            let expected: Vec<usize> = (0..64).map(|i| (t * 1000 + i) * 2).collect();
            assert_eq!(row, &expected);
        }
    }

    #[test]
    fn test_par_try_map_panic_containment_and_pool_reuse() {
        let _guard = POOL_TEST_LOCK.lock().unwrap();
        let res = par_try_map((0usize..64).collect(), 4, |i| {
            if i == 31 {
                panic!("intentional worker panic test");
            }
            Ok(i)
        });
        assert_eq!(res, Err(VzError::IoError));

        // Pool must remain clean and reusable immediately after panic containment.
        let reused = par_try_map((0usize..32).collect(), 4, |i| Ok(i + 5)).unwrap();
        let expected: Vec<usize> = (5usize..37).collect();
        assert_eq!(reused, expected);
    }
}
