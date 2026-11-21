use std::sync::OnceLock;

static PARALLELISM_CACHE: OnceLock<usize> = OnceLock::new();

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
