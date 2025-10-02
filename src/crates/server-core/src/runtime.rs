//! Multi-threaded Async Runtime
//!
//! Implements efficient async runtime architecture with:
//! - Work-stealing thread pools (Tokio)
//! - Isolated thread pools for different workload types
//! - CPU core-based thread pool sizing
//! - Runtime metrics and monitoring
//!
//! Complies with SERVER_REQUIREMENTS F-01.03 and PR-14.1

use crate::error::ServerError;
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};

/// Thread pool configuration
#[derive(Debug, Clone)]
pub struct ThreadPoolConfig {
    /// Number of worker threads (0 = auto-detect based on CPU cores)
    pub worker_threads: usize,

    /// Maximum blocking threads for blocking operations
    pub max_blocking_threads: usize,

    /// Thread stack size in bytes
    pub thread_stack_size: usize,

    /// Thread name prefix
    pub thread_name: String,
}

impl Default for ThreadPoolConfig {
    fn default() -> Self {
        let cpu_cores = num_cpus::get();
        Self {
            worker_threads: cpu_cores,
            max_blocking_threads: 512,
            thread_stack_size: 2 * 1024 * 1024, // 2MB
            thread_name: "norc-worker".to_string(),
        }
    }
}

/// Workload type for thread pool isolation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkloadType {
    /// Network I/O operations (accept, read, write)
    NetworkIO,

    /// Cryptographic operations (encrypt, decrypt, sign, verify)
    Crypto,

    /// Business logic and message processing
    Business,

    /// Background tasks (cleanup, monitoring)
    Background,
}

/// Multi-threaded async runtime manager
pub struct AsyncRuntime {
    /// Main runtime for general tasks
    main_runtime: Arc<Runtime>,

    /// Dedicated runtime for network I/O
    network_runtime: Arc<Runtime>,

    /// Dedicated runtime for cryptographic operations
    crypto_runtime: Arc<Runtime>,

    /// Dedicated runtime for background tasks
    background_runtime: Arc<Runtime>,

    /// Runtime metrics
    metrics: Arc<RuntimeMetrics>,
}

impl AsyncRuntime {
    /// Create a new async runtime with isolated thread pools
    pub fn new(config: &norc_config::ResourceLimits) -> Result<Self, ServerError> {
        let cpu_cores = num_cpus::get();

        // Determine worker thread counts based on CPU cores
        let worker_threads = if config.worker_threads == 0 {
            cpu_cores
        } else {
            config.worker_threads
        };

        eprintln!(
            "Initializing async runtime with {} CPU cores detected",
            cpu_cores
        );
        eprintln!("Worker threads: {}", worker_threads);

        // Main runtime: 50% of cores for general tasks
        let main_workers = (worker_threads / 2).max(1);
        let main_runtime = Self::build_runtime("norc-main", main_workers, 512)?;
        eprintln!("Main runtime: {} workers", main_workers);

        // Network I/O runtime: 30% of cores for network operations
        let network_workers = ((worker_threads * 3) / 10).max(1);
        let network_runtime = Self::build_runtime("norc-network", network_workers, 256)?;
        eprintln!("Network runtime: {} workers", network_workers);

        // Crypto runtime: 15% of cores for cryptographic operations
        let crypto_workers = ((worker_threads * 15) / 100).max(1);
        let crypto_runtime = Self::build_runtime("norc-crypto", crypto_workers, 128)?;
        eprintln!("Crypto runtime: {} workers", crypto_workers);

        // Background runtime: 5% of cores for background tasks
        let background_workers = ((worker_threads * 5) / 100).max(1);
        let background_runtime = Self::build_runtime("norc-background", background_workers, 64)?;
        eprintln!("Background runtime: {} workers", background_workers);

        let metrics = Arc::new(RuntimeMetrics::new());

        Ok(Self {
            main_runtime: Arc::new(main_runtime),
            network_runtime: Arc::new(network_runtime),
            crypto_runtime: Arc::new(crypto_runtime),
            background_runtime: Arc::new(background_runtime),
            metrics,
        })
    }

    /// Build a Tokio runtime with specific configuration
    fn build_runtime(
        name: &str,
        worker_threads: usize,
        max_blocking_threads: usize,
    ) -> Result<Runtime, ServerError> {
        Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .max_blocking_threads(max_blocking_threads)
            .thread_name(name)
            .thread_stack_size(2 * 1024 * 1024) // 2MB stack
            .enable_all() // Enable I/O and time drivers
            .build()
            .map_err(|e| ServerError::Internal(format!("Failed to build runtime: {}", e)))
    }

    /// Get runtime handle for specific workload type
    pub fn get_handle(&self, workload: WorkloadType) -> tokio::runtime::Handle {
        match workload {
            WorkloadType::NetworkIO => self.network_runtime.handle().clone(),
            WorkloadType::Crypto => self.crypto_runtime.handle().clone(),
            WorkloadType::Business => self.main_runtime.handle().clone(),
            WorkloadType::Background => self.background_runtime.handle().clone(),
        }
    }

    /// Spawn a task on the appropriate runtime
    pub fn spawn<F>(&self, workload: WorkloadType, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.metrics.increment_spawned(workload);

        match workload {
            WorkloadType::NetworkIO => self.network_runtime.spawn(future),
            WorkloadType::Crypto => self.crypto_runtime.spawn(future),
            WorkloadType::Business => self.main_runtime.spawn(future),
            WorkloadType::Background => self.background_runtime.spawn(future),
        }
    }

    /// Spawn a blocking task on the appropriate runtime
    pub fn spawn_blocking<F, R>(&self, workload: WorkloadType, f: F) -> tokio::task::JoinHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        self.metrics.increment_blocking_spawned(workload);

        match workload {
            WorkloadType::NetworkIO => self.network_runtime.spawn_blocking(f),
            WorkloadType::Crypto => self.crypto_runtime.spawn_blocking(f),
            WorkloadType::Business => self.main_runtime.spawn_blocking(f),
            WorkloadType::Background => self.background_runtime.spawn_blocking(f),
        }
    }

    /// Block on a future using the main runtime
    pub fn block_on<F: std::future::Future>(&self, future: F) -> F::Output {
        self.main_runtime.block_on(future)
    }

    /// Get runtime metrics
    pub fn metrics(&self) -> &RuntimeMetrics {
        &self.metrics
    }

    /// Shutdown all runtimes gracefully
    pub fn shutdown(self) {
        eprintln!("Shutting down async runtimes...");

        // Drop the Arc references to allow shutdown
        drop(self.main_runtime);
        drop(self.network_runtime);
        drop(self.crypto_runtime);
        drop(self.background_runtime);

        eprintln!("Async runtimes shutdown complete");
    }
}

/// Runtime metrics for monitoring
pub struct RuntimeMetrics {
    /// Number of tasks spawned per workload type
    tasks_spawned: std::sync::atomic::AtomicU64,

    /// Number of blocking tasks spawned per workload type
    blocking_tasks_spawned: std::sync::atomic::AtomicU64,
}

impl RuntimeMetrics {
    fn new() -> Self {
        Self {
            tasks_spawned: std::sync::atomic::AtomicU64::new(0),
            blocking_tasks_spawned: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn increment_spawned(&self, _workload: WorkloadType) {
        self.tasks_spawned
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn increment_blocking_spawned(&self, _workload: WorkloadType) {
        self.blocking_tasks_spawned
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get total tasks spawned
    pub fn tasks_spawned(&self) -> u64 {
        self.tasks_spawned
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get total blocking tasks spawned
    pub fn blocking_tasks_spawned(&self) -> u64 {
        self.blocking_tasks_spawned
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use norc_config::ResourceLimits;

    #[test]
    fn test_runtime_creation() {
        let limits = ResourceLimits {
            max_connections: 1000,
            max_message_size: 1024 * 1024,
            rate_limit_per_connection: 100,
            max_memory_per_connection: 1024 * 1024,
            worker_threads: 0, // Auto-detect
        };

        let runtime = AsyncRuntime::new(&limits);
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_spawn_task() {
        let limits = ResourceLimits {
            max_connections: 1000,
            max_message_size: 1024 * 1024,
            rate_limit_per_connection: 100,
            max_memory_per_connection: 1024 * 1024,
            worker_threads: 4,
        };

        let runtime = AsyncRuntime::new(&limits).unwrap();

        // Spawn a simple task
        let handle = runtime.spawn(WorkloadType::Business, async { 42 });

        let result = runtime.block_on(handle).unwrap();
        assert_eq!(result, 42);
    }

    #[test]
    fn test_spawn_blocking() {
        let limits = ResourceLimits {
            max_connections: 1000,
            max_message_size: 1024 * 1024,
            rate_limit_per_connection: 100,
            max_memory_per_connection: 1024 * 1024,
            worker_threads: 4,
        };

        let runtime = AsyncRuntime::new(&limits).unwrap();

        // Spawn a blocking task
        let handle = runtime.spawn_blocking(WorkloadType::Crypto, || {
            // Simulate CPU-intensive work
            std::thread::sleep(std::time::Duration::from_millis(10));
            100
        });

        let result = runtime.block_on(handle).unwrap();
        assert_eq!(result, 100);
    }

    #[test]
    fn test_metrics() {
        let limits = ResourceLimits {
            max_connections: 1000,
            max_message_size: 1024 * 1024,
            rate_limit_per_connection: 100,
            max_memory_per_connection: 1024 * 1024,
            worker_threads: 4,
        };

        let runtime = AsyncRuntime::new(&limits).unwrap();

        let initial_tasks = runtime.metrics().tasks_spawned();

        runtime.spawn(WorkloadType::NetworkIO, async {});
        runtime.spawn(WorkloadType::Crypto, async {});

        assert_eq!(runtime.metrics().tasks_spawned(), initial_tasks + 2);
    }
}
