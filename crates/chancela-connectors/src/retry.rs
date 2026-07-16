use std::future::Future;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{CancellationToken, ConnectorError};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            initial_delay_ms: 250,
            max_delay_ms: 4_000,
        }
    }
}

pub async fn retry_operation<T, F, Fut>(
    policy: RetryPolicy,
    cancellation: &CancellationToken,
    mut operation: F,
) -> Result<(T, u32), ConnectorError>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<T, ConnectorError>>,
{
    let attempts = policy.max_attempts.clamp(1, 16);
    let mut delay = policy.initial_delay_ms.max(1);
    for attempt in 1..=attempts {
        cancellation.check()?;
        match operation(attempt).await {
            Ok(value) => return Ok((value, attempt)),
            Err(error) if error.is_retryable() && attempt < attempts => {
                let wait_ms = error
                    .retry_after_seconds
                    .map(|seconds| seconds.saturating_mul(1_000))
                    .unwrap_or(delay)
                    .min(policy.max_delay_ms.max(1));
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(wait_ms)) => {}
                    _ = wait_for_cancellation(cancellation) => return Err(ConnectorError::cancelled()),
                }
                delay = delay.saturating_mul(2).min(policy.max_delay_ms.max(1));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("attempt loop always returns")
}

async fn wait_for_cancellation(cancellation: &CancellationToken) {
    while !cancellation.is_cancelled() {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
