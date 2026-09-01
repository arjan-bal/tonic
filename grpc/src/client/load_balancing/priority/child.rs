/*
 *
 * Copyright 2026 gRPC authors.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use crate::client::load_balancing::DynLbPolicy;
use crate::client::load_balancing::LbPolicy;
use crate::client::load_balancing::LbPolicyBuilder;
use crate::client::load_balancing::LbPolicyOptions;
use crate::client::load_balancing::ParsedJsonLbConfig;
use crate::client::load_balancing::WorkScheduler;
use crate::client::load_balancing::priority::config::ChildConfig;
use crate::client::name_resolution::ResolverUpdate;
use crate::rt::BoxedTaskHandle;
use crate::rt::GrpcRuntime;

#[derive(Debug)]
pub(crate) struct ChildData {
    pub(crate) state: ChildState,
    pub(crate) child_config: ChildConfig,
    // TODO: Figure out how to intercept re-resolution requests from children.
}

pub(crate) struct Timer {
    pub(crate) deadline: Instant,
    pub(crate) task_handle: BoxedTaskHandle,
}

impl std::fmt::Debug for Timer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectingState")
            .field("deadline", &self.deadline)
            .finish()
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        self.task_handle.abort();
    }
}

impl Timer {
    pub(crate) fn new(
        duration: Duration,
        work_scheduler: Arc<dyn WorkScheduler>,
        rt: GrpcRuntime,
    ) -> Timer {
        let rt_clone = rt.clone();
        let task_handle = rt.spawn(Box::pin(async move {
            rt_clone.sleep(duration).await;
            work_scheduler.schedule_work(None);
        }));
        Timer {
            deadline: Instant::now() + duration,
            task_handle,
        }
    }
}

#[derive(Debug)]
pub(crate) enum ChildState {
    /// Child not part of child manager.
    Uninitialized(ResolverUpdate),
    /// Connection attempt started, timer running.
    Connecting(Timer),
    /// Connection timer expired, in Connecting or Transient Failure.
    Retrying,
    /// Idle or Ready.
    Steady,
    // Child present in child manager and cache.
    Deactivated(Timer),
}

#[derive(Debug)]
pub(crate) struct ChildBuilder {}

impl LbPolicyBuilder for ChildBuilder {
    type LbPolicy = Box<DynLbPolicy>;

    fn build(&self, options: LbPolicyOptions) -> Self::LbPolicy {
        todo!()
    }

    fn name(&self) -> &'static str {
        todo!()
    }

    fn parse_config(
        &self,
        _config: &ParsedJsonLbConfig,
    ) -> Result<Option<<Self::LbPolicy as LbPolicy>::LbConfig>, String> {
        Ok(None)
    }
}
