"""
Job Manager with Real Cancellation and SSE Progress
Manages scan jobs with proper cancellation tokens and streaming updates.
"""
import asyncio
import uuid
from datetime import datetime
from typing import AsyncGenerator, Callable, Any
from collections.abc import Coroutine

from schemas.report import ScanJob, ScanStatus, ScanReport


class CancellationToken:
    """Token for cooperative cancellation."""
    
    def __init__(self):
        self._cancelled = asyncio.Event()
    
    def cancel(self) -> None:
        """Request cancellation."""
        self._cancelled.set()
    
    def is_cancelled(self) -> bool:
        """Check if cancellation was requested."""
        return self._cancelled.is_set()
    
    async def wait_if_cancelled(self) -> None:
        """Raise if cancelled - use in async loops."""
        if self._cancelled.is_set():
            raise asyncio.CancelledError("Job was cancelled")
    
    def check(self) -> None:
        """Synchronous check - raises if cancelled."""
        if self._cancelled.is_set():
            raise asyncio.CancelledError("Job was cancelled")


class JobManager:
    """
    Manages scan jobs with:
    - Real cancellation via CancellationToken
    - SSE progress streaming
    - Job state persistence
    """
    
    def __init__(self):
        self._jobs: dict[str, ScanJob] = {}
        self._tokens: dict[str, CancellationToken] = {}
        self._reports: dict[str, ScanReport] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._subscribers: dict[str, list[asyncio.Queue]] = {}
    
    def create_job(self, project_path: str) -> tuple[str, CancellationToken]:
        """Create a new scan job and return (job_id, cancellation_token)."""
        job_id = f"scan_{uuid.uuid4().hex[:12]}"
        
        job = ScanJob(
            id=job_id,
            status=ScanStatus.PENDING,
        )
        
        token = CancellationToken()
        
        self._jobs[job_id] = job
        self._tokens[job_id] = token
        self._subscribers[job_id] = []
        
        return job_id, token
    
    def get_job(self, job_id: str) -> ScanJob | None:
        """Get job status."""
        return self._jobs.get(job_id)
    
    def get_token(self, job_id: str) -> CancellationToken | None:
        """Get cancellation token for a job."""
        return self._tokens.get(job_id)
    
    def get_report(self, job_id: str) -> ScanReport | None:
        """Get completed scan report."""
        return self._reports.get(job_id)
    
    async def start_job(
        self,
        job_id: str,
        scan_func: Callable[..., Coroutine[Any, Any, ScanReport]],
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Start a scan job in the background.

        `scan_func` is called as: `await scan_func(*args, job_id, token, self, **kwargs)`.
        This keeps backwards compatibility while allowing new scan parameters
        (e.g. `ruleset_path`) without having to rework the job manager.
        """
        job = self._jobs.get(job_id)
        token = self._tokens.get(job_id)
        
        if not job or not token:
            raise ValueError(f"Job not found: {job_id}")
        
        job.status = ScanStatus.RUNNING
        job.started_at = datetime.now()
        await self._notify_subscribers(job_id)
        
        async def run_scan():
            try:
                report = await scan_func(*args, job_id, token, self, **kwargs)
                job.status = ScanStatus.COMPLETED
                job.progress = 100.0
                job.completed_at = datetime.now()
                self._reports[job_id] = report
            except asyncio.CancelledError:
                job.status = ScanStatus.CANCELLED
                job.completed_at = datetime.now()
            except Exception as e:
                import traceback
                traceback.print_exc()
                job.status = ScanStatus.FAILED
                job.error = str(e)
                job.completed_at = datetime.now()
            finally:
                await self._notify_subscribers(job_id)
        
        task = asyncio.create_task(run_scan())
        self._tasks[job_id] = task
    
    async def cancel_job(self, job_id: str) -> bool:
        """Cancel a running scan job."""
        token = self._tokens.get(job_id)
        job = self._jobs.get(job_id)
        task = self._tasks.get(job_id)
        
        if not token or not job:
            return False
        
        if job.status != ScanStatus.RUNNING:
            return False
        
        # Signal cancellation
        token.cancel()
        
        # Also cancel the asyncio task if running
        if task and not task.done():
            task.cancel()
        
        return True
    
    async def update_progress(
        self,
        job_id: str,
        progress: float,
        phase: str = "",
        current_file: str | None = None,
        files_processed: int = 0,
        files_total: int = 0,
    ) -> None:
        """Update job progress (called by scanner)."""
        job = self._jobs.get(job_id)
        if not job:
            return
        
        job.progress = min(progress, 99.9)  # Reserve 100 for completion
        job.current_phase = phase
        job.current_file = current_file
        job.files_processed = files_processed
        job.files_total = files_total
        
        await self._notify_subscribers(job_id)
    
    async def _notify_subscribers(self, job_id: str) -> None:
        """Notify all SSE subscribers of job update."""
        job = self._jobs.get(job_id)
        if not job:
            return
        
        subscribers = self._subscribers.get(job_id, [])
        payload = job.model_dump_json()
        for queue in subscribers:
            try:
                # Keep only the freshest state per subscriber to avoid long
                # backlogs when progress updates are very frequent.
                if queue.full():
                    try:
                        queue.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                queue.put_nowait(payload)
            except Exception:
                pass  # Ignore failed subscribers
    
    async def subscribe(self, job_id: str) -> AsyncGenerator[str, None]:
        """Subscribe to job updates via SSE."""
        job = self._jobs.get(job_id)
        if not job:
            yield f"data: {{\"error\": \"Job not found\"}}\n\n"
            return
        
        # Latest-only queue prevents stale progress lag on large scans.
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1)
        self._subscribers.setdefault(job_id, []).append(queue)
        
        try:
            # Send initial state
            yield f"data: {job.model_dump_json()}\n\n"
            
            # Stream updates until job is done
            while job.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield f"data: {data}\n\n"
                    
                    # Check if job finished
                    job = self._jobs.get(job_id)
                    if not job or job.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
                        break
                except asyncio.TimeoutError:
                    # Send keepalive
                    yield f": keepalive\n\n"
            
            # Send final state
            if job:
                yield f"data: {job.model_dump_json()}\n\n"
        finally:
            # Cleanup subscriber
            if job_id in self._subscribers and queue in self._subscribers[job_id]:
                self._subscribers[job_id].remove(queue)
    
    def cleanup_job(self, job_id: str) -> None:
        """Remove job data (call after client has retrieved results)."""
        self._jobs.pop(job_id, None)
        self._tokens.pop(job_id, None)
        self._reports.pop(job_id, None)
        self._tasks.pop(job_id, None)
        self._subscribers.pop(job_id, None)


# Global instance
job_manager = JobManager()
