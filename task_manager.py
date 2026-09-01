# task_manager.py
import threading
import uuid
import queue as q
from enum import Enum
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, Future
import json
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    PENDING_CONFIRMATION = "pending_confirmation"
    COMPLETED = "completed"
    FAILED = "failed"

class TaskManager:
    def __init__(self, max_workers=5, state_file="tasks_state.json"):
        self.tasks = {}                     # task_id -> dict
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.pending_queue = q.Queue()      # optional, not used yet
        self.futures = {}                   # task_id -> Future
        self.state_file = Path(state_file)
        self._max_workers = max_workers
        self._load_state()

    def _save_state(self):
        """Save all tasks to disk."""
        logger.info(f"task SAVE_STATE func is called")
        task_id = str(uuid.uuid4())
        logger.info(f"saving started")
        state = {}
        logger.info(f"task: {task_id} saved to disk")
        for task_id, task in self.tasks.items():
            task_copy = task.copy()
            # Remove non‑serializable objects
            task_copy.pop("resume_event", None)
            task_copy["status"] = task_copy["status"].value
            state[task_id] = task_copy
            logger.info(f"saving done ")
        self.state_file.write_text(json.dumps(state, indent=2, default=str))

    def _load_state(self):
        """Restore tasks from disk if file exists."""
        if not self.state_file.exists():
            return
        try:
            data = json.loads(self.state_file.read_text())
            for task_id, task_data in data.items():
                task_data["status"] = TaskStatus(task_data["status"])
                task_data["resume_event"] = threading.Event()
                self.tasks[task_id] = task_data
        except Exception as e:
            logger.error(f"Failed to load task state: {e}")

    def create_task(self, user_id, workspace_id, provider, model, messages, mode, target, use_rag=False):
        task_id = str(uuid.uuid4())
        logger.info(f"creating task ...")
        with self.lock:
            logger.info(f"self lock")
            self.tasks[task_id] = {
                "id": task_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "provider": provider,
                "model": model,
                "messages": messages,
                "mode": mode,
                "target": target,
                "use_rag": use_rag,
                "status": TaskStatus.PENDING,
                "events": [],
                "result": None,
                "error": None,
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat(),
                "resume_event": threading.Event(),
                "pending_proposal": None,
                "full_messages": None,
                "iteration": 0,
                "confirmed": False,
                "plan": None,
                "current_step": 0,
                "cancelled": False,
            }
            logger.info(f"saving: {task_id} state")
            self._save_state()
            logger.info(f"saved: {task_id}")
        logger.info(f"{task_id} task id created ")
        return task_id

    def get_task(self, task_id):
        with self.lock:
            return self.tasks.get(task_id)

    def update_task(self, task_id, **kwargs):
        logger.info(f"upadte started..")
        with self.lock:
            if task_id in self.tasks:
                self.tasks[task_id].update(kwargs)
                self.tasks[task_id]["updated_at"] = datetime.utcnow().isoformat()
                self._save_state()
                logger.info(f"update finsished..")

    def append_event(self, task_id, event_type, data):
        with self.lock:
            if task_id in self.tasks:
                self.tasks[task_id]["events"].append({"event": event_type, "data": data})
                self.tasks[task_id]["updated_at"] = datetime.utcnow().isoformat()
                self._save_state()

    def wait_for_confirmation(self, task_id, timeout=None):
        task = self.get_task(task_id)
        if not task:
            return False
        event = task.get("resume_event")
        if not event:
            return False
        return event.wait(timeout)

    def submit_task(self, task_id, func, *args, **kwargs):
        future = self.executor.submit(func, *args, **kwargs)
        logger.info(f"sumtion of task started")
        with self.lock:
            self.futures[task_id] = future
            logger.info(f"task submited")
        return future

    def cancel_task(self, task_id):
        with self.lock:
            future = self.futures.get(task_id)
            if future and not future.done():
                cancelled = future.cancel()
                if cancelled:
                    self.tasks[task_id]["status"] = TaskStatus.FAILED
                    self.tasks[task_id]["error"] = "Cancelled by user"
                    self._save_state()
                return cancelled
            return False

    def get_queue_size(self):
        return self.pending_queue.qsize()

    def get_active_count(self):
        with self.lock:
            return sum(1 for f in self.futures.values() if f.running())

    def set_cancelled(self, task_id):
        """Mark a task as cancelled."""
        with self.lock:
            if task_id in self.tasks:
                self.tasks[task_id]['cancelled'] = True
                self._save_state()

    def is_cancelled(self, task_id):
        """Check if a task has been marked for cancellation."""
        task = self.get_task(task_id)
        if not task:
            return False
        return task.get('cancelled', False)
        
    def add_tokens(self, task_id, count):
        if task_id in self.tasks:
            self.tasks[task_id]['tokens_used'] = self.tasks[task_id].get('tokens_used', 0) + count

    def get_task(self, task_id):
        return self.tasks.get(task_id)
            
# Global instance
task_manager = TaskManager(max_workers=5, state_file="tasks_state.json")
