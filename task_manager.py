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
from models import db, Task as TaskModel, Workspace, get_or_create_workspace

logger = logging.getLogger(__name__)

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    PENDING_CONFIRMATION = "pending_confirmation"
    COMPLETED = "completed"
    FAILED = "failed"

class TaskManager:
    def __init__(self, max_workers=5, state_file="tasks_state.json"):
        self.tasks = {}                     
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.pending_queue = q.Queue()      
        self.futures = {}                  
        self._max_workers = max_workers
        self._load_state()

    def _load_state(self):
        """Load tasks from the database."""
        with self.lock:
            tasks = TaskModel.query.all()
            for task in tasks:
                self.tasks[task.task_id] = {
                    "id": task.task_id,
                    "user_id": task.user_id,
                    "workspace_id": task.workspace_id,
                    "provider": task.provider,
                    "model": task.model,
                    "messages": [], 
                    "mode": task.mode,
                    "target": task.target,
                    "use_rag": task.use_rag,
                    "status": TaskStatus(task.status),
                    "events": task.get_events(),
                    "result": task.result,
                    "error": task.error,
                    "created_at": task.created_at.isoformat(),
                    "updated_at": task.updated_at.isoformat(),
                    "resume_event": threading.Event(),
                    "pending_proposal": None,
                    "full_messages": None,
                    "iteration": 0,
                    "confirmed": False,
                    "plan": task.get_plan(),
                    "current_step": task.current_step,
                    "cancelled": False,
                    "tokens_used": task.tokens_used,
                }

    def create_task(self, user_id, workspace_id, provider, model, messages, mode, target, use_rag=False):
        task_id = str(uuid.uuid4())
        workspace = Workspace.query.filter_by(workspace_id=workspace_id, user_id=user_id).first()
        if not workspace:
            workspace = get_or_create_workspace(user_id, workspace_id)
        with self.lock:
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
        logger.info(f"{task_id} task id created ")
        db_task = TaskModel(
            task_id=task_id,
            user_id=user_id,
            workspace_id=workspace.id,  
            provider=provider,
            model=model,
            mode=mode,
            target=target,
            use_rag=use_rag,
            status=TaskStatus.PENDING.value,
            events='[]',
            plan=None,
            current_step=0
        )
        db.session.add(db_task)
        db.session.commit()
        db_task.workspace_id = workspace.id
        return task_id

    def get_task(self, task_id):
        with self.lock:
            return self.tasks.get(task_id)

    def update_task(self, task_id, **kwargs):
        with self.lock:
            if task_id in self.tasks:
                self.tasks[task_id].update(kwargs)
                self.tasks[task_id]["updated_at"] = datetime.utcnow().isoformat()
                db_task = TaskModel.query.filter_by(task_id=task_id).first()
                if db_task:
                    for key, value in kwargs.items():
                        if key == 'status':
                            db_task.status = value.value if hasattr(value, 'value') else value
                        elif key == 'events':
                            db_task.set_events(value)
                        elif key == 'plan':
                            db_task.set_plan(value)
                        elif key == 'result':
                            db_task.result = value
                        elif key == 'error':
                            db_task.error = value
                        elif key == 'current_step':
                            db_task.current_step = value
                        elif key == 'tokens_used':
                            db_task.tokens_used = value
                    db_task.updated_at = datetime.utcnow()
                    db.session.commit()

    def append_event(self, task_id, event_type, data):
        with self.lock:
            if task_id in self.tasks:
                self.tasks[task_id]["events"].append({"event": event_type, "data": data})
                self.tasks[task_id]["updated_at"] = datetime.utcnow().isoformat()
                

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
                return cancelled
            return False

    def get_queue_size(self):
        return self.pending_queue.qsize()

    def get_active_count(self):
        with self.lock:
            return sum(1 for f in self.futures.values() if f.running())

    def set_cancelled(self, task_id):
        with self.lock:
            if task_id in self.tasks:
                self.tasks[task_id]['cancelled'] = True

    def is_cancelled(self, task_id):
        task = self.get_task(task_id)
        if not task:
            return False
        return task.get('cancelled', False)
        
    def add_tokens(self, task_id, count):
        if task_id in self.tasks:
            self.tasks[task_id]['tokens_used'] = self.tasks[task_id].get('tokens_used', 0) + count

    def get_task(self, task_id):
        return self.tasks.get(task_id)
            
task_manager = TaskManager(max_workers=5, state_file="tasks_state.json")
