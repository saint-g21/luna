"""
Database module for storing command executions, caching, knowledge entries,
false positive patterns, CVE cache, and session memory.
"""

import json
import logging
import hashlib
import re
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from sqlalchemy import create_engine, func, Column, String, Integer, Float, DateTime, Text, Boolean
from sqlalchemy.orm import sessionmaker, scoped_session, declarative_base

Base = declarative_base()
logger = logging.getLogger(__name__)

# ----------------- Database Models -----------------

class CommandExecution(Base):
    __tablename__ = 'command_executions'
    id = Column(Integer, primary_key=True)
    tool_name = Column(String)
    command = Column(Text)
    parameters = Column(Text)  # JSON string
    target = Column(String)
    session_id = Column(String)
    success = Column(Boolean)
    stdout = Column(Text)
    stderr = Column(Text)
    return_code = Column(Integer)
    timed_out = Column(Boolean)
    partial_results = Column(Boolean)
    execution_time = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)
    false_positive = Column(Boolean, default=False)
    false_positive_reason = Column(Text)
    actual_vulnerability = Column(Boolean, default=True)
    encrypted = Column(Boolean, default=False)

class KnowledgeEntry(Base):
    __tablename__ = 'knowledge_entries'
    id = Column(Integer, primary_key=True)
    category = Column(String)
    key = Column(String)
    value = Column(Text)
    confidence = Column(Float)
    source = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

class FalsePositivePattern(Base):
    __tablename__ = 'false_positive_patterns'
    id = Column(Integer, primary_key=True)
    tool = Column(String)
    pattern = Column(Text)
    description = Column(Text)
    times_matched = Column(Integer, default=0)

class CommandCache(Base):
    __tablename__ = 'command_cache'
    id = Column(Integer, primary_key=True)
    tool_name = Column(String)
    command_hash = Column(String, unique=True, index=True)
    command = Column(Text)
    parameters = Column(Text)
    target = Column(String)
    stdout = Column(Text)
    stderr = Column(Text)
    return_code = Column(Integer)
    success = Column(Boolean)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_accessed = Column(DateTime, default=datetime.utcnow)
    access_count = Column(Integer, default=0)
    ttl_seconds = Column(Integer, default=3600)
    encrypted = Column(Boolean, default=False)

class ExpectedOutputPattern(Base):
    __tablename__ = 'expected_output_patterns'
    id = Column(Integer, primary_key=True)
    tool_name = Column(String)
    pattern = Column(Text)
    pattern_type = Column(String)  # 'regex' or 'literal'
    outcome = Column(String)       # 'vulnerability', 'false_positive', 'info'
    description = Column(Text)
    confidence = Column(Float)
    times_matched = Column(Integer, default=0)

class CVECache(Base):
    __tablename__ = 'cve_cache'
    id = Column(Integer, primary_key=True)
    keyword = Column(String, index=True)
    result_json = Column(Text)     # JSON array of CVEs
    created_at = Column(DateTime, default=datetime.utcnow)
    ttl_hours = Column(Integer, default=24)

# NEW: Session memory for conversation history
class SessionMemory(Base):
    __tablename__ = 'session_memory'
    id = Column(Integer, primary_key=True)
    session_id = Column(String, index=True)
    role = Column(String)          # 'user', 'assistant', 'tool'
    content = Column(Text)
    tool_name = Column(String, nullable=True)
    tool_call_id = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)  # TTL for memory entries

# ----------------- Database Class -----------------

class KnowledgeDB:
    def __init__(self, db_path="knowledge.db", encryption_enabled=False, cipher=None):
        self.engine = create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(self.engine)
        self.Session = scoped_session(sessionmaker(bind=self.engine))
        self.encryption_enabled = encryption_enabled
        self.cipher = cipher

    @contextmanager
    def session_scope(self):
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ---------- Command Logging ----------
    def log_command(self, tool_name: str, command: str, parameters: dict,
                    target: str, session_id: str, success: bool,
                    stdout: str, stderr: str, return_code: int,
                    timed_out: bool, partial_results: bool,
                    execution_time: float, encrypted: bool = False) -> int:
        with self.session_scope() as session:
            exec_record = CommandExecution(
                tool_name=tool_name,
                command=command,
                parameters=json.dumps(parameters),
                target=target,
                session_id=session_id,
                success=success,
                stdout=stdout,
                stderr=stderr,
                return_code=return_code,
                timed_out=timed_out,
                partial_results=partial_results,
                execution_time=execution_time,
                encrypted=encrypted
            )
            session.add(exec_record)
            session.flush()
            return exec_record.id

    def get_similar_commands(self, tool_name: str, target: str, limit=5):
        with self.session_scope() as session:
            return session.query(CommandExecution).filter(
                CommandExecution.tool_name == tool_name,
                CommandExecution.target == target
            ).order_by(CommandExecution.timestamp.desc()).limit(limit).all()

    def get_most_effective_commands(self, tool_name: str, limit=10):
        with self.session_scope() as session:
            return session.query(CommandExecution).filter(
                CommandExecution.tool_name == tool_name,
                CommandExecution.success == True,
                CommandExecution.actual_vulnerability == True
            ).order_by(CommandExecution.timestamp.desc()).limit(limit).all()

    def mark_false_positive(self, execution_id: int, reason: str):
        with self.session_scope() as session:
            exec_record = session.query(CommandExecution).get(execution_id)
            if exec_record:
                exec_record.false_positive = True
                exec_record.false_positive_reason = reason

    # ---------- False Positive Patterns ----------
    def add_false_positive_pattern(self, tool: str, pattern: str, description: str):
        with self.session_scope() as session:
            existing = session.query(FalsePositivePattern).filter_by(
                tool=tool, pattern=pattern
            ).first()
            if existing:
                existing.times_matched += 1
            else:
                session.add(FalsePositivePattern(
                    tool=tool,
                    pattern=pattern,
                    description=description
                ))

    def check_false_positive(self, tool: str, output: str) -> Optional[str]:
        with self.session_scope() as session:
            patterns = session.query(FalsePositivePattern).filter_by(tool=tool).all()
            for pattern in patterns:
                if pattern.pattern in output:
                    pattern.times_matched += 1
                    session.commit()
                    return pattern.description
        return None

    # ---------- Knowledge Entries ----------
    def get_knowledge(self, category: str, key: str) -> Optional[str]:
        with self.session_scope() as session:
            entry = session.query(KnowledgeEntry).filter_by(category=category, key=key).first()
            return entry.value if entry else None

    def set_knowledge(self, category: str, key: str, value: str, confidence=1.0, source="auto"):
        with self.session_scope() as session:
            entry = session.query(KnowledgeEntry).filter_by(category=category, key=key).first()
            if entry:
                entry.value = value
                entry.confidence = confidence
                entry.source = source
                entry.timestamp = datetime.utcnow()
            else:
                session.add(KnowledgeEntry(
                    category=category, key=key, value=value,
                    confidence=confidence, source=source
                ))

    # ---------- Command Caching ----------
    def _hash_command(self, tool_name: str, command: str, params: dict) -> str:
        data = json.dumps({"tool": tool_name, "cmd": command, "params": params}, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()

    def get_cached_result(self, tool_name: str, command: str, params: dict) -> Optional[Dict]:
        cmd_hash = self._hash_command(tool_name, command, params)
        with self.session_scope() as session:
            cache = session.query(CommandCache).filter_by(
                tool_name=tool_name, command_hash=cmd_hash
            ).first()
            if not cache:
                return None
            if datetime.utcnow() - cache.created_at > timedelta(seconds=cache.ttl_seconds):
                return None
            cache.access_count += 1
            cache.last_accessed = datetime.utcnow()
            session.commit()
            stdout = cache.stdout
            stderr = cache.stderr
            if cache.encrypted and self.cipher:
                from crypto_utils import decrypt_value
                stdout = decrypt_value(self.cipher, stdout)
                stderr = decrypt_value(self.cipher, stderr)
            return {
                "stdout": stdout,
                "stderr": stderr,
                "return_code": cache.return_code,
                "success": cache.success,
                "from_cache": True
            }

    def store_cached_result(self, tool_name: str, command: str, params: dict,
                            result: Dict, ttl_seconds: int = 3600, encrypted: bool = False):
        cmd_hash = self._hash_command(tool_name, command, params)
        with self.session_scope() as session:
            existing = session.query(CommandCache).filter_by(command_hash=cmd_hash).first()
            stdout = result.get("stdout", "")
            stderr = result.get("stderr", "")
            if existing:
                existing.stdout = stdout
                existing.stderr = stderr
                existing.return_code = result.get("return_code", -1)
                existing.success = result.get("success", False)
                existing.created_at = datetime.utcnow()
                existing.encrypted = encrypted
            else:
                session.add(CommandCache(
                    tool_name=tool_name,
                    command_hash=cmd_hash,
                    command=command,
                    parameters=json.dumps(params),
                    target=params.get("target") or params.get("url") or "",
                    stdout=stdout,
                    stderr=stderr,
                    return_code=result.get("return_code", -1),
                    success=result.get("success", False),
                    ttl_seconds=ttl_seconds,
                    encrypted=encrypted
                ))

    def clear_cache(self, tool_name: str = None, older_than_hours: int = None):
        with self.session_scope() as session:
            query = session.query(CommandCache)
            if tool_name:
                query = query.filter_by(tool_name=tool_name)
            if older_than_hours:
                cutoff = datetime.utcnow() - timedelta(hours=older_than_hours)
                query = query.filter(CommandCache.created_at < cutoff)
            query.delete()
            session.commit()

    def get_cache_stats(self) -> Dict:
        with self.session_scope() as session:
            total = session.query(CommandCache).count()
            by_tool = session.query(CommandCache.tool_name, func.count()).group_by(CommandCache.tool_name).all()
            return {"total_entries": total, "by_tool": dict(by_tool)}

    # ---------- Expected Output Patterns ----------
    def match_expected_pattern(self, tool_name: str, output: str) -> Optional[Dict]:
        with self.session_scope() as session:
            patterns = session.query(ExpectedOutputPattern).filter_by(tool_name=tool_name).all()
            for p in patterns:
                if p.pattern_type == 'regex':
                    if re.search(p.pattern, output, re.IGNORECASE):
                        p.times_matched += 1
                        session.commit()
                        return {"outcome": p.outcome, "description": p.description, "confidence": p.confidence}
                else:
                    if p.pattern in output:
                        p.times_matched += 1
                        session.commit()
                        return {"outcome": p.outcome, "description": p.description, "confidence": p.confidence}
        return None

    def add_expected_pattern(self, tool: str, pattern: str, pattern_type: str, outcome: str, description: str, confidence: float):
        with self.session_scope() as session:
            session.add(ExpectedOutputPattern(
                tool_name=tool, pattern=pattern, pattern_type=pattern_type,
                outcome=outcome, description=description, confidence=confidence
            ))

    # ---------- CVE Caching ----------
    def get_cached_cve(self, keyword: str) -> Optional[List[Dict]]:
        with self.session_scope() as session:
            cache = session.query(CVECache).filter_by(keyword=keyword).first()
            if not cache:
                return None
            if datetime.utcnow() - cache.created_at > timedelta(hours=cache.ttl_hours):
                return None
            return json.loads(cache.result_json)

    def cache_cve_result(self, keyword: str, cves: List[Dict], ttl_hours: int = 24):
        with self.session_scope() as session:
            existing = session.query(CVECache).filter_by(keyword=keyword).first()
            if existing:
                existing.result_json = json.dumps(cves)
                existing.created_at = datetime.utcnow()
                existing.ttl_hours = ttl_hours
            else:
                session.add(CVECache(
                    keyword=keyword,
                    result_json=json.dumps(cves),
                    ttl_hours=ttl_hours
                ))

    # ---------- NEW: Session Memory ----------
    def add_session_memory(self, session_id: str, role: str, content: str,
                           tool_name: str = None, tool_call_id: str = None,
                           ttl_hours: int = 168) -> int:
        """Store a conversation turn in session memory with expiration."""
        expires_at = datetime.utcnow() + timedelta(hours=ttl_hours)
        with self.session_scope() as session:
            mem = SessionMemory(
                session_id=session_id,
                role=role,
                content=content,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                expires_at=expires_at
            )
            session.add(mem)
            session.flush()
            return mem.id

    def get_session_memory(self, session_id: str, limit: int = 50) -> List[Dict]:
        """Retrieve recent conversation history for a session."""
        with self.session_scope() as session:
            now = datetime.utcnow()
            memories = session.query(SessionMemory).filter(
                SessionMemory.session_id == session_id,
                SessionMemory.expires_at > now
            ).order_by(SessionMemory.timestamp.asc()).limit(limit).all()
            return [
                {
                    "role": m.role,
                    "content": m.content,
                    "tool_name": m.tool_name,
                    "tool_call_id": m.tool_call_id
                }
                for m in memories
            ]

    def clear_session_memory(self, session_id: str):
        """Delete all memory for a session."""
        with self.session_scope() as session:
            session.query(SessionMemory).filter_by(session_id=session_id).delete()
