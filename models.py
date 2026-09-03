# models.py
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import json

db = SQLAlchemy()

def get_or_create_workspace(user_id, workspace_id):
    user = User.query.filter_by(username=username).first()
    if not user:
        raise ValueError("User not found")
    workspace = Workspace.query.filter_by(user_id=user.id, workspace_id=workspace_id).first()
    if not workspace:
        workspace = Workspace(workspace_id=workspace_id, name=workspace_id, user_id=user.id)
        db.session.add(workspace)
        db.session.commit()
    return workspace


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    workspaces = db.relationship('Workspace', backref='owner', lazy='dynamic')
    tasks = db.relationship('Task', backref='user', lazy='dynamic')
    chat_messages = db.relationship('ChatMessage', backref='user', lazy='dynamic')
    
    def get_id(self):
        return str(self.id) 

class PendingUser(db.Model):
    __tablename__ = 'pending_users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    confirmed = db.Column(db.Boolean, default=False)

class Workspace(db.Model):
    __tablename__ = 'workspaces'
    
    id = db.Column(db.Integer, primary_key=True)
    workspace_id = db.Column(db.String(255), unique=True, nullable=False)  
    name = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    chat_messages = db.relationship('ChatMessage', backref='workspace', lazy='dynamic')
    session_memories = db.relationship('SessionMemory', backref='workspace', uselist=False)
    memory_entries = db.relationship('MemoryEntry', backref='workspace', lazy='dynamic')

class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'
    
    id = db.Column(db.Integer, primary_key=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspaces.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False)  
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class SessionMemory(db.Model):
    __tablename__ = 'session_memories'
    
    id = db.Column(db.Integer, primary_key=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspaces.id'), unique=True, nullable=False)
    executed_commands = db.Column(db.Text, default='[]')  
    current_phase = db.Column(db.String(50), default='reconnaissance')
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def get_commands(self):
        return json.loads(self.executed_commands)
    
    def set_commands(self, commands):
        self.executed_commands = json.dumps(commands)

class MemoryEntry(db.Model):
    __tablename__ = 'memory_entries'
    
    id = db.Column(db.Integer, primary_key=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspaces.id'), nullable=False)
    tool = db.Column(db.String(100), nullable=False)
    args = db.Column(db.Text)
    result = db.Column(db.Text)
    user_query = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class Task(db.Model):
    __tablename__ = 'tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.String(36), unique=True, nullable=False)  # UUID
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspaces.id'), nullable=False)
    
    provider = db.Column(db.String(50))
    model = db.Column(db.String(100))
    mode = db.Column(db.String(20))
    target = db.Column(db.String(255))
    use_rag = db.Column(db.Boolean, default=False)
    
    status = db.Column(db.String(30), default='pending')  
    events = db.Column(db.Text, default='[]')  
    result = db.Column(db.Text)
    error = db.Column(db.Text)
    
    plan = db.Column(db.Text) 
    current_step = db.Column(db.Integer, default=0)
    tokens_used = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def get_events(self):
        return json.loads(self.events)
    
    def set_events(self, events):
        self.events = json.dumps(events)
    
    def get_plan(self):
        return json.loads(self.plan) if self.plan else None
    
    def set_plan(self, plan):
        self.plan = json.dumps(plan)

class LLMProvider(db.Model):
    __tablename__ = 'llm_providers'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(20), default='openai')
    url = db.Column(db.String(255))
    api_key = db.Column(db.String(255))
    enabled = db.Column(db.Boolean, default=True)

class MCPServer(db.Model):
    __tablename__ = 'mcp_servers'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    config = db.Column(db.Text, nullable=False)  # JSON
    enabled = db.Column(db.Boolean, default=True)

class Script(db.Model):
    __tablename__ = 'scripts'
    
    id = db.Column(db.Integer, primary_key=True)
    script_id = db.Column(db.String(36), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    type = db.Column(db.String(20), default='custom')
    code = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_run = db.Column(db.DateTime)

class ScrapedData(db.Model):
    __tablename__ = 'scraped_data'
    
    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.String(36), unique=True, nullable=False)
    script_id = db.Column(db.String(36))
    url = db.Column(db.String(500))
    summary = db.Column(db.Text)
    data = db.Column(db.Text)
    preview = db.Column(db.Text)
    destination = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)