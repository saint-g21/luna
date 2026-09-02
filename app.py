#!/usr/bin/env python3
"""
Moonshot Agent – Full Stack Web UI (Enhanced)
Supports HTTP/SSE and stdio MCP servers, auto‑discovery of tools,
and admin‑confirmed signup.
"""

import os
import sys
import json
import re
import yaml
import requests
import bcrypt
import chromadb
import subprocess
import resource
import tempfile
import shutil
import uuid
import time
import secrets
import shlex
import ast
import logging
import tiktoken
from pathlib import Path
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, Response, stream_with_context, session, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from flask_cors import CORS
from pyngrok import ngrok
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sentence_transformers import SentenceTransformer
import PyPDF2
import pandas as pd
import threading
import queue
from mcp_router import init_router, router_bp, tool_rate_limiter
from task_manager import task_manager, TaskStatus 
from extensions import limiter
from collections import defaultdict
from flask_wtf.csrf import CSRFProtect

# ---------- Configuration ----------
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(24)),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16 MB upload limit
)
csrf = CSRFProtect(app)
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('CSRF_SECRET_KEY', os.urandom(24))
CORS(app, resources={r"/api/*": {"origins": "*"}, r"/mcp/*": {"origins": "*"}})

# ---------- Rate Limiting ----------
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
limiter.init_app(app)

# ---------- Logging ----------
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# ---------- Paths ----------
MCP_SERVERS_FILE = Path("mcp_servers.json")
LLM_PROVIDERS_FILE = Path("llm_providers.json")
PLAYBOOKS_DIR = Path("playbooks")
PROMPTS_DIR = Path("prompts")
KNOWLEDGE_DIR = Path("knowledge")
VECTOR_STORE_DIR = Path("vector_store")
SCRIPTS_DIR = Path("scripts")
SCRIPTS_META_FILE = SCRIPTS_DIR / "scripts_meta.json"
SCRAPED_DATA_DIR = Path("scraped_data")
SCRAPED_META_FILE = SCRAPED_DATA_DIR / "runs_meta.json"
USERS_DIR = Path("users")
PENDING_USERS_FILE = Path("pending_users.json")
USERS_FILE = Path("users.json")
PENTEST_API_KEY = os.environ.get("PENTEST_API_KEY", "")
TOOL_SERVER_MAP = {}
TOOL_SERVER_LOCK = threading.Lock()

# After creating the app, before any request handling:
router = init_router("mcp_servers.json")   # initializes all servers and discovers tools
app.register_blueprint(router_bp)

@app.before_request
def require_login():
    # Skip for login, signup, static files, and health (if public)
    public_endpoints = ['login', 'signup', 'static', 'health']
    if request.endpoint and request.endpoint in public_endpoints:
        return
    if request.path.startswith('/login') or request.path.startswith('/signup'):
        return
    if request.path.startswith('/static'):
        return
    # Require authentication for all other routes
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

for d in [KNOWLEDGE_DIR, PLAYBOOKS_DIR, PROMPTS_DIR, VECTOR_STORE_DIR, SCRIPTS_DIR, SCRAPED_DATA_DIR, USERS_DIR]:
    d.mkdir(exist_ok=True)

if not SCRIPTS_META_FILE.exists():
    with open(SCRIPTS_META_FILE, "w") as f:
        json.dump([], f)
if not SCRAPED_META_FILE.exists():
    with open(SCRAPED_META_FILE, "w") as f:
        json.dump([], f)

def discover_all_tools():
    global TOOL_SERVER_MAP
    tools = router.list_tools()
    for item in tools:
        TOOL_SERVER_MAP[item['name']] = item['server']
    logger.info(f"Discovered tools via router: {TOOL_SERVER_MAP}")
           
def extract_json_object(text: str):
    """
    Extract the first valid JSON object from a string, handling markdown fences.
    """
    # Remove any markdown code fences (``` or ```json) entirely
    text = re.sub(r'```(?:json)?\s*', '', text)   # remove opening fences
    text = re.sub(r'```\s*', '', text)            # remove all closing fences
    # Remove any leading/trailing whitespace
    text = text.strip()
    
    # Find the first '{'
    start = text.find('{')
    if start == -1:
        return None
    
    # Find the matching '}' using a stack, respecting strings
    brace_count = 0
    in_string = False
    escape = False
    end = start
    for i, ch in enumerate(text[start:], start):
        if escape:
            escape = False
            continue
        if ch == '\\':
            escape = True
            continue
        if ch == '"' and not escape:
            in_string = not in_string
            continue
        if not in_string:
            if ch == '{':
                brace_count += 1
            elif ch == '}':
                brace_count -= 1
                if brace_count == 0:
                    end = i
                    break
    if brace_count != 0:
        return None  # unbalanced braces
    
    candidate = text[start:end+1]
    
    # Try to parse as JSON
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        # Fix common issues: single quotes, trailing commas
        candidate = candidate.replace("'", '"')
        candidate = re.sub(r',(\s*[}\]])', r'\1', candidate)
        try:
            return json.loads(candidate)
        except:
            return None
            
# ---------- Authentication ----------
class User(UserMixin):
    def __init__(self, username):
        self.id = username
'''       
class ToolRateLimiter:
    def __init__(self):
        self.records = defaultdict(list)  # key: (user, tool), value: list of timestamps

    def is_allowed(self, user, tool, max_calls, period_seconds):
        key = (user, tool)
        now = time.time()
        self.records[key] = [ts for ts in self.records[key] if ts > now - period_seconds]
        if len(self.records[key]) >= max_calls:
            return False
        self.records[key].append(now)
        return True

tool_rate_limiter = ToolRateLimiter()
'''
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(stored, provided):
    try:
        return bcrypt.checkpw(provided.encode(), stored.encode())
    except ValueError:
        return False

def load_users():
    if not USERS_FILE.exists():
        admin_pw = os.environ.get('ADMIN_PASSWORD')
        if not admin_pw:
            admin_pw = secrets.token_urlsafe(16)
            logger.info(f"*** Generated admin password: {admin_pw} ***")
            print(f"*** Admin password generated: {admin_pw} ***")
        default = {"saint": hash_password(admin_pw)}
        with open(USERS_FILE, "w") as f:
            json.dump(default, f)
        return default
    with open(USERS_FILE) as f:
        return json.load(f)

def load_pending_users():
    if not PENDING_USERS_FILE.exists():
        return {}
    with open(PENDING_USERS_FILE) as f:
        return json.load(f)

def save_pending_users(data):
    with open(PENDING_USERS_FILE, "w") as f:
        json.dump(data, f, indent=2)

users_db = load_users()
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    if user_id in users_db:
        return User(user_id)
    return None

# ---------- Workspace functions (unchanged) ----------
def get_user_dir(username):
    user_dir = USERS_DIR / username
    user_dir.mkdir(exist_ok=True)
    return user_dir

def get_user_workspaces_dir(username):
    workspace_dir = get_user_dir(username) / "workspaces"
    workspace_dir.mkdir(exist_ok=True)
    return workspace_dir

def get_workspace_dir(username, workspace_id):
    return get_user_workspaces_dir(username) / workspace_id

def get_workspace_chat_file(username, workspace_id):
    return get_workspace_dir(username, workspace_id) / "chat_history.json"

def load_chat_history(username, workspace_id):
    filepath = get_workspace_chat_file(username, workspace_id)
    if filepath.exists():
        with open(filepath) as f:
            return json.load(f)
    return []

def save_chat_history(username, workspace_id, history):
    filepath = get_workspace_chat_file(username, workspace_id)
    safe_join(get_workspace_dir(username, workspace_id).mkdir(exist_ok=True))
    with open(filepath, "w") as f:
        json.dump(history, f)

def delete_chat_history(username, workspace_id):
    filepath = get_workspace_chat_file(username, workspace_id)
    if filepath.exists():
        filepath.unlink()
    mem_file = safe_join(get_workspace_dir(username, workspace_id) / "session_memory.json")
    if mem_file.exists():
        mem_file.unlink()
    save_chat_history(username, workspace_id, [])

def get_workspace_session_memory(username, workspace_id):
    mem_file = safe_join(get_workspace_dir(username, workspace_id) / "session_memory.json")
    if mem_file.exists():
        with open(mem_file) as f:
            return json.load(f)
    return {"executed_commands": [], "current_phase": "reconnaissance"}

def save_workspace_session_memory(username, workspace_id, memory):
    mem_file = safe_join(get_workspace_dir(username, workspace_id) / "session_memory.json")
    safe_join(get_workspace_dir(username, workspace_id).mkdir(exist_ok=True))
    with open(mem_file, "w") as f:
        json.dump(memory, f)

def list_workspaces(username):
    workspace_dir = get_user_workspaces_dir(username)
    workspaces = []
    for d in workspace_dir.iterdir():
        if d.is_dir():
            meta_file = d / "meta.json"
            name = d.name
            if meta_file.exists():
                try:
                    meta = json.loads(meta_file.read_text())
                    name = meta.get("name", d.name)
                except Exception:
                    pass
            workspaces.append({"id": d.name, "name": name})
    return workspaces
    
# ---------- Workspace Memory ----------
def get_workspace_memory_file(username, workspace_id):
    return get_workspace_dir(username, workspace_id) / "memory.json"

def load_workspace_memory(username, workspace_id, limit=50):
    """Return a list of memory entries (most recent first)."""
    mem_file = get_workspace_memory_file(username, workspace_id)
    if not mem_file.exists():
        return []
    try:
        data = json.loads(mem_file.read_text())
        # Ensure it's a list
        if not isinstance(data, list):
            return []
        # sort by timestamp descending (most recent first)
        data.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return data[:limit]
    except (json.JSONDecodeError, OSError):
        return []

def append_workspace_memory(username, workspace_id, tool, args, result, user_query=None):
    """Append a structured entry to memory, and add to vector store if embedder available."""
    mem_file = get_workspace_memory_file(username, workspace_id)
    entries = []
    if mem_file.exists():
        try:
            entries = json.loads(mem_file.read_text())
            if not isinstance(entries, list):
                entries = []
        except:
            entries = []
    entry = {
        "timestamp": datetime.now().isoformat(),
        "tool": tool,
        "args": args,
        "result": result[:2000]
    }
    entries.append(entry)
    if len(entries) > 100:
        entries = entries[-100:]
    mem_file.write_text(json.dumps(entries, indent=2))

    # --- Vector Store ---
    if EMBEDDER_AVAILABLE:
        # Create a searchable text: tool + args + result
        text_to_embed = f"Tool: {tool}\nArgs: {json.dumps(args)}\nResult: {result[:500]}"
        # Generate ID based on timestamp and tool
        entry_id = f"{username}_{workspace_id}_{datetime.now().timestamp()}"
        embedding = embedder.encode([text_to_embed]).tolist()[0]
        # Include username and workspace as metadata for filtering
        metadata = {
            "username": username,
            "workspace": workspace_id,
            "tool": tool,
            "timestamp": entry["timestamp"]
        }
        # We'll store the full result in the document field for retrieval
        memory_collection.add(
            ids=[entry_id],
            embeddings=[embedding],
            documents=[text_to_embed],
            metadatas=[metadata]
        )
 
def retrieve_similar_memories(query, username, workspace_id, n_results=3):
    """Retrieve similar past actions from the vector store for this workspace."""
    if not EMBEDDER_AVAILABLE:
        return []
    try:
        query_embedding = embedder.encode([query]).tolist()[0]
        results = memory_collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results,
            # Filter by workspace and username to avoid cross-contamination
            where={"$and": [{"workspace": workspace_id}, {"username": username}]}
        )
        if results['documents'] and results['documents'][0]:
            return results['documents'][0]  # list of text snippets
        return []
    except Exception as e:
        logger.error(f"Vector memory retrieval failed: {e}")
        return []
               
def summarize_conversation(messages, provider="kaggle", model="llama3.1:8b"):
    """Summarize a list of messages into a compact paragraph."""
    if not messages:
        return ""
    
    # Build a prompt for summarization
    conversation_text = "\n".join([f"{m['role']}: {m['content']}" for m in messages])
    prompt = f"""Summarize the following conversation between a user and an AI penetration testing assistant.
Focus on: what the user asked, what tools were run, and what key findings were discovered.
Keep it under 300 words.

Conversation:
{conversation_text}

Summary:"""
    
    summary_messages = [{"role": "user", "content": prompt}]
    summary = call_llm(provider, model, summary_messages)
    if summary is None:
        # Fallback: just truncate
        return conversation_text[:500] + "..."
    return summary.strip()

def resume_pending_tasks():
    """Check for any tasks that were running before restart and resume them."""
    for task_id, task in list(task_manager.tasks.items()):
        status = task.get('status')
        if status in (TaskStatus.PENDING, TaskStatus.RUNNING, TaskStatus.PENDING_CONFIRMATION):
            logger.info(f"Resuming task {task_id} (status: {status.value})")
            # Reconstruct the arguments for run_llm_loop
            def resume_work(tid=task_id):
                # Re-run the loop with the saved state
                run_llm_loop(
                    tid,
                    task['provider'],
                    task['model'],
                    task['messages'],
                    task['mode'],
                    task['workspace_id'],
                    task['target'],
                    task.get('use_rag', False)
                )
            task_manager.submit_task(task_id, resume_work)

# ---------- RAG ----------
chroma_client = chromadb.PersistentClient(path=str(VECTOR_STORE_DIR))
collection = chroma_client.get_or_create_collection("knowledge")
memory_collection = chroma_client.get_or_create_collection("workspace_memory")
try:
    embedder = SentenceTransformer('all-MiniLM-L6-v2')
    EMBEDDER_AVAILABLE = True
except Exception as e:
    logger.warning(f"SentenceTransformer not loaded: {e}")
    embedder = None
    EMBEDDER_AVAILABLE = False

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'json', 'csv', 'md'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_file(filepath):
    ext = filepath.suffix.lower()
    if ext in {'.txt', '.md'}:
        return filepath.read_text(encoding='utf-8')
    elif ext == '.pdf':
        with open(filepath, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            return "\n".join([page.extract_text() for page in reader.pages if page.extract_text()])
    elif ext == '.json':
        return json.dumps(json.loads(filepath.read_text()))
    elif ext == '.csv':
        df = pd.read_csv(filepath)
        return df.to_string()
    return ""

# ---------- Sandbox (enhanced) ----------
DANGEROUS_MODULES = {'os', 'subprocess', 'socket', 'shutil', 'sys', 'requests', 'urllib', 'ftplib', 'telnetlib', 'pickle', 'marshal'}

def is_code_dangerous(code):
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    module = alias.name.split('.')[0]
                    if module in DANGEROUS_MODULES:
                        return True
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {'exec', 'eval', '__import__'}:
                    return True
        return False
    except SyntaxError:
        return True

def run_script_safe(code, args=None, timeout=30, env_vars=None):
    if is_code_dangerous(code):
        return {'stdout': '', 'stderr': 'Script blocked: contains dangerous modules or functions.', 'returncode': -1, 'timeout': False}

    with tempfile.TemporaryDirectory() as tmpdir:
        script_path = Path(tmpdir) / "script.py"
        script_path.write_text(code)
        safe_env = {
            'PATH': '/usr/local/bin:/usr/bin:/bin',
            'HOME': tmpdir,
            'TMP': tmpdir,
            'TEMP': tmpdir,
            'PYTHONUNBUFFERED': '1',
            'PYTHONDONTWRITEBYTECODE': '1'
        }
        if env_vars:
            safe_env.update(env_vars)
        for var in ['HTTP_PROXY', 'HTTPS_PROXY', 'FTP_PROXY', 'NO_PROXY']:
            safe_env.pop(var, None)

        python_cmd = shutil.which('pypy3') or shutil.which('python3') or 'python3'
        cmd = [python_cmd, str(script_path)]
        if args:
            cmd.extend(args)

        def limit_resources():
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout+5))
                resource.setrlimit(resource.RLIMIT_AS, (200 * 1024 * 1024, 250 * 1024 * 1024))
                resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 20 * 1024 * 1024))
                resource.setrlimit(resource.RLIMIT_NPROC, (20, 20))
            except (resource.error, AttributeError):
                pass

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    preexec_fn=limit_resources if os.name == 'posix' else None,
                                    text=True, env=safe_env, cwd=tmpdir)
            stdout, stderr = proc.communicate(timeout=timeout)
            return {'stdout': stdout, 'stderr': stderr, 'returncode': proc.returncode, 'timeout': False}
        except subprocess.TimeoutExpired:
            proc.kill()
            return {'stdout': '', 'stderr': f'Script timed out after {timeout}s', 'returncode': -1, 'timeout': True}
        except Exception as e:
            return {'stdout': '', 'stderr': str(e), 'returncode': -1, 'timeout': False}

        
# ===========================================
#             HELPERS
# ===========================================
def is_admin():
    return current_user.is_authenticated and current_user.id == 'saint'
    
def safe_join(base_dir: Path, subpath: str) -> Path:
    """Join base_dir and subpath, ensuring the result is inside base_dir."""
    base = base_dir.resolve()
    target = (base / subpath).resolve()
    # Normalize to prevent e.g., /etc/passwd
    if not str(target).startswith(str(base)):
        abort(403, description="Access denied: invalid path.")
    return target
    
def load_scripts_meta():
    with open(SCRIPTS_META_FILE) as f:
        return json.load(f)
def save_scripts_meta(meta):
    with open(SCRIPTS_META_FILE, "w") as f:
        json.dump(meta, f, indent=2)
def load_scraped_meta():
    with open(SCRAPED_META_FILE) as f:
        return json.load(f)
def save_scraped_meta(meta):
    with open(SCRAPED_META_FILE, "w") as f:
        json.dump(meta, f, indent=2)
def count_tokens(text, model="gpt-3.5-turbo"):
    """Return an approximate token count, falling back to len/4 on errors."""
    try:
        try:
            encoding = tiktoken.encoding_for_model(model)
        except KeyError:
            # Fallback to cl100k_base, but catch download errors
            try:
                encoding = tiktoken.get_encoding("cl100k_base")
            except Exception:
                # If download fails, use a rough estimate
                return len(text) // 4  # ~4 chars per token
        return len(encoding.encode(text))
    except Exception:
        # Any other failure (SSL, network, etc.) -> rough estimate
        return len(text) // 4
def get_mcp_servers():
    if not MCP_SERVERS_FILE.exists():
        return {}
    try:
        with open(MCP_SERVERS_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        save_mcp_servers({})
        return {}
def save_mcp_servers(servers):
    with open(MCP_SERVERS_FILE, 'w') as f:
        json.dump(servers, f, indent=2)
def load_llm_providers():
    if not LLM_PROVIDERS_FILE.exists():
        default = {
            "kaggle": {"name": "Kaggle (ruth)", "type": "openai", "url": os.environ.get('KAGGLE_TUNNEL_URL', 'http://your-kaggle-tunnel-url'), "api_key": "dummy", "enabled": True},
            "ollama": {"name": "Ollama (local)", "type": "ollama", "url": "http://localhost:11434", "api_key": "", "enabled": True}
        }
        with open(LLM_PROVIDERS_FILE, "w") as f:
            json.dump(default, f, indent=2)
        return default
    with open(LLM_PROVIDERS_FILE) as f:
        return json.load(f)
def save_llm_providers(providers):
    with open(LLM_PROVIDERS_FILE, "w") as f:
        json.dump(providers, f, indent=2)

def ollama_chat(model, messages):
    url = 'http://localhost:11434/api/chat'
    payload = {'model': model, 'messages': messages, 'stream': False}
    try:
        resp = requests.post(url, json=payload, timeout=12000)
        if resp.ok:
            result = resp.json()
            reply = result.get('message', {}).get('content', '')
            return jsonify({'choices': [{'message': {'content': reply}}]})
        else:
            return jsonify({'error': f'Ollama error: {resp.status_code}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def custom_openai_chat(base_url, api_key, messages):
    target = f"{base_url}/chat/completions"
    headers = {'Content-Type': 'application/json'}
    if api_key:
        headers['Authorization'] = f"Bearer {api_key}"
    try:
        resp = requests.post(target, json={'messages': messages}, headers=headers, timeout=12000)
        if resp.status_code != 200:
            return jsonify({'error': f'Provider returned {resp.status_code}: {resp.text[:100]}'}), resp.status_code
        return Response(resp.content, status=resp.status_code,
                        content_type=resp.headers.get('content-type', 'application/json'))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def call_llm(provider, model, messages, workspace_id=None):
    """Call LLM and return the assistant's content."""
    task_id=None
    if provider == 'ollama':
        ollama_url = 'http://localhost:11434/api/chat'
        payload = {'model': model, 'messages': messages, 'stream': False, 'temperature': 0.1}
        full_text = " ".join([m.get('content', '') for m in messages])
        token_count = count_tokens(full_text, model)
        if task_id:
            task_manager.add_tokens(task_id, token_count)
        logger.info(f"LLM request tokens: {token_count} (model: {model})")
        try:
            resp = requests.post(ollama_url, json=payload, timeout=12000)
            if resp.ok:
                result = resp.json()
                return result.get('message', {}).get('content', '')
            else:
                return None
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            return None
    else:
        # Kaggle or custom OpenAI provider
        providers = load_llm_providers()
        if provider not in providers:
            logger.error(f"Provider '{provider}' not found in config")
            return None
        prov = providers[provider]
        if not prov.get('enabled', False):
            logger.error(f"Provider '{provider}' is disabled")
            return None
        
        url = prov.get('url')
        api_key = prov.get('api_key', '')
        if not url:
            logger.error("Provider URL not set")
            return None
        
        # Use the new /v1/chat/completions endpoint
        target = f"{url}/v1/chat/completions"
        headers = {
            'Content-Type': 'application/json',
            'X-API-Key': api_key
        }
        
        # Prepare payload with session_id (workspace) and messages
        payload = {
            "session_id": workspace_id or "default",  # use workspace ID as session
            "message": messages[-1]['content'] if messages else "",  # the latest user message
            "model": model,
            "messages": messages,   # include full history so server can use it directly
            "max_tokens": 1024,
            "temperature": 0.7,
            "use_rag": False       # we'll allow the frontend to enable this via a checkbox
        }
        
        try:
            resp = requests.post(target, json=payload, headers=headers, timeout=12000)
            if resp.status_code == 200:
                result = resp.json()
                # Extract assistant message from response
                assistant_content = result.get('choices', [{}])[0].get('message', {}).get('content', '')
                return assistant_content
            else:
                logger.error(f"Kaggle server error: {resp.status_code} - {resp.text[:200]}")
                return None
        except Exception as e:
            logger.error(f"Kaggle request failed: {e}")
            return None
'''       else:
            # fallback to Ollama
            ollama_url = 'http://localhost:11434/api/chat'
            payload = {'model': 'llama3.1:8b', 'messages': messages, 'stream': False}
            try:
                resp = requests.post(ollama_url, json=payload, timeout=12000)
                if resp.ok:
                    result = resp.json()
                    return result.get('message', {}).get('content', '')
                else:
                    return None
            except Exception as e:
                logger.error(f"Fallback Ollama error: {e}")
                return None
'''
def run_llm_loop(task_id, provider, model, messages, mode, workspace, target, use_rag=False):
    task_manager.update_task(task_id, status=TaskStatus.RUNNING)
    
    task = task_manager.get_task(task_id)
    username = task['user_id']
    workspace_id = task['workspace_id']
    logger.info(f"loop started ...")

    # Build system prompt
    logger.info(f"trying to build prompt")
    try:
        tools_description = get_tools_description()
        logger.info(f"building prompt plaese wait.. ")
    except Exception:
        tools_description = "No tools available (error retrieving)."

    # Build system prompt with memory injection
    base_system = """You are an autonomous penetration testing assistant.
you have access to full conversation history, including previous tool outputs.
if you need tool names and schema respond with {"request": "list_tools"}

**IMPORTANT FORMAT RULES:**
- If you need to call a tool (single step), respond with **ONLY** a JSON object like:
  {"tool": "nmap", "args": {"target": "10.2.21.12", "scan_type": "-T4 -sV"}}
- If the user asks for a multi‑step task (recon, full scan, etc.), respond with **ONLY** a JSON plan like:
  {"plan": [{"tool": "nmap", "args": {...}}, {"tool": "gobuster", "args": {...}}]}
- For any normal conversation (greetings, explanations, summaries), you may respond in plain text.
- Do not include any extra text when outputting JSON – the JSON must be the entire response.

Examples:
User: "Scan 10.2.21.12 for open ports"
Assistant: {"tool": "nmap", "args": {"target": "10.2.21.12", "scan_type": "-T4 -sV"}}

User: "Recon 10.2.21.12 thoroughly"
Assistant: {"plan": [{"tool": "nmap", "args": {"target": "10.2.21.12", "scan_type": "-T4 -sV"}}, {"tool": "gobuster", "args": {"url": "http://10.2.21.12", "mode": "dir"}}]}

If you are not sure, always output a JSON plan or tool call rather than asking for clarification.
"""

    logger.info(f"base memory set to: {base_system}")
    # --- Load recent memory for this workspace ---
    memory_text = ""
    logger.info(f"loading recent memory")
    if workspace and task_id:
        if task:
            memory_entries = load_workspace_memory(username, workspace, limit=5)
            if memory_entries:
                memory_text = "\nRecent tool results (from this workspace):\n"
                for entry in memory_entries:
                    memory_text += f"- Tool: {entry['tool']} at {entry['timestamp'][:16]}\n"
                    memory_text += f"  Result: {entry['result'][:300]}...\n"
                memory_text += "You can use these results to avoid repeating the same actions.\n"

    # RAG
    rag_context = ""
    if use_rag and EMBEDDER_AVAILABLE:
        last_user_msg = next((m['content'] for m in reversed(messages) if m['role'] == 'user'), '')
        if last_user_msg:
            query_embedding = embedder.encode([last_user_msg]).tolist()
            results = collection.query(query_embeddings=query_embedding, n_results=3)
            if results['documents'][0]:
                rag_context = "\nRelevant knowledge:\n" + "\n".join(results['documents'][0])

    # --- Vector Memory: retrieve similar past actions ---
    vector_memory_text = ""
    logger.info(f"Vector memory")
    if workspace and task_id and EMBEDDER_AVAILABLE:
        task = task_manager.get_task(task_id)
        if task:
            username = task['user_id']
            # Use the last user message as the query
            last_user_msg = next((m['content'] for m in reversed(messages) if m['role'] == 'user'), '')
            if last_user_msg:
                similar = retrieve_similar_memories(last_user_msg, username, workspace, n_results=2)
                if similar:
                    vector_memory_text = "\nSimilar past actions found (vector memory):\n"
                    vector_memory_text += "\n".join([f"- {snippet[:200]}..." for snippet in similar])
                    vector_memory_text += "\nYou may adapt these approaches.\n"
                    
    system_prompt = base_system + memory_text + vector_memory_text                

    full_messages = [{"role": "system", "content": system_prompt + rag_context}] + messages
    total_tokens = sum(count_tokens(m.get('content', ''), model) for m in  full_messages)
    logger.info(f"Total conversation tokens: {total_tokens} (threshold: 8000)")
    if total_tokens > 8000:
        logger.warning("Approaching token limit - consider compressing history.")

    estimated_tokens = sum(len(m.get('content', '')) / 4 for m in full_messages)
    if estimated_tokens > 3000:  # safe limit
        # Keep the system prompt and the last 2 user/assistant turns
        system_messages = [m for m in full_messages if m['role'] == 'system']
        recent_messages = full_messages[-4:]  # last 4 messages
        old_messages = full_messages[len(system_messages):-4]
        if old_messages:
            logger.info(f"Compressing {len(old_messages)} old messages...")
            summary_text = summarize_conversation(old_messages, provider, model)
            # Replace old messages with a single "summary" message
            full_messages = system_messages + [
                {"role": "system", "content": f"Previous conversation summary: {summary_text}"}
            ] + recent_messages


    max_iterations = 10
    iteration = 0

    while iteration < max_iterations:
        # 0 cancel task
        if task_manager.is_cancelled(task_id):
            logger.info(f"Task {task_id} cancelled gracefully.")
            task_manager.update_task(task_id, status=TaskStatus.FAILED, error="Cancelled by user")
            return
            
        # 1. Call LLM
        logger.info(f"start of iterations")
        assistant_content = call_llm(provider, model, full_messages, workspace_id=workspace)
        last_user = next((m['content'] for m in reversed(full_messages) if m['role'] == 'user'), None)
        if assistant_content is None:
            task_manager.update_task(task_id, status=TaskStatus.FAILED, error="LLM returned no content")
            return

        parsed = extract_json_object(assistant_content)
        if parsed and isinstance(parsed, dict):
            if parsed.get('request') == 'list_tools' or parsed.get('tool') == 'list_tools':
                tools_desc = get_tools_description()
                full_messages.append({"role": "assistant", "content": assistant_content})
                full_messages.append({"role": "user", "content": f"Here is the list of available tools:\n{tools_desc}"})
                iteration += 1
                continue

        # Try to parse as a plan first
        plan_json = None
        try:
            # Attempt to parse the entire content as JSON (after stripping markdown if any)
            cleaned = assistant_content.strip()
            # Remove any markdown code fences
            cleaned = re.sub(r'^```(?:json)?\s*', '', cleaned)
            cleaned = re.sub(r'```\s*$', '', cleaned)
            plan_json = json.loads(cleaned)
        except json.JSONDecodeError:
            # Fallback to the existing extractor
            plan_json = extract_json_object(assistant_content)

        if plan_json and isinstance(plan_json, dict) and 'plan' in plan_json:
            plan = plan_json['plan']
            if not isinstance(plan, list) or not plan:
                # invalid plan
                pass
            else:
                # Store plan in task manager (we'll add a field)
                task_manager.update_task(task_id, plan=plan, current_step=0)
                # Send a "plan" event to frontend
                task_manager.append_event(task_id, "plan", {"plan": plan})
                
                # If in assistant mode, ask for confirmation of the whole plan
                if mode == 'assistant':
                    task_manager.update_task(
                        task_id,
                        status=TaskStatus.PENDING_CONFIRMATION,
                        pending_proposal={"plan": plan},
                        full_messages=full_messages.copy(),
                        iteration=iteration
                    )
                    task_manager.append_event(task_id, "plan_proposal", {"plan": plan})
                    confirmed = task_manager.wait_for_confirmation(task_id, timeout=300)
                    if not confirmed:
                        task_manager.update_task(task_id, status=TaskStatus.FAILED, error="Plan confirmation failed")
                        return
                    # proceed to execute
                # else autonomous: just execute
                step_results = []  # store outputs of each step
                step_status = []   # store success/failure of each step

                # Helper: replace placeholders like {prev.output} in args
                def chain_args(args, step_index, step_results):
                    if not step_results:
                        return args
                    # Get the output of the previous step (or last successful step)
                    last_output = step_results[-1] if step_results else ""
                    # Simple placeholder replacement
                    new_args = {}
                    for key, value in args.items():
                        if isinstance(value, str) and "{prev.output}" in value:
                            new_args[key] = value.replace("{prev.output}", last_output[:500])  # truncate
                        elif isinstance(value, str) and "{step_0.output}" in value and len(step_results) > 0:
                            new_args[key] = value.replace("{step_0.output}", step_results[0][:500])
                        else:
                            new_args[key] = value
                    return new_args

                # Execute each step sequentially
                task = task_manager.get_task(task_id)
                step = task.get('current_step', 0)
                while step < len(plan):
                    step_item = plan[step]
                    tool_name = step_item['tool']
                    args = step_item['args']

                    # --- Conditional Execution: skip if previous step failed 
                    if step > 0 and not step_status[-1]:
                        task_manager.append_event(task_id, "thinking", {"message": f"Skipping {tool_name} because previous step failed."})
                        step += 1
                        continue

                    # --- Tool Chaining: inject previous output ---
                    chained_args = chain_args(args, step, step_results)
                
                    # Inject target if missing
                    if target:
                        for key in ['target', 'host', 'url']:
                            if key not in chained_args:
                                chained_args[key] = target

                    task_manager.append_event(task_id, "tool_call", {"tool": tool_name, "args": chained_args})

                    # --- Auto‑Retry logic (max 2 attempts) ---
                    max_retries = 2
                    attempt = 0
                    success = False
                    tool_result = None

                    while attempt < max_retries and not success:
                        attempt += 1
                        try:
                            # If this is a retry, adjust args (e.g., lower timeout, change scan_type)
                            if attempt > 1:
                                task_manager.append_event(task_id, "thinking", {"message": f"Retrying {tool_name} (attempt {attempt})..."})
                                # Simple fallback: if nmap scan_type was -T4, try -T3
                                if tool_name == "nmap" and chained_args.get("scan_type") == "-T4 -sV":
                                    chained_args["scan_type"] = "-T3 -sV"
                                # If gobuster, add a delay
                                if tool_name == "gobuster" and "delay" not in chained_args:
                                    chained_args["delay"] = "500ms"
            
                            user_id = task['user_id']
                            # Get last user query for vector memory
                            last_user = next((m['content'] for m in reversed(full_messages) if m['role'] == 'user'), None)
                            tool_result = execute_tool(tool_name, chained_args, workspace, user_id, user_query=last_user)
            
                            # Check if tool result indicates success (no "Error:" prefix)
                            if not tool_result.startswith("Error:"):
                                success = True
                                step_results.append(tool_result)
                                step_status.append(True)
                                task_manager.append_event(task_id, "tool_result", {"output": tool_result})
                                # Store in conversation
                                full_messages.append({"role": "assistant", "content": f"Step {step+1}: {tool_name} ran successfully."})
                                full_messages.append({"role": "user", "content": f"Tool {tool_name} returned:\n{tool_result}"})
                            else:
                                # Failure
                                if attempt == max_retries:
                                    # Final failure – log it and continue to next step
                                    step_results.append(f"FAILED: {tool_result}")
                                    step_status.append(False)
                                    task_manager.append_event(task_id, "tool_result", {"output": f"Failed after {max_retries} attempts: {tool_result}"})
                                    # Don't stop the whole plan – just mark as failed and move on
                                else:
                                    # Wait a bit before retrying
                                    time.sleep(2)
                        except Exception as e:
                            logger.error(f"Tool execution error: {e}")
                            if attempt == max_retries:
                                step_results.append(f"EXCEPTION: {str(e)}")
                                step_status.append(False)
                                task_manager.append_event(task_id, "tool_result", {"output": f"Exception: {str(e)}"})
                            else:
                                time.sleep(2)

                    step += 1
                    task_manager.update_task(task_id, current_step=step)
    
                # After all steps, produce a final summary
                # We can call the LLM again with all results to get a summary
                # Or just finish and let the user ask follow-ups.
                # For simplicity, we'll just finish and return a final message.
                final_summary = f"Completed {len(plan)} steps. Check the results above."
                task_manager.append_event(task_id, "final", {"content": final_summary})
                # Save to chat
                history = load_chat_history(username, workspace_id)
                history.append({"role": "assistant", "content": final_summary})
                save_chat_history(username, workspace_id, history)
                task_manager.update_task(task_id, status=TaskStatus.COMPLETED, result=final_summary)
                return
        
        # 2. Try to parse tool call
        tool_call = extract_json_object(assistant_content)
        if tool_call and isinstance(tool_call, dict) and 'tool' in tool_call and 'args' in tool_call:
            tool_name = tool_call['tool']
            args = tool_call['args']
            # Inject target if missing
            if target:
                for key in ['target', 'host', 'url']:
                    if key not in args:
                        args[key] = target

            # Store the tool call event (so the frontend can show it)
            task_manager.append_event(task_id, "tool_call", {"tool": tool_name, "args": args})

            if mode == 'assistant':
                # ---- Assistant mode: ask for confirmation ----
                # Save current state so we can resume
                task_manager.update_task(
                    task_id,
                    status=TaskStatus.PENDING_CONFIRMATION,
                    pending_proposal={"tool": tool_name, "args": args},
                    full_messages=full_messages.copy(),
                    iteration=iteration
                )
                # Store the proposal event for the UI
                task_manager.append_event(task_id, "tool_proposal", {"tool": tool_name, "args": args})

                # Wait for confirmation (timeout = 5 minutes)
                confirmed = task_manager.wait_for_confirmation(task_id, timeout=300)
                if not confirmed:
                    task_manager.update_task(
                        task_id,
                        status=TaskStatus.FAILED,
                        error="Confirmation timeout or cancelled"
                    )
                    return

                # Resume: execute the tool
                # Retrieve updated state
                task = task_manager.get_task(task_id)
                if not task or task['status'] == TaskStatus.FAILED:
                    return

                task_manager.append_event(task_id, "thinking", {"message": f"Preparing to run {tool_name}..."})
                
                # Execute tool with the confirmed args
                user_id = task['user_id']
                # Get the last user message from full_messages
                last_user = next((m['content'] for m in reversed(full_messages) if m['role'] == 'user'), None)
                tool_result = execute_tool(tool_name, args, workspace, user_id, user_query=last_user)
                task_manager.append_event(task_id, "tool_result", {"output": tool_result})

                # Add to conversation
                full_messages = task['full_messages']  # restored
                full_messages.append({"role": "assistant", "content": assistant_content})
                full_messages.append({"role": "user", "content": f"Tool {tool_name} returned:\n{tool_result}"})
                iteration = task['iteration'] + 1
                # Reset confirmation state
                task_manager.update_task(task_id, status=TaskStatus.RUNNING, confirmed=False)
                continue  # next iteration

            else:
                # ---- Autonomous mode: execute directly ----
                user_id = task_manager.get_task(task_id)['user_id']
                task_manager.append_event(task_id, "thinking", {"message": f"Preparing to run {tool_name}..."})
                tool_result = execute_tool(tool_name, args, workspace, user_id)
                task_manager.append_event(task_id, "tool_result", {"output": tool_result})
                full_messages.append({"role": "assistant", "content": assistant_content})
                full_messages.append({"role": "user", "content": f"Tool {tool_name} returned:\n{tool_result}"})
                iteration += 1
                continue

        # No tool call – final answer
        task_manager.append_event(task_id, "final", {"content": assistant_content})
        # Save to chat history
        task = task_manager.get_task(task_id)
        if task:
            username = task['user_id']  # user_id is actually username in our system
            workspace_id = task['workspace_id']
            # Append assistant message to chat history
            history = load_chat_history(username, workspace_id)
            history.append({"role": "assistant", "content": assistant_content})
            save_chat_history(username, workspace_id, history)
        task_manager.update_task(task_id, status=TaskStatus.COMPLETED, result=assistant_content)
        return

    # Max iterations reached
    task_manager.update_task(task_id, status=TaskStatus.FAILED, error="Max iterations reached")                
# =============================================================================
# MCP SUPPORT – HTTP/SSE and stdio
# =============================================================================

class StdioMCPSession:
    """Manages a subprocess MCP server over stdio."""
    def __init__(self, command, env=None, cwd=None):
        self.command = command
        self.env = env or {}
        self.cwd = cwd
        self.proc = None
        self.lock = threading.Lock()
        self.response_queues = {}
        self.reader_thread = None
        self.running = False
        self.tools_cache = None  # list of tool names after discovery

    def start(self):
        if self.proc and self.proc.poll() is None:
            return True
        full_env = os.environ.copy()
        full_env.update(self.env)
        try:
            self.proc = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=full_env,
                cwd=self.cwd,
                bufsize=1
            )
            self.running = True
            self.response_queues = {}
            self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
            self.reader_thread.start()
            logger.info(f"Started stdio MCP process: {' '.join(self.command)}")
            return True
        except Exception as e:
            logger.error(f"Failed to start stdio MCP: {e}")
            return False
        return self.initialize()   
         
    def initialize(self):
        # Send initialize
        init_req = {
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "moonshot-agent", "version": "1.0"},
                "capabilities": {}
            }
        }
        resp = self.send_request("init-1", "initialize", init_req["params"])
        if resp is None:
            logger.error("Initialize request failed")
            return False
        # Send initialized notification (no response expected)
        notif = {
            "jsonrpc": "2.0",
            "method": "initialized",
            "params": {}
        }
        self.proc.stdin.write(json.dumps(notif) + "\n")
        self.proc.stdin.flush()
        logger.info("MCP initialization complete")
        return True

    def _reader_loop(self):
        while self.running and self.proc and self.proc.poll() is None:
            line = self.proc.stdout.readline()
            if not line:
                break
            try:
                response = json.loads(line.strip())
                req_id = response.get('id')
                if req_id is not None and req_id in self.response_queues:
                    self.response_queues[req_id].put(response)
            except json.JSONDecodeError:
                logger.warning(f"Non-JSON line from stdio: {line.strip()}")

    def send_request(self, request_id, method, params):
        """Send a JSON-RPC request and return the response (blocking)."""
        with self.lock:
            if not self.proc or self.proc.poll() is not None:
                if not self.start():
                    return None
            payload = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params
            }
            logger.debug(f"Sending stdio request: {payload}")
            self.proc.stdin.write(json.dumps(payload) + "\n")
            self.proc.stdin.flush()
            q = queue.Queue()
            self.response_queues[request_id] = q
        try:
            response = q.get(timeout=60)
        except queue.Empty:
            logger.error(f"Timeout waiting for response to {method}")
            return None
        finally:
            with self.lock:
                self.response_queues.pop(request_id, None)
        return response
        

    def stop(self):
        self.running = False
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=5)
            self.proc = None
        if self.reader_thread and self.reader_thread.is_alive():
            self.reader_thread.join(timeout=1)
        logger.info("Stopped stdio MCP process")

    def is_alive(self):
        return self.proc is not None and self.proc.poll() is None

'''
class MCPSessionManager:
    def __init__(self):
        self.sessions = {}  # server_name -> session info
        self.lock = threading.Lock()

    def start_session(self, server_name, server_config):
        """Start a session for the given server (HTTP or stdio) and return session info."""
        with self.lock:
            if server_name in self.sessions:
                existing = self.sessions[server_name]
                if existing['type'] == 'http':
                    if 'sse_thread' in existing and not existing['sse_thread'].is_alive():
                        logger.info(f"SSE thread dead, restarting session for {server_name}")
                        # remove and restart
                        del self.sessions[server_name]
                        return self.start_session(server_name, server_config)  # restart fresh
                elif existing['type'] == 'stdio':
                    if not existing['stdio_session'].is_alive():
                        logger.info(f"stdio session dead, restarting for {server_name}")
                        existing['stdio_session'].start()
                return existing

            server_type = server_config.get('type', 'http')
            if server_type == 'http':
                url = server_config.get('url')
                if not url:
                    raise ValueError("HTTP server missing url")
                # SSE-based session – connect and get session ID
                q = queue.Queue()
                session_id = None
                stop_event = threading.Event()

                def sse_worker():
                    nonlocal session_id
                    while not stop_event.is_set():
                        try:
                            response = requests.get(f"{url}/sse", stream=True, timeout=3000)
                            if response.status_code != 200:
                                logger.error(f"SSE endpoint returned {response.status_code} for {server_name}")
                                time.sleep(5)
                                continue
                            logger.info(f"sse connection established for {server_name}, reading lines ....")    
                            # now read the stream
                            for line in response.iter_lines(decode_unicode=True):
                                if stop_event.is_set():
                                    break
                                if not line:
                                    continue    
                                logger.debug(f"SSE line: {line}")
                                if line.startswith('data: '):
                                    data_content = line[6:].strip()
                                    if '?session_id=' in data_content:
                                        parts = data_content.split('?session_id=') 
                                        logger.debug(f"Found Session_id in data: {data_content}")
                                        if len(parts) > 1:
                                            session_id = parts[1].split(' ')[0].split('&')[0]
                                            logger.info(f"✅ Captured session_id: {session_id}")
                                            q.put(session_id)
                                            #return  # success, exit thread
                                    try:
                                        msg = json.loads(data_content)
                                        if 'id' in msg:
                                            req_id = msg['id']
                                            # Find the session's response queue
                                            with self.lock:
                                                session_info = self.sessions.get(server_name)
                                                if session_info and req_id in session_info.get('response_queues', {}):
                                                    session_info['response_queues'][req_id].put(msg)
                                    except json.JSONDecodeError:
                                        pass                
                                                    
                        except requests.exceptions.RequestException as e:
                            logger.error(f"SSE connection error for {server_name}: {e}")
                            time.sleep(5)
                        except Exception as e:
                            logger.error(f"unexpected error in sse worker for {server_name}: {e}")
                            time.sleep(5)
                             
                thread = threading.Thread(target=sse_worker, daemon=True)
                thread.start()
                try:
                    session_id = q.get(timeout=100)
                    logger.info(f"Got session ID: {session_id}, now initialzing........")
                    # ---- MCP Initialization ----
                    init_req_id = str(uuid.uuid4())
                    init_response = self.send_http_request(server_name, init_req_id, "initialize", {
                        "protocolVersion": "2025-03-26",
                        "clientInfo": {"name": "moonshot-agent", "version": "1.0"},
                        "capabilities": {}
                    })
                    if init_response is None or 'error' in init_response:
                        raise RuntimeError("Initialize failed")
                    # Send initialized notification (no response needed)
                    notif_payload = {"jsonrpc": "2.0", "method": "initialized", "params": {}}
                    requests.post(messages_url, json=notif_payload, timeout=5)
                    messages_url = f"{url}/messages/?session_id={session_id}"
                    try:
                        init_resp = requests.post(messages_url, json=init_payload, timeout=300)
                        logger.info(f"Sending initialize to {messages_url}")
                        if init_resp.status_code != 200:
                            logger.error(f"Initialize failed: {init_resp.status_code} {init_resp.text}")
                            raise RuntimeError("Initialize failed")
                        # Send initialized notification (no response expected)
                        notif_payload = {
                            "jsonrpc": "2.0",
                            "method": "initialized",
                            "params": {}
                        }
                        requests.post(messages_url, json=notif_payload, timeout=5)
                        logger.info(f"MCP initialization completed for {server_name}")
                    except Exception as e:
                        logger.error(f"Init error: {e}")
                        raise RuntimeError(f"Initialize failed: {e}")
 
                except queue.Empty:
                    raise RuntimeError(f"Failed to get session ID for {server_name}")
                session_info = {
                    'type': 'http',
                    'url': url,
                    'session_id': session_id,
                    'sse_thread': thread,
                    'stop_event': stop_event,
                    'tools_cache': None,
                    'response_queues': {}
                }
                self.sessions[server_name] = session_info
                logger.info(f"HTTP session started for {server_name} with ID {session_id}")
                return session_info

            elif server_type == 'stdio':
                command = server_config.get('command')
                if not command:
                    raise ValueError("stdio server missing command")
                env = server_config.get('env', {})
                cwd = server_config.get('cwd')
                stdio_session = StdioMCPSession(command, env=env, cwd=cwd)
                if not stdio_session.start():
                    raise RuntimeError(f"Failed to start stdio server {server_name}")
                session_info = {
                    'type': 'stdio',
                    'stdio_session': stdio_session,
                    'tools_cache': None
                }
                self.sessions[server_name] = session_info
                logger.info(f"stdio session started for {server_name}")
                return session_info
            else:
                raise ValueError(f"Unknown server type: {server_type}")

    def stop_session(self, server_name):
        with self.lock:
            session = self.sessions.get(server_name)
            if not session:
                return False
            if session['type'] == 'http':
                if 'stop_event' in session:
                    session['stop_event'].set()
                del self.sessions[server_name]
                logger.info(f"HTTP session stopped for {server_name}")
            elif session['type'] == 'stdio':
                session['stdio_session'].stop()
                del self.sessions[server_name]
                logger.info(f"stdio session stopped for {server_name}")
            return True

    def get_session(self, server_name):
        with self.lock:
            return self.sessions.get(server_name)

    def discover_tools(self, server_name):
        """Call tools/list and cache the result in the session."""
        session = self.get_session(server_name)
        if not session:
            return None
        if session.get('tools_cache') is not None:
            return session['tools_cache']
        logger.info(f"Sending initialize to {messages_url}")
        
        # Send tools/list request
        if session['type'] == 'http':
            # Use existing session_id and url
            url = session['url']
            session_id = session['session_id']
            req_id = str(uuid.uuid4())
            response = self.send_http_request(server_name, req_id, "tools/list", {})
            if response and 'result' in response:
                tools = response['result'].get('tools', [])
                tool_names = [t.get('name') for t in tools if t.get('name')]
                session['tools_cache'] = tool_names
                return tool_names
            messages_url = f"{url}/messages/?session_id={session_id}"
            try:
                resp = requests.post(messages_url, json=payload, timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    tools = data.get('result', {}).get('tools', [])
                    tool_names = [t.get('name') for t in tools if t.get('name')]
                    session['tools_cache'] = tool_names
                    return tool_names
            except Exception as e:
                logger.error(f"Failed to discover tools for HTTP {server_name}: {e}")
                return None
        elif session['type'] == 'stdio':
            stdio = session['stdio_session']
            req_id = str(uuid.uuid4())
            response = stdio.send_request(req_id, "tools/list", {})
            if response:
                tools = response.get('result', {}).get('tools', [])
                tool_names = [t.get('name') for t in tools if t.get('name')]
                session['tools_cache'] = tool_names
                return tool_names
        return None

    def send_http_request(self, server_name, request_id, method, params):
        """Send a JSON-RPC request via HTTP and wait for the response on the SSE queue."""
        session = self.get_session(server_name)
        if not session or session['type'] != 'http':
            return None

        # Ensure response_queues exists
        if 'response_queues' not in session:
            session['response_queues'] = {}
        q = queue.Queue()
        session['response_queues'][request_id] = q

        try:
            url = session['url']
            session_id = session['session_id']
            messages_url = f"{url}/messages/?session_id={session_id}"

            payload = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params
            }
            resp = requests.post(messages_url, json=payload, timeout=30)
            if resp.status_code not in (200, 202):
                logger.error(f"HTTP request failed: {resp.status_code} {resp.text}")
                return None

            # Wait for response on SSE queue
            try:
                response = q.get(timeout=60)
                return response
            except queue.Empty:
                logger.error(f"Timeout waiting for response to {method}")
                return None
        finally:
            # Clean up the queue
            session['response_queues'].pop(request_id, None)

    def send_tool_call(self, server_name, tool_name, arguments):
        session = self.get_session(server_name)
        if not session:
            return None
        if session['type'] == 'http':
            url = session['url']
            session_id = session['session_id']
            req_id = str(uuid.uuid4())
            response = self.send_http_request(server_name, req_id, "tools/call", {"name": tool_name, "arguments": arguments})
            if response and 'result' in response:
                return response['result']
            messages_url = f"{url}/messages/?session_id={session_id}"
            try:
                resp = requests.post(messages_url, json=payload, timeout=60)
                return resp
            except Exception as e:
                logger.error(f"HTTP tool call failed: {e}")
                return None
        elif session['type'] == 'stdio':
            stdio = session['stdio_session']
            req_id = str(uuid.uuid4())
            response = stdio.send_request(req_id, "tools/call", {"name": tool_name, "arguments": arguments})
            if response is None:
                return None
            # Wrap as a Response-like object
            class StdioResponse:
                def __init__(self, json_data):
                    self._json = json_data
                    self.status_code = 200
                    self.headers = {'content-type': 'application/json'}
                    self.content = json.dumps(json_data)
                    self.text = self.content
                def json(self):
                    return self._json
            return StdioResponse(response)
        else:
            return None
'''
class MCPSessionManager:
    def __init__(self):
        self.sessions = {}  # server_name -> session info
        self.lock = threading.Lock()

    def send_http_request(self, server_name, request_id, method, params):
        """Send a JSON-RPC request via HTTP and wait for the response on the SSE queue."""
        session = self.get_session(server_name)
        if not session or session['type'] != 'http':
            return None

        # Ensure response_queues exists
        if 'response_queues' not in session:
            session['response_queues'] = {}
        q = queue.Queue()
        session['response_queues'][request_id] = q

        try:
            url = session['url']
            session_id = session['session_id']
            messages_url = f"{url}/messages/?session_id={session_id}"

            payload = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params
            }
            resp = requests.post(messages_url, json=payload, timeout=3000)
            logger.info(f"POST {messages_url} status: {resp.status_code}, body: {resp.text[:200]} ")
            if resp.status_code not in (200, 202):
                logger.error(f"HTTP request failed: {resp.status_code} {resp.text}")
                return None

            # Wait for response on SSE queue
            try:
                response = q.get(timeout=600)
                return response
            except queue.Empty:
                logger.error(f"Timeout waiting for response to {method}")
                return None
        finally:
            # Clean up the queue
            session['response_queues'].pop(request_id, None)

    def start_session(self, server_name, server_config):
        """Start a session for the given server (HTTP or stdio) and return session info."""
        with self.lock:
            if server_name in self.sessions:
                existing = self.sessions[server_name]
                if existing['type'] == 'http':
                    if 'sse_thread' in existing and not existing['sse_thread'].is_alive():
                        logger.info(f"SSE thread dead, restarting session for {server_name}")
                        del self.sessions[server_name]
                        return self.start_session(server_name, server_config)
                elif existing['type'] == 'stdio':
                    if not existing['stdio_session'].is_alive():
                        logger.info(f"stdio session dead, restarting for {server_name}")
                        existing['stdio_session'].start()
                return existing

            server_type = server_config.get('type', 'http')
            if server_type == 'http':
                url = server_config.get('url')
                if not url:
                    raise ValueError("HTTP server missing url")
                q = queue.Queue()
                session_id = None
                stop_event = threading.Event()

                def sse_worker():
                    nonlocal session_id
                    retry_count = 0
                    max_retries = 3
                    while not stop_event.is_set():
                        try:
                            response = requests.get(f"{url}/sse", stream=True, timeout=3000)
                            if response.status_code != 200:
                                logger.error(f"SSE endpoint returned {response.status_code} for {server_name}")
                                time.sleep(5)
                                retry_count += 1
                                if retry_count >=max_retries:
                                    logger.error(f"too many retries for {server_name}, giving up.")
                                    break
                                continue
                            logger.info(f"sse connection established for {server_name}, reading lines ....")
                            retry_count = 0
                            for line in response.iter_lines(decode_unicode=True):
                                if stop_event.is_set():
                                    break
                                if not line:
                                    continue
                                logger.debug(f"SSE line: {line}")

                                if line.startswith('data: '):
                                    data_content = line[6:].strip()
                                    # Capture session ID
                                    if '?session_id=' in data_content and not session_id:
                                        parts = data_content.split('?session_id=')
                                        if len(parts) > 1:
                                            session_id = parts[1].split(' ')[0].split('&')[0]
                                            logger.info(f":) Captured session_id: {session_id} for: {server_name}")
                                            q.put(session_id)
                                            continue
 
                                    # Parse JSON-RPC responses
                                    try:
                                        msg = json.loads(data_content)
                                        if 'id' in msg:
                                            logger.info(f"Received Json-RPC response: {msg}")
                                            req_id = msg['id']
                                            with self.lock:
                                                session_info = self.sessions.get(server_name)
                                                if session_info and req_id in session_info.get('response_queues', {}):
                                                    session_info['response_queues'][req_id].put(msg)
                                    except json.JSONDecodeError:
                                        pass
                        except Exception as e:
                            logger.error(f":( SSE worker error: {e}")
                            time.sleep(5)
                            retry_count += 1
                            if retry_count >= max_retries:
                                logger.error(f":( Too many retries for: {server_name}, quiting...")
                                break

                thread = threading.Thread(target=sse_worker, daemon=True)
                thread.start()
                try:
                    session_id = q.get(timeout=30)
                except queue.Empty:
                    stop_event.set()
                    thread.join(timeout=2)
                    raise RuntimeError(f"Failed to get session ID for {server_name}")

                logger.info(f"Got session ID: {session_id} for: {server_name}, now initializing...")

                # Create session info (will be stored after initialization)
                session_info = {
                    'type': 'http',
                    'url': url,
                    'session_id': session_id,
                    'sse_thread': thread,
                    'stop_event': stop_event,
                    'tools_cache': None,
                    'response_queues': {}
                }
                self.sessions[server_name] = session_info

                # Send initialize via send_http_request
                init_req_id = str(uuid.uuid4())
                init_response = self.send_http_request(server_name, init_req_id, "initialize", {
                    "protocolVersion": "2024-11-05",
                    "clientInfo": {"name": "moonshot-agent", "version": "1.0"},
                    "capabilities": {}
                })
                if init_response is None or 'error' in init_response:
                    self.stop_session(server_name)
                    raise RuntimeError("Initialize failed")
                logger.info(f"MCP initialization completed for {server_name}")

                # Send initialized notification (no response expected)
                notif_payload = {
                    "jsonrpc": "2.0",
                    "method": "initialized",
                    "params": {}
                }
                requests.post(f"{url}/messages/?session_id={session_id}", json=notif_payload, timeout=5)

                return session_info

            elif server_type == 'stdio':
                command = server_config.get('command')
                if not command:
                    raise ValueError("stdio server missing command")
                env = server_config.get('env', {})
                cwd = server_config.get('cwd')
                stdio_session = StdioMCPSession(command, env=env, cwd=cwd)
                if not stdio_session.start():
                    raise RuntimeError(f"Failed to start stdio server {server_name}")
                session_info = {
                    'type': 'stdio',
                    'stdio_session': stdio_session,
                    'tools_cache': None
                }
                self.sessions[server_name] = session_info
                logger.info(f"stdio session started for {server_name}")
                return session_info
            else:
                raise ValueError(f"Unknown server type: {server_type}")

    def stop_session(self, server_name):
        with self.lock:
            session = self.sessions.get(server_name)
            if not session:
                return False
            if session['type'] == 'http':
                if 'stop_event' in session:
                    session['stop_event'].set()
                del self.sessions[server_name]
                logger.info(f"HTTP session stopped for {server_name}")
            elif session['type'] == 'stdio':
                session['stdio_session'].stop()
                del self.sessions[server_name]
                logger.info(f"stdio session stopped for {server_name}")
            return True

    def get_session(self, server_name):
        with self.lock:
            return self.sessions.get(server_name)

    def discover_tools(self, server_name):
        session = self.get_session(server_name)
        if not session:
            return None
        if session.get('tools_cache') is not None:
            return session['tools_cache']

        if session['type'] == 'http':
            req_id = str(uuid.uuid4())
            response = self.send_http_request(server_name, req_id, "tools/list", {}, timeout=1200)
            if response and 'result' in response:
                tools = response['result'].get('tools', [])
                tool_names = [t.get('name') for t in tools if t.get('name')]
                session['tools_cache'] = tool_names
                return tool_names
            else:
                logger.error(f"Failed to discover tools: {response}")
                return None
        elif session['type'] == 'stdio':
            stdio = session['stdio_session']
            req_id = str(uuid.uuid4())
            response = stdio.send_request(req_id, "tools/list", {})
            if response:
                tools = response.get('result', {}).get('tools', [])
                tool_names = [t.get('name') for t in tools if t.get('name')]
                session['tools_cache'] = tool_names
                return tool_names
        return None

    def send_tool_call(self, server_name, tool_name, arguments):
        session = self.get_session(server_name)
        if not session:
            return None
        if session['type'] == 'http': 
            req_id = str(uuid.uuid4())
            response = self.send_http_request(server_name, req_id, "tools/call", {"name": tool_name, "arguments": arguments})
            if response and 'result' in response:
                # Wrap as a Response-like object for compatibility with existing code
                class StdioResponse:
                    def __init__(self, json_data):
                        self._json = json_data
                        self.status_code = 200
                        self.headers = {'content-type': 'application/json'}
                        self.content = json.dumps(json_data)
                        self.text = self.content
                    def json(self):
                        return self._json
                return StdioResponse(response['result'])
            else:
                logger.error(f"Tool call failed: {response}")
                return None
        elif session['type'] == 'stdio':
            stdio = session['stdio_session']
            req_id = str(uuid.uuid4())
            response = stdio.send_request(req_id, "tools/call", {"name": tool_name, "arguments": arguments})
            if response is None:
                return None
            class StdioResponse:
                def __init__(self, json_data):
                    self._json = json_data
                    self.status_code = 200
                    self.headers = {'content-type': 'application/json'}
                    self.content = json.dumps(json_data)
                    self.text = self.content
                def json(self):
                    return self._json
            return StdioResponse(response)
        else:
            return None

# Global instance
mcp_manager = MCPSessionManager()

# ---------- MCP Proxy Endpoints (multi-server) ----------
@app.route('/mcp/sse')
@login_required
def mcp_sse():
    server_name = request.args.get('server')
    if not server_name:
        return jsonify({'error': 'Missing server parameter'}), 400
    servers = get_mcp_servers()
    config = servers.get(server_name)
    if not config:
        return jsonify({'error': 'Server not found'}), 404
    server_type = config.get('type', 'http')
    if server_type != 'http':
        return jsonify({'error': 'SSE not supported for stdio servers'}), 501
    proxy_url = config.get('url')
    if not proxy_url:
        return jsonify({'error': 'Server has no URL'}), 400

    def generate():
        try:
            with requests.get(f"{proxy_url}/sse", stream=True, timeout=3000) as r:
                for chunk in r.iter_content(chunk_size=1024, decode_unicode=True):
                    if chunk:
                        yield chunk
        except Exception as e:
            yield f"event: error\ndata: {str(e)}\n\n"
    response = Response(stream_with_context(generate()), mimetype='text/event-stream')
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Cache-Control'] = 'no-cache'
    return response

@app.route('/mcp/messages', methods=['POST', 'OPTIONS'], strict_slashes=False)
@login_required
def mcp_messages():
    if request.method == 'OPTIONS':
        response = Response('', status=200)
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return response

    server_name = request.args.get('server')
    if not server_name:
        return jsonify({'error': 'Missing server parameter'}), 400
    servers = get_mcp_servers()
    config = servers.get(server_name)
    if not config:
        return jsonify({'error': 'Server not found'}), 404
    server_type = config.get('type', 'http')
    if server_type == 'http':
        proxy_url = config.get('url')
        if not proxy_url:
            return jsonify({'error': 'Server has no URL'}), 400
        query_string = request.query_string.decode() if request.query_string else ''
        target_url = f"{proxy_url}/messages"
        if query_string:
            target_url += f"?{query_string}"
        try:
            resp = requests.post(target_url, json=request.json, stream=True, timeout=12000)
        except Exception as e:
            return jsonify({'error': f'Proxy connection error: {str(e)}'}), 502
        response = Response(resp.iter_content(chunk_size=1024),
                            status=resp.status_code,
                            content_type=resp.headers.get('content-type', 'application/json'))
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
    elif server_type == 'stdio':
        # Ensure session exists
        try:
            session_info = mcp_manager.start_session(server_name, config)
        except Exception as e:
            return jsonify({'error': f'Failed to start stdio session: {str(e)}'}), 500
        stdio = session_info['stdio_session']
        rpc_request = request.json
        if not rpc_request or 'method' not in rpc_request:
            return jsonify({'error': 'Invalid JSON-RPC request'}), 400
        req_id = rpc_request.get('id', str(uuid.uuid4()))
        method = rpc_request['method']
        params = rpc_request.get('params', {})
        response = stdio.send_request(req_id, method, params)
        if response is None:
            return jsonify({'error': 'No response from stdio server'}), 504
        return jsonify(response)
    else:
        return jsonify({'error': 'Unsupported server type'}), 400

# ---------- API: MCP Server Management (start/stop) ----------
@app.route('/api/mcp_servers/<name>/start', methods=['POST'])
@login_required
def start_mcp_server(name):
    if not is_admin():
        return jsonify({'error': 'Admin access required'}), 403
    servers = get_mcp_servers()
    config = servers.get(name)
    if not config:
        return jsonify({'error': 'Server not found'}), 404
    try:
        session_info = mcp_manager.start_session(name, config)
        # Discover tools after start (optional)
        tools = mcp_manager.discover_tools(name)
        return jsonify({'status': 'started', 'tools': tools or []})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/mcp_servers/<name>/stop', methods=['POST'])
@login_required
def stop_mcp_server(name):
    if not is_admin():
        return jsonify({'error': 'Admin access required'}), 403
    if mcp_manager.stop_session(name):
        return jsonify({'status': 'stopped'})
    else:
        return jsonify({'error': 'Server not running'}), 404

@app.route('/api/mcp_servers/<name>/status', methods=['GET'])
@login_required
def get_mcp_server_status(name):
    servers = get_mcp_servers()
    config = servers.get(name)
    if not config:
        return jsonify({'error': 'Server not found'}), 404
    session = mcp_manager.get_session(name)
    if session is None:
        return jsonify({'status': 'stopped'})
    if session['type'] == 'stdio':
        alive = session['stdio_session'].is_alive()
        return jsonify({'status': 'running' if alive else 'stopped'})
    else:  # http
        # Check if SSE thread is alive
        if 'sse_thread' in session and session['sse_thread'].is_alive():
            return jsonify({'status': 'running'})
        else:
            return jsonify({'status': 'stopped'})

@app.route('/api/mcp_servers/<name>/tools', methods=['GET'])
@login_required
def get_mcp_server_tools(name):
    """Return cached tools (or discover if not yet)."""
    servers = get_mcp_servers()
    config = servers.get(name)
    if not config:
        return jsonify({'error': 'Server not found'}), 404
    # Ensure session is started
    session = mcp_manager.get_session(name)
    if not session:
        try:
            session = mcp_manager.start_session(name, config)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    tools = mcp_manager.discover_tools(name)
    return jsonify({'tools': tools or []})

# ---------- Streaming (tool execution) with auto‑spawn ----------
STREAM_ALLOWED_TOOLS = {"nmap", "gobuster", "sqlmap", "nikto", "wpscan", "hydra", "enum4linux", "curl", "ffuf", "dirb", "aircrack-ng", "airmon-ng", "airodump-ng", "wifite", "netcat", "john"}

@app.route('/api/stream/run_tool', methods=['POST'])
@login_required
def stream_run_tool():
    data = request.json
    tool = data.get('tool')
    args = data.get('args', {})
    target = data.get('target', '')
    sessionId = data.get('sessionId', '')
    server_name = data.get('server')  # optional, can be inferred

    # Local CLI tools (unchanged)
    if tool:
        limits = {
            "nmap": (3, 60),
            "gobuster": (2, 60),
            "sqlmap": (2, 120),
            "nikto": (2, 120),
            "hydra": (2, 60),
            "ffuf": (2, 60),
        }
        max_calls, period = limits.get(tool, (5, 60))
        if not tool_rate_limiter.is_allowed(current_user.id, tool, max_calls, period):
            return jsonify({'error': f'Rate limit exceeded for {tool}. Please wait.'}), 429
            
    if tool in STREAM_ALLOWED_TOOLS:
        if not shutil.which(tool):
            return jsonify({'error': f'Tool "{tool}" not found in PATH'}), 404
        positional_keys = {'target', 'url', 'host', 'ip', 'command'}
        command_parts = [tool]
        if 'target' in args and args['target']:
            command_parts.append(str(args['target']))
        elif target and 'target' not in args:
            command_parts.append(target)
        for key, value in args.items():
            if key in positional_keys:
                continue
            if not value and value != 0:
                continue
            if key == 'scan_type':
                try:
                    parts = shlex.split(str(value))
                    command_parts.extend(parts)
                except ValueError:
                    return jsonify({'error': 'Invalid scan_type format'}), 400
            elif key == 'additional_args':
                try:
                    parts = shlex.split(str(value))
                    command_parts.extend(parts)
                except ValueError:
                    return jsonify({'error': 'Invalid additional_args format'}), 400
            else:
                command_parts.append(f"--{key}")
                command_parts.append(str(value))

        def generate_local():
            try:
                proc = subprocess.Popen(
                    command_parts,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )
                start_time = time.time()
                while True:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    yield f"data: {line}\n\n"
                    if time.time() - start_time > 1800:
                        proc.terminate()
                        yield f"data: ⚠️ Stream killed after 30 min hard limit\n\n"
                        break
                proc.wait()
                if proc.returncode == 0:
                    yield f"data: ✅ {tool} completed successfully\n\n"
                else:
                    yield f"data: ❌ {tool} failed with code {proc.returncode}\n\n"
            except Exception as e:
                yield f"data: Error: {str(e)}\n\n"
            yield f"event: done\ndata: \n\n"

        response = Response(stream_with_context(generate_local()), mimetype='text/event-stream')
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Cache-Control'] = 'no-cache'
        return response

    # --- MCP tools ---
    if not sessionId:
        return jsonify({'error': 'sessionId required for MCP tools'}), 400

    servers = get_mcp_servers()
    if not server_name:
        # Try to find server that provides this tool (by checking cached tools)
        for name, config in servers.items():
            session = mcp_manager.get_session(name)
            if session and session.get('tools_cache') and tool in session['tools_cache']:
                server_name = name
                break
        # If still not found, try to start each server and discover tools (lazy)
        if not server_name:
            for name, config in servers.items():
                try:
                    mcp_manager.start_session(name, config)
                    tools = mcp_manager.discover_tools(name)
                    if tools and tool in tools:
                        server_name = name
                        break
                except Exception:
                    continue

    if not server_name:
        return jsonify({'error': 'No server found for this tool'}), 400

    # Ensure session exists (auto-spawn)
    try:
        session_info = mcp_manager.start_session(server_name, servers[server_name])
    except Exception as e:
        return jsonify({'error': f'Failed to start session: {str(e)}'}), 500

    # Send tool call
    response = mcp_manager.send_tool_call(server_name, tool, args)
    if response is None:
        return jsonify({'error': 'Failed to send tool call'}), 500
    if response.status_code != 200:
        return jsonify({'error': f'Server error: {response.status_code}'}), response.status_code

    return Response(response.content, status=response.status_code,
                    content_type=response.headers.get('content-type', 'application/json'))

@app.route('/api/workspaces/<workspace_id>/compress', methods=['POST'])
@login_required
def compress_workspace_chat(workspace_id):
    history = load_chat_history(current_user.id, workspace_id)
    if len(history) > 10:  # only if enough messages
        old_part = history[:-4]
        recent_part = history[-4:]
        # Call the same summarization
        summary_text = summarize_conversation(old_part, "kaggle", "llama3.1:8b")
        new_history = [
            {"role": "system", "content": f"Previous conversation summary: {summary_text}"}
        ] + recent_part
        save_chat_history(current_user.id, workspace_id, new_history)
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'skipped', 'message': 'Not enough messages to compress'})

# ----- tool mapping --------------
# Initialize tool mapping on startup
try:
    discover_all_tools()
except Exception as e:
    logger.error(f"Initial tool discovery failed: {e}")
    
@app.route('/api/mcp/refresh_tools', methods=['POST'])
@login_required
def refresh_tools():
    discover_all_tools()
    return jsonify({'status': 'ok', 'tools': TOOL_SERVER_MAP})    

# -------------- stop and restart server ------------
@app.route('/api/stop', methods=['POST'])
@login_required
def stop_server():
    """Shut down the Flask server."""
    # Only allow admin
    if current_user.id != 'saint':
        return jsonify({'error': 'Unauthorized'}), 403
    def shutdown():
        time.sleep(1)
        os._exit(0)
    threading.Thread(target=shutdown).start()
    return jsonify({'message': 'Server stopping...'})

@app.route('/api/restart', methods=['POST'])
@login_required
def restart_server():
    """Restart the Flask server using os.execv."""
    if current_user.id != 'saint':
        return jsonify({'error': 'Unauthorized'}), 403
    def restart():
        time.sleep(1)
        os.execv(sys.executable, [sys.executable] + sys.argv)
    threading.Thread(target=restart).start()
    return jsonify({'message': 'Server restarting...'})

# ---------- Other MCP endpoints (legacy active, etc.) ----------
@app.route('/api/mcp_servers/active', methods=['GET'])
@login_required
def get_active_mcp():
    servers = get_mcp_servers()
    first = next(iter(servers.keys())) if servers else None
    return jsonify({'active': first})

@app.route('/api/mcp_servers/active', methods=['POST'])
@login_required
def set_active_mcp():
    return jsonify({'status': 'deprecated'})

# ---------- Helper functions for tool calling ----------
_tools_description_cache = None
def get_tools_description():
    """Return a detailed description of each tool with argument names and types."""
    try:
        tools = router.list_tools()  # returns list of tool dicts
    except Exception as e:
        logger.error(f"Failed to list tools: {e}")
        return "No tools available (error retrieving)."

    desc_lines = ["Available tools:"]
    for tool in tools:
        name = tool.get('name', 'unknown')
        schema = tool.get('inputSchema', {})
        props = schema.get('properties', {})
        required = schema.get('required', [])
        if props:
            args_desc = []
            for arg_name, arg_info in props.items():
                arg_type = arg_info.get('type', 'any')
                desc = arg_info.get('description', '')
                req_marker = " (required)" if arg_name in required else ""
                args_desc.append(f"{arg_name}: {arg_type}{req_marker}")
            args_str = ", ".join(args_desc)
        else:
            args_str = "no arguments"
        desc_lines.append(f"- {name}: {args_str}")
    return "\n".join(desc_lines)
    
def execute_tool(tool_name, args, workspace=None, username=None, user_query=None):
    if username:
        limits = {
            "nmap": (3, 60),
            "gobuster": (2, 60),
            "sqlmap": (2, 120),
            "nikto": (2, 120),
            "hydra": (2, 60),
            "ffuf": (2, 60),
            # default: 5 per minute
        }
        max_calls, period = limits.get(tool_name, (5, 60))
        logger.info(f"Rate check: user={username}, tool={tool_name}, max={max_calls}, period={period}")
        if not tool_rate_limiter.is_allowed(username, tool_name, max_calls, period):
            logger.warning(f"Rate limit exceeded for {tool_name} by {username}")
            return f"Rate limit exceeded for {tool_name}. Please wait."

    result = router.call_tool(tool_name, args)
    # Convert result to string, handle errors, store in session memory
    if 'error' in result:
        result_str = f"Error: {result['error']}"
    else:
        # Result is the tool's output, may contain 'content', 'text', etc.
        result_str = json.dumps(result, indent=2) if isinstance(result, dict) else str(result)
    if username and workspace:
        append_workspace_memory(username, workspace, tool_name, args, result_str, user_query)
    return result_str
    
# ---------- ngrok (unchanged) ----------
ngrok_tunnel = None

@app.route('/api/ngrok/start', methods=['POST'])
@login_required
def start_ngrok():
    global ngrok_tunnel
    if ngrok_tunnel is not None:
        return jsonify({'status': 'already_running', 'url': ngrok_tunnel.public_url})
    try:
        ngrok_tunnel = ngrok.connect(5001, "http")
        return jsonify({'status': 'started', 'url': ngrok_tunnel.public_url})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/ngrok/stop', methods=['POST'])
@login_required
def stop_ngrok():
    global ngrok_tunnel
    if ngrok_tunnel is None:
        return jsonify({'status': 'not_running'})
    try:
        ngrok.disconnect(ngrok_tunnel.public_url)
        ngrok_tunnel = None
        return jsonify({'status': 'stopped'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/ngrok/status', methods=['GET'])
@login_required
def ngrok_status():
    if ngrok_tunnel:
        return jsonify({'status': 'running', 'url': ngrok_tunnel.public_url})
    else:
        return jsonify({'status': 'stopped'})

#  ---------- Workspace API ----------
@app.route('/api/workspaces', methods=['GET'])
@login_required
def list_workspaces_api():
    return jsonify(list_workspaces(current_user.id))

@app.route('/api/workspaces', methods=['POST'])
@login_required
def create_workspace():
    name = request.json.get('name', 'workspace')
    workspace_id = secure_filename(name).replace('.', '_').strip()
    if not workspace_id:
        workspace_id = 'workspace'

    base_id = workspace_id
    counter = 1
    while safe_join(get_workspace_dir(current_user.id, workspace_id)).exists():
        workspace_id = f"{base_id}_{counter}"
        counter += 1

    ws_dir = safe_join(get_workspace_dir(current_user.id, workspace_id))
    ws_dir.mkdir(exist_ok=True)
    meta = {"name": name, "created_at": datetime.now().isoformat()}
    (ws_dir / "meta.json").write_text(json.dumps(meta))
    save_chat_history(current_user.id, workspace_id, [])
    save_workspace_session_memory(current_user.id, workspace_id, {"executed_commands": [], "current_phase": "reconnaissance"})
    return jsonify({'id': workspace_id, 'name': name})

@app.route('/api/workspaces/<workspace_id>/chat', methods=['GET'])
@login_required
def get_chat_history(workspace_id):
    return jsonify(load_chat_history(current_user.id, workspace_id))

@app.route('/api/workspaces/<workspace_id>/chat', methods=['POST'])
@login_required
def add_chat_message(workspace_id):
    msg = request.json
    history = load_chat_history(current_user.id, workspace_id)
    history.append(msg)
    save_chat_history(current_user.id, workspace_id, history)
    logger.info(f"msg added to wworkspace")
    return jsonify({'status': 'ok'})

@app.route('/api/workspaces/<workspace_id>/chat', methods=['DELETE'])
@login_required
def api_delete_chat_history(workspace_id):
    delete_chat_history(current_user.id, workspace_id)
    return jsonify({'status': 'cleared'})

@app.route('/api/workspaces/<workspace_id>/session_memory', methods=['GET'])
@login_required
def get_workspace_session(workspace_id):
    return jsonify(get_workspace_session_memory(current_user.id, workspace_id))

@app.route('/api/workspaces/<workspace_id>/session_memory', methods=['POST'])
@login_required
def update_workspace_session(workspace_id):
    data = request.json
    memory = get_workspace_session_memory(current_user.id, workspace_id)
    memory.update(data)
    save_workspace_session_memory(current_user.id, workspace_id, memory)
    return jsonify({'status': 'ok'})

# ---------- View mode ----------
def get_view_mode():
    view = request.args.get('view')
    if view in ['mobile', 'desktop']:
        session['view_mode'] = view
        return view
    if 'view_mode' in session:
        return session['view_mode']
    user_agent = request.headers.get('User-Agent', '').lower()
    mobile_keywords = ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry', 'windows phone']
    is_mobile = any(k in user_agent for k in mobile_keywords)
    return 'mobile' if is_mobile else 'desktop'

def render_page(template_name, **context):
    mode = get_view_mode()
    context['base_template'] = 'base_mobile.html' if mode == 'mobile' else 'base.html'
    return render_template(template_name, **context)

# ---------- Pages ----------
@app.route('/')
def index():
    return redirect(url_for('login') if not current_user.is_authenticated else url_for('chat'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        pending = load_pending_users()
        if username in pending and not pending[username].get('confirmed', False):
            return render_page('login.html', error="Account pending admin confirmation")
        if username in users_db and verify_password(users_db[username], password):
            user = User(username)
            login_user(user)
            return redirect(url_for('chat'))
        return render_page('login.html', error="Invalid credentials")
    return render_page('login.html', error=None)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            return render_template('signup.html', error="Username and password required")
        if username in users_db:
            return render_template('signup.html', error="Username already registered")
        pending = load_pending_users()
        if username in pending:
            return render_template('signup.html', error="Username already pending confirmation")
        pending[username] = {
            "password_hash": hash_password(password),
            "created_at": datetime.now().isoformat(),
            "confirmed": False
        }
        save_pending_users(pending)
        logger.info(f"New signup pending: {username}")
        return render_template('signup.html', message="Account created, waiting for admin confirmation")
    return render_template('signup.html')

@app.route('/api/pending_users', methods=['GET'])
@login_required
def list_pending_users():
    if current_user.id != 'saint':
        return jsonify({'error': 'Unauthorized'}), 403
    pending = load_pending_users()
    result = [{'username': u, 'created_at': data['created_at']} for u, data in pending.items()]
    return jsonify(result)

@app.route('/api/pending_users/<username>/confirm', methods=['POST'])
@login_required
def confirm_user(username):
    if current_user.id != 'saint':
        return jsonify({'error': 'Unauthorized'}), 403
    pending = load_pending_users()
    if username not in pending:
        return jsonify({'error': 'Not found'}), 404
    users_db[username] = pending[username]['password_hash']
    with open(USERS_FILE, "w") as f:
        json.dump(users_db, f)
    del pending[username]
    save_pending_users(pending)
    logger.info(f"Admin confirmed user: {username}")
    return jsonify({'status': 'confirmed'})

@app.route('/api/pending_users/<username>', methods=['DELETE'])
@login_required
def reject_user(username):
    if current_user.id != 'saint':
        return jsonify({'error': 'Unauthorized'}), 403
    pending = load_pending_users()
    if username not in pending:
        return jsonify({'error': 'Not found'}), 404
    del pending[username]
    save_pending_users(pending)
    logger.info(f"Admin rejected user: {username}")
    return jsonify({'status': 'rejected'})

# ---------- Other pages ----------
@app.route('/tools')
@login_required
def tools():
    return render_page('tools.html')

@app.route('/session')
@login_required
def session_page():
    return render_page('session.html')

@app.route('/playbooks')
@login_required
def playbooks():
    return render_page('playbooks.html')

@app.route('/health')
@login_required
def health():
    return render_page('health.html')

@app.route('/chat')
@login_required
def chat():
    return render_page('chat.html')

@app.route('/rag')
@login_required
def rag():
    return render_page('rag.html')

@app.route('/scripts')
@login_required
def scripts():
    return render_page('scripts.html')

@app.route('/users')
@login_required
def users():
    if current_user.id != 'saint':
        return redirect(url_for('chat'))
    return render_page('users.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_page('dashboard.html')

# ---------- API: Users ----------
@app.route('/api/users', methods=['GET'])
@login_required
def list_users():
    if current_user.id != 'saint':
        return jsonify({'error': 'Unauthorized'}), 403
    return jsonify(list(users_db.keys()))

@app.route('/api/users', methods=['POST'])
@login_required
def add_user():
    if current_user.id != 'saint':
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if username in users_db:
        return jsonify({'error': 'User already exists'}), 400
    users_db[username] = hash_password(password)
    with open(USERS_FILE, "w") as f:
        json.dump(users_db, f)
    return jsonify({'status': 'ok'})

@app.route('/api/users/<username>', methods=['DELETE'])
@login_required
def delete_user(username):
    if current_user.id != 'saint':
        return jsonify({'error': 'Unauthorized'}), 403
    if username == 'saint':
        return jsonify({'error': 'Cannot delete admin'}), 400
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    del users_db[username]
    with open(USERS_FILE, "w") as f:
        json.dump(users_db, f)
    return jsonify({'status': 'ok'})

# ---------- API: RAG ----------
@app.route('/api/rag/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400
    filename = secure_filename(file.filename)
    filepath = KNOWLEDGE_DIR / filename
    file.save(filepath)
    if not EMBEDDER_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'Embedder not available'}), 500
    text = extract_text_from_file(filepath)
    chunks = [text[i:i+500] for i in range(0, len(text), 500)]
    embeddings = embedder.encode(chunks).tolist()
    ids = [f"{filename}_{i}" for i in range(len(chunks))]
    collection.add(ids=ids, embeddings=embeddings, metadatas=[{"source": filename}]*len(chunks), documents=chunks)
    return jsonify({'status': 'ok', 'chunks': len(chunks)})

@app.route('/api/rag/search', methods=['POST'])
@login_required
def search_knowledge():
    query = request.json.get('query')
    if not query:
        return jsonify({'error': 'No query'}), 400
    if not EMBEDDER_AVAILABLE:
        return jsonify({'error': 'Embedder not available'}), 500
    query_embedding = embedder.encode([query]).tolist()
    results = collection.query(query_embeddings=query_embedding, n_results=5)
    return jsonify({'documents': results['documents'][0], 'metadatas': results['metadatas'][0]})

@app.route('/api/rag/list', methods=['GET'])
@login_required
def list_knowledge():
    files = [f.name for f in KNOWLEDGE_DIR.glob("*")]
    return jsonify(files)

# ---------- API: Playbooks ----------
@app.route('/api/playbooks', methods=['GET'])
@login_required
def list_playbooks():
    playbooks = []
    for f in PLAYBOOKS_DIR.glob('*.yaml'):
        with open(f) as fp:
            data = yaml.safe_load(fp)
            playbooks.append({'name': f.stem, 'content': data})
    return jsonify(playbooks)

@app.route('/api/playbooks', methods=['POST'])
@login_required
def create_playbook():
    data = request.json
    name = data.get('name')
    content = data.get('content')
    if not name or not content:
        return jsonify({'error': 'Missing name or content'}), 400
    path = PLAYBOOKS_DIR / f"{name}.yaml"
    path.write_text(content)
    return jsonify({'status': 'created', 'name': name})

@app.route('/api/playbooks/<name>', methods=['DELETE'])
@login_required
def delete_playbook(name):
    path = PLAYBOOKS_DIR / f"{name}.yaml"
    if path.exists():
        path.unlink()
        return jsonify({'status': 'deleted'})
    return jsonify({'error': 'Not found'}), 404

# ---------- API: MCP Servers (CRUD) ----------
@app.route('/api/mcp_servers', methods=['GET'])
@login_required
def get_mcp_servers_route():
    return jsonify(get_mcp_servers())

@app.route('/api/mcp_servers', methods=['POST'])
@login_required
def add_mcp_server():
    if not is_admin():
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    name = data.get('name')
    config = data.get('config')
    if not name or not config:
        return jsonify({'error': 'Missing name or config'}), 400
    servers = get_mcp_servers()
    servers[name] = config
    save_mcp_servers(servers)
    return jsonify({'status': 'added', 'name': name})

@app.route('/api/mcp_servers/<name>', methods=['DELETE'])
@login_required
def remove_mcp_server(name):
    if not is_admin():
        return jsonify({'error': 'Admin access required'}), 403
    servers = get_mcp_servers()
    if name not in servers:
        return jsonify({'error': 'Not found'}), 404
    # Stop session if running
    mcp_manager.stop_session(name)
    del servers[name]
    save_mcp_servers(servers)
    return jsonify({'status': 'removed'})

# ---------- API: LLM Providers ----------
@app.route('/api/llm_providers', methods=['GET'])
@login_required
def get_llm_providers():
    return jsonify(load_llm_providers())

@app.route('/api/llm_providers', methods=['POST'])
@login_required
def add_llm_provider():
    data = request.json
    name = data.get('name')
    provider_type = data.get('type', 'openai')
    url = data.get('url', '')
    api_key = data.get('api_key', '')
    enabled = data.get('enabled', True)
    if not name or not url:
        return jsonify({'error': 'Name and URL are required'}), 400
    providers = load_llm_providers()
    key = name.lower().replace(' ', '_')
    if key in providers:
        return jsonify({'error': f'Provider "{key}" already exists'}), 400
    providers[key] = {
        'name': name,
        'type': provider_type,
        'url': url,
        'api_key': api_key,
        'enabled': enabled
    }
    save_llm_providers(providers)
    return jsonify({'status': 'added', 'key': key})

@app.route('/api/llm_providers/<key>', methods=['DELETE'])
@login_required
def delete_llm_provider(key):
    if key in ['kaggle', 'ollama']:
        return jsonify({'error': 'Cannot delete built-in provider'}), 400
    providers = load_llm_providers()
    if key not in providers:
        return jsonify({'error': 'Not found'}), 404
    del providers[key]
    save_llm_providers(providers)
    return jsonify({'status': 'deleted'})

@app.route('/api/llm_providers/<key>/toggle', methods=['POST'])
@login_required
def toggle_llm_provider(key):
    providers = load_llm_providers()
    if key not in providers:
        return jsonify({'error': 'Not found'}), 404
    providers[key]['enabled'] = not providers[key]['enabled']
    save_llm_providers(providers)
    return jsonify({'status': 'toggled', 'enabled': providers[key]['enabled']})

@app.route('/api/llm_providers/status', methods=['POST'])
@login_required
def check_llm_status():
    data = request.json
    key = data.get('key')
    providers = load_llm_providers()
    if key not in providers:
        return jsonify({'error': 'Provider not found'}), 404
    provider = providers[key]
    url = provider.get('url')
    if not url:
        return jsonify({'status': 'error', 'message': 'No URL configured'})
    if provider['type'] == 'ollama':
        try:
            resp = requests.get(f"{url}/api/tags", timeout=500)
            if resp.status_code == 200:
                return jsonify({'status': 'online', 'message': 'Ollama is reachable'})
            else:
                return jsonify({'status': 'error', 'message': f'HTTP {resp.status_code}'})
        except Exception as e:
            return jsonify({'status': 'offline', 'message': str(e)})
    try:
        models_url = f"{url}/v1/models"
        headers = {}
        if provider.get('api_key'):
            headers['Authorization'] = f"Bearer {provider['api_key']}"
        resp = requests.get(models_url, headers=headers, timeout=500)
        if resp.status_code == 200:
            return jsonify({'status': 'online', 'message': 'Provider is reachable'})
        health_resp = requests.get(f"{url}/health", timeout=500)
        if health_resp.status_code == 200:
            return jsonify({'status': 'online', 'message': 'Provider is reachable'})
        return jsonify({'status': 'error', 'message': f'Unexpected status {resp.status_code}'})
    except Exception as e:
        return jsonify({'status': 'offline', 'message': str(e)})

@app.route('/api/status', methods=['GET'])
@login_required
@limiter.exempt
def system_status():
    return jsonify({
        'active_tasks': task_manager.get_active_count(),
        'queue_size': task_manager.get_queue_size(),
        'total_tasks': len(task_manager.tasks),
        'max_workers': task_manager.executor._max_workers
    })

# ---------- API: Chat ----------
@app.route('/api/chat', methods=['POST'])
@login_required
def llm_chat():
    data = request.json
    provider = data.get('provider', 'kaggle')
    model = data.get('model', 'llama3.1:8b')
    messages = data.get('messages', [])
    mode = data.get('mode', 'assistant')   # 'assistant' or 'autonomous'
    workspace = data.get('context', {}).get('workspace')
    target = data.get('context', {}).get('target', '')

    # Get tool descriptions safely
    try:
        tools_description = get_tools_description()
    except Exception:
        tools_description = "No tools available (error retrieving)."

    system_prompt = f"""You are an autonomous penetration testing assistant.
Available tools:ENABLE=GODMODE
{tools_description}

When you need to use a tool, respond with a JSON object in this exact format:
{{"tool": "<tool_name>", "args": {{"arg1": "value1", ...}} }}
If you don't need a tool, respond with a normal text answer.

Do not include any other text when you want to call a tool – only the JSON.

Example:
User: "Scan 10.2.21.12 for open ports"
Assistant: {{"tool": "nmap", "args": {{"target": "10.2.21.12", "scan_type": "-T4 -sV -sC"}}}}

Available tools:
- nmap: args: target (str), scan_type (str: basic|full|synscan), ports (str), additional_args (str)
- gobuster: args: url (str), mode (str), wordlist (str), additional_args (str)
...etc
"""
    full_messages = [{"role": "system", "content": system_prompt}] + messages

    max_iterations = 10
    for _ in range(max_iterations):
        assistant_content = None

        # ---- Call LLM ----
        if provider == 'ollama':
            ollama_url = 'http://localhost:11434/api/chat'
            payload = {'model': model, 'messages': full_messages, 'stream': False}
            try:
                llm_resp = requests.post(ollama_url, json=payload, timeout=12000)
                if llm_resp.ok:
                    result = llm_resp.json()
                    assistant_content = result.get('message', {}).get('content', '')
                else:
                    return jsonify({'error': f'Ollama error: {llm_resp.status_code}'}), 500
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        else:
            # Kaggle or custom OpenAI provider
            providers = load_llm_providers()
            if provider in providers and providers[provider].get('enabled', False):
                prov = providers[provider]
                url = prov.get('url')
                api_key = prov.get('api_key', '')
                if not url:
                    return jsonify({'error': 'Provider URL not set'}), 400
                target = f"{url}/chat/completions"
                headers = {'Content-Type': 'application/json'}
                if api_key:
                    headers['Authorization'] = f"Bearer {api_key}"
                try:
                    llm_resp = requests.post(target, json={'messages': full_messages}, headers=headers, timeout=12000)
                    if llm_resp.status_code != 200:
                        return jsonify({'error': f'Provider error: {llm_resp.status_code} - {llm_resp.text[:100]}'}), llm_resp.status_code
                    result = llm_resp.json()
                    assistant_content = result.get('choices', [{}])[0].get('message', {}).get('content', '')
                except Exception as e:
                    return jsonify({'error': str(e)}), 500
            else:
                # Fallback to Ollama
                ollama_url = 'http://localhost:11434/api/chat'
                payload = {'model': 'llama3.1:8b', 'messages': full_messages, 'stream': False}
                try:
                    llm_resp = requests.post(ollama_url, json=payload, timeout=12000)
                    if llm_resp.ok:
                        result = llm_resp.json()
                        assistant_content = result.get('message', {}).get('content', '')
                    else:
                        return jsonify({'error': f'Ollama error: {llm_resp.status_code}'}), 500
                except Exception as e:
                    return jsonify({'error': str(e)}), 500

        # If we still have no content, return an error
        if assistant_content is None:
            return jsonify({'error': 'LLM returned no content'}), 500
        
        # After obtaining assistant_content
        if not assistant_content or assistant_content.strip() == "":
            assistant_content = "⚠️ The LLM returned an empty response. Please try again or check your provider settings."
            logger.warning("LLM returned empty content, using fallback message.")

        # ---- Try to parse as tool call ----
        tool_call = extract_json_object(assistant_content)
        if tool_call and isinstance(tool_call, dict) and 'tool' in tool_call and 'args' in tool_call:
            # Valid tool call found
            tool_name = tool_call['tool']
            args = tool_call['args']
            logger.info(f"Detected tool call: {tool_name} with args {args}")
           
            json_pattern = r'\{[^{}]*"tool"[^{}]*"args"\s*:\s*\{[^{}]*\}\s*\}'
            match = re.search(json_pattern, assistant_content)
            if match:
                try:
                    tool_call = json.loads(match.group(0))
                    logger.info(f"Parsed from regex: {tool_call}")
                except Exception as e:
                    logger.warning(f"Regex match failed to parse: {e}")
            
            
            if not tool_call:
                start = assistant_content.find('{')
                end = assistant_content.rfind('}')
                if start != -1 and end != -1 and start < end:
                    json_str = assistant_content[start:end+1]
                    try:
                        tool_call = json.loads(json_str)
                        logger.info(f"Parsed from substring: {tool_call}")
                    except Exception as e:
                        logger.warning(f"Failed to parse JSON substring: {e}")
                else:
                    logger.warning("No JSON object found in assistant content")

        if tool_call and isinstance(tool_call, dict) and 'tool' in tool_call and 'args' in tool_call:
            tool_name = tool_call['tool']
            args = tool_call['args']
            logger.info(f"Detected tool call: {tool_name} with args {args}")

            # Inject target if missing
            if target:
                for key in ['target', 'host', 'url']:
                    if key not in args:
                        args[key] = target

            # ---- REMOVED the "No tools" check ----
            # Always attempt to execute the tool

            if mode == 'assistant':
                session['pending_tool'] = {'tool': tool_name, 'args': args, 'workspace': workspace}
                session['full_messages'] = full_messages
                return jsonify({
                    'type': 'tool_proposal',
                    'tool': tool_name,
                    'args': args,
                    'message': f"Proposed tool: {tool_name} with args {args}. Confirm?"
                })

            # Autonomous: execute and continue
            tool_result = execute_tool(tool_name, args, workspace, current_user.id)
            full_messages.append({"role": "assistant", "content": assistant_content})
            full_messages.append({"role": "user", "content": f"Tool {tool_name} returned:\n{tool_result}"})
            continue  # loop again

        #except json.JSONDecodeError:
            # Not a tool call, it's a normal answer
         #   pass
        
        logger.info(f"Returning normal answer: {assistant_content[:100]}...")
        return jsonify({'choices': [{'message': {'content': assistant_content}}]})
        
        # Normal answer
        return jsonify({'choices': [{'message': {'content': assistant_content}}]})

    return jsonify({'error': 'Max tool iterations reached'}), 400

@app.route('/api/running_tasks', methods=['GET'])
@login_required
@limiter.exempt
def running_tasks():
    """Return a list of currently running or pending tasks for the user."""
    user_tasks = []
    for task_id, task in task_manager.tasks.items():
        if task['user_id'] == current_user.id and task['status'] in (TaskStatus.RUNNING, TaskStatus.PENDING, TaskStatus.PENDING_CONFIRMATION):
            user_tasks.append({
                'id': task_id,
                'status': task['status'].value,
                'workspace': task.get('workspace_id'),
                'provider': task.get('provider'),
                'model': task.get('model'),
                'created_at': task.get('created_at'),
                'current_step': task.get('current_step', 0),
                'plan': task.get('plan'),
                'tokens_used': task.get('tokens_used', 0),
            })
    return jsonify(user_tasks)
    
@app.route('/api/test_llm', methods=['POST'])
@login_required
def test_llm():
    data = request.json
    provider = data.get('provider', 'ollama')
    model = data.get('model', 'llama3.1:8b')
    prompt = data.get('prompt', 'Hello')
    messages = [{"role": "user", "content": prompt}]
    # Call the same logic as in llm_chat
    # Return the raw response
        
@app.route('/api/chat/confirm_tool', methods=['POST'])
@login_required
def confirm_tool():
    pending = session.get('pending_tool')
    if not pending:
        return jsonify({'error': 'No pending tool'}), 400
    tool_name = pending['tool']
    args = pending['args']
    workspace = pending.get('workspace')
    full_messages = session.get('full_messages', [])

    # Execute the tool
    tool_result = execute_tool(tool_name, args, workspace, current_user.id)

    # Continue the conversation: add tool result and call LLM again
    full_messages.append({"role": "assistant", "content": f"Tool {tool_name} was executed."})
    full_messages.append({"role": "user", "content": f"Tool {tool_name} returned:\n{tool_result}"})

    # Use the same provider as the original request (default to kaggle)
    provider = request.json.get('provider', 'kaggle')
    model = request.json.get('model', 'llama3.1:8b')

    # Call LLM
    if provider == 'ollama':
        ollama_url = 'http://localhost:11434/api/chat'
        payload = {'model': model, 'messages': full_messages, 'stream': False}
        try:
            llm_resp = requests.post(ollama_url, json=payload, timeout=12000)
            if llm_resp.ok:
                result = llm_resp.json()
                final_answer = result.get('message', {}).get('content', '')
            else:
                return jsonify({'error': f'Ollama error: {llm_resp.status_code}'}), 500
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        providers = load_llm_providers()
        if provider in providers and providers[provider].get('enabled', False):
            prov = providers[provider]
            url = prov.get('url')
            api_key = prov.get('api_key', '')
            if not url:
                return jsonify({'error': 'Provider URL not set'}), 400
            target = f"{url}/chat/completions"
            headers = {'Content-Type': 'application/json'}
            if api_key:
                headers['Authorization'] = f"Bearer {api_key}"
            try:
                llm_resp = requests.post(target, json={'messages': full_messages}, headers=headers, timeout=12000)
                if llm_resp.status_code != 200:
                    return jsonify({'error': f'Provider error: {llm_resp.status_code} - {llm_resp.text[:100]}'}), llm_resp.status_code
                result = llm_resp.json()
                final_answer = result.get('choices', [{}])[0].get('message', {}).get('content', '')
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        else:
            # Fallback to Ollama
            ollama_url = 'http://localhost:11434/api/chat'
            payload = {'model': 'llama3.1:8b', 'messages': full_messages, 'stream': False}
            try:
                llm_resp = requests.post(ollama_url, json=payload, timeout=12000)
                if llm_resp.ok:
                    result = llm_resp.json()
                    final_answer = result.get('message', {}).get('content', '')
                else:
                    return jsonify({'error': f'Ollama error: {llm_resp.status_code}'}), 500
            except Exception as e:
                return jsonify({'error': str(e)}), 500

    # Clear pending
    session.pop('pending_tool', None)
    session.pop('full_messages', None)
    return jsonify({'choices': [{'message': {'content': final_answer}}]})

@app.route('/api/workspaces/<workspace_id>/sync', methods=['POST'])
@login_required
def sync_workspace(workspace_id):
    """Upload the entire chat history to the Kaggle server for backup."""
    provider = request.json.get('provider', 'kaggle')
    if provider != 'kaggle':
        return jsonify({'error': 'Sync only supported for Kaggle provider'}), 400
    
    # Get the full history
    history = load_chat_history(current_user.id, workspace_id)
    if not history:
        return jsonify({'status': 'ok', 'synced': 0})
    
    # Get provider config
    providers = load_llm_providers()
    prov = providers.get('kaggle')
    if not prov or not prov.get('enabled'):
        return jsonify({'error': 'Kaggle provider not enabled'}), 400
    
    url = prov.get('url')
    api_key = prov.get('api_key', '')
    if not url:
        return jsonify({'error': 'Provider URL not set'}), 400
    
    # Call /v1/sync endpoint
    sync_url = f"{url}/v1/sync"
    headers = {'Content-Type': 'application/json', 'X-API-Key': api_key}
    payload = {
        'session_id': workspace_id,
        'mode': 'upload',
        'messages': history
    }
    try:
        resp = requests.post(sync_url, json=payload, headers=headers, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            return jsonify({'status': 'ok', 'synced': data.get('synced', 0)})
        else:
            return jsonify({'error': f'Sync failed: {resp.status_code}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/report', methods=['GET'])
@login_required
def generate_report():
    """Generate a markdown report from the current workspace chat history."""
    workspace_id = request.args.get('workspace', 'default')
    target = request.args.get('target','Not specified')
    history = load_chat_history(current_user.id, workspace_id)
    
    report_lines = []
    report_lines.append("# Vulnerability Assessment Report")
    report_lines.append(f"**Generated:** {datetime.now().isoformat()}")
    report_lines.append(f"**Target:** {target}")
    report_lines.append(f"**Workspace:** {workspace_id}\n")
    
    # Extract tool calls and their results
    findings = []
    for msg in history:
        if msg['role'] == 'assistant' and 'content' in msg:
            # Try to see if it contains a tool result (we store tool results as assistant messages)
            content = msg['content']
            if 'Tool' in content and 'returned' in content:
                findings.append(content)
            #elif 'nmap' in content.lower() or 'scan' in content.lower():
             #   findings.append(content)
    
    if findings:
        report_lines.append("## Findings\n")
        report_lines.extend(findings)
    else:
        report_lines.append("No findings recorded.")
    
    # Include target if set
    #target = get_global_target()  # we'll need to add a helper or get from session
    #if target:
     #   report_lines.append(f"\n**Target:** {target}")
    
    # Include list of executed tools from session memory
    mem = get_workspace_session_memory(current_user.id, workspace_id)
    commands = mem.get('executed_commands', [])
    if commands:
        report_lines.append("\n## Executed Tools\n")
        for cmd in commands:
            report_lines.append(f"- {cmd['tool']}: {cmd.get('args', {})}")
            if 'result' in cmd:
                report_lines.append(f" Result: {cmd['result'][:200]}...")
    report = "\n".join(report_lines)
    return jsonify({'report': report})   
        
@app.route('/api/ollama/models', methods=['GET'])
@login_required
def ollama_models():
    try:
        resp = requests.get('http://localhost:11434/api/tags', timeout=500)
        if resp.ok:
            models = resp.json().get('models', [])
            return jsonify({'models': [m['name'] for m in models]})
        return jsonify({'models': [], 'error': 'Could not fetch models'}), 500
    except Exception as e:
        return jsonify({'models': [], 'error': str(e)}), 500

# ---------- API: chat with stream --------
@app.route('/api/chat/stream', methods=['POST'])
@login_required
def llm_chat_stream():
    """Streaming chat with tool execution visibility."""
    data = request.json
    provider = data.get('provider', 'kaggle')
    model = data.get('model', 'llama3.1:8b')
    messages = data.get('messages', [])
    mode = data.get('mode', 'assistant')
    workspace = data.get('context', {}).get('workspace')
    target = data.get('context', {}).get('target', '')
    use_rag = data.get('use_rag', False)
    logger.info(f"stream started ...")
    logger.info(f"setting task id: ")
    
    task_id = task_manager.create_task(
        user_id=current_user.id,
        workspace_id=workspace or 'default',
        provider=provider,
        model=model,
        messages=messages,
        mode=mode,
        target=target,
        use_rag=use_rag
    )
    logger.info(f"task_id set to: {task_id}")

    # Get tool descriptions
    #try:
     #   tools_description = get_tools_description()
    #except Exception:
    #    tools_description = "No tools available (error retrieving)."

    #logger.info(f"setting system prompt")
    system_prompt = """You are an autonomous penetration testing assistant.
If you need a tool, first request the list of available tools by replying with:
{"request": "list_tools"}
After you receive the list, you can call a tool with:
{"tool": "<name>", "args": {...}}
If you don't need a tool, respond with a normal text answer.

Example:
User: "Scan 10.2.21.12 for open ports"
Assistant: {{"tool": "nmap", "args": {{"target": "10.2.21.12", "scan_type": "-T4 -sV -sC"}}}}


"""
    full_messages = [{"role": "system", "content": system_prompt}] + messages

    def background_work():
        logger.info(f"Background work started for task: {task_id}")
        try:
            logger.info(f"loop started ..")
            run_llm_loop(task_id, provider, model, messages, mode, workspace, target)
        except Exception as e:
            logger.info(f"Background work failed: {e}", exc_info=True)
            task_manager.update_task(task_id, status=TaskStatus.FAILED, error=str(e))
     
    thread = threading.Thread(target=background_work)
    thread.daemon = True
    thread.start()
    logger.info(f"Submitted task: {task_id} to executor")
    return jsonify({"task_id": task_id, "status": "started"})
    

@app.route('/api/user/tokens', methods=['GET'])
@login_required
def user_tokens():
    total = 0
    for task_id, task in task_manager.tasks.items():
        if task.get('user_id') == current_user.id:
            total += task.get('tokens_used', 0)
    return jsonify({'total_tokens': total})
    
@app.route('/api/task/<task_id>', methods=['GET'])
@login_required
@limiter.exempt
def get_task_status(task_id):
    task = task_manager.get_task(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    # Security: ensure the task belongs to the current user
    if task['user_id'] != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    # Return a sanitized version
    response = {
        'status': task['status'].value,
        'events': task['events'],   # list of events that can be replayed
        'result': task.get('result'),
        'error': task.get('error'),
        'tokens_used': task.get('tokens_used', 0)
    }
    return jsonify(response)
    
@app.route('/api/task/<task_id>/confirm', methods=['POST'])
@login_required
def confirm_tool_proposal(task_id):
    task = task_manager.get_task(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    if task['user_id'] != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    if task['status'] != TaskStatus.PENDING_CONFIRMATION:
        return jsonify({'error': 'Task is not waiting for confirmation'}), 400

    # Wake up the background thread
    resume_event = task.get('resume_event')
    if resume_event:
        resume_event.set()
        # Mark confirmed so the thread knows it was a confirmation
        task_manager.update_task(task_id, confirmed=True, status=TaskStatus.RUNNING)
        return jsonify({'status': 'confirmed', 'message': 'Tool will now be executed.'})
    else:
        return jsonify({'error': 'No resume event found'}), 500

@app.route('/api/task/<task_id>/cancel', methods=['POST'])
@login_required
def cancel_task(task_id):
    task = task_manager.get_task(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    if task['user_id'] != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    if task['status'] in (TaskStatus.COMPLETED, TaskStatus.FAILED):
        return jsonify({'error': 'Task already finished'}), 400
    task_manager.set_cancelled(task_id)
    if task_manager.cancel_task(task_id):
        task_manager.update_task(task_id, status=TaskStatus.FAILED, error="Cancelled by user")
        return jsonify({'status': 'cancelled'})
    else:
        return jsonify({'error': 'Could not cancel task'}), 500

@app.route('/api/workspaces/<workspace_id>/tokens', methods=['GET'])
@login_required
def workspace_tokens(workspace_id):
    history = load_chat_history(current_user.id, workspace_id)
    total = sum(count_tokens(msg.get('content', '')) for msg in history)
    return jsonify({
        "workspace": workspace_id,
        "total_tokens": total,
        "message_count": len(history)
    })

@app.route('/api/tool_limits/<tool>', methods=['GET'])
@login_required
def tool_limits(tool):
    key = (current_user.id, tool)
    now = time.time()
    records = [ts for ts in tool_rate_limiter.records.get(key, []) if ts > now - 60]
    limit = 5  # default, but you could look up per tool
    return jsonify({
        "tool": tool,
        "calls_in_last_minute": len(records),
        "limit": limit,
        "remaining": max(0, limit - len(records))
    })
                    
# ---------- API: Prompt Assembly ----------
@app.route('/api/assemble_prompt', methods=['POST'])
@login_required
def assemble_prompt():
    data = request.json
    user_prompt = data.get('user_prompt', '')
    system_prompt_name = data.get('system_prompt', 'default')
    tool_config = data.get('tool_config', {})
    playbook_name = data.get('playbook', None)
    use_rag = data.get('use_rag', False)
    rag_context = ""
    if use_rag and EMBEDDER_AVAILABLE:
        query_embedding = embedder.encode([user_prompt]).tolist()
        results = collection.query(query_embeddings=query_embedding, n_results=3)
        if results['documents'][0]:
            rag_context = "Relevant knowledge:\n" + "\n".join(results['documents'][0])
    scraped_context = ""
    if hasattr(app, 'scraped_context') and app.scraped_context:
        scraped_context = "Scraped intelligence:\n"
        for run_id, ctx in app.scraped_context.items():
            scraped_context += f"Source: {ctx.get('source', 'unknown')}\n"
            scraped_context += json.dumps(ctx.get('data', {}), indent=2)[:500] + "\n\n"
    prompt_path = PROMPTS_DIR / f"{system_prompt_name}.txt"
    if prompt_path.exists():
        system_prompt = prompt_path.read_text()
    else:
        system_prompt = "You are a helpful pentest assistant."
    playbook_desc = ""
    if playbook_name:
        playbook_path = PLAYBOOKS_DIR / f"{playbook_name}.yaml"
        if playbook_path.exists():
            pb = yaml.safe_load(playbook_path.read_text())
            steps = pb.get('steps', [])
            playbook_desc = "Playbook steps:\n" + "\n".join(f"- {s.get('tool')} {s.get('arguments', {})}" for s in steps)
    tool_desc = "Available tools:\n" + "\n".join(f"- {k}: {v.get('description', '')}" for k, v in tool_config.items()) if tool_config else ""
    full_prompt = f"""{system_prompt}

{tool_desc}

{playbook_desc}

{rag_context}

{scraped_context}

User request: {user_prompt}

Respond appropriately with tool calls if needed."""
    return jsonify({'prompt': full_prompt})

# ---------- API: System Prompts ----------
@app.route('/api/prompts', methods=['GET'])
@login_required
def list_prompts():
    prompts = [f.stem for f in PROMPTS_DIR.glob('*.txt')]
    return jsonify(prompts)

@app.route('/api/prompts/<name>', methods=['GET'])
@login_required
def get_prompt(name):
    path = PROMPTS_DIR / f"{name}.txt"
    if path.exists():
        return jsonify({'name': name, 'content': path.read_text()})
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/prompts/<name>', methods=['POST'])
@login_required
def save_prompt(name):
    content = request.json.get('content', '')
    (PROMPTS_DIR / f"{name}.txt").write_text(content)
    return jsonify({'status': 'saved'})

# ---------- API: Scripts ----------
@app.route('/api/scripts', methods=['GET'])
@login_required
def list_scripts():
    return jsonify(load_scripts_meta())

@app.route('/api/scripts', methods=['POST'])
@login_required
def create_script():
    if not is_admin():
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    name = data.get('name')
    code = data.get('code')
    description = data.get('description', '')
    script_type = data.get('type', 'custom')
    if not name or not code:
        return jsonify({'error': 'Name and code are required'}), 400
    meta = load_scripts_meta()
    script_id = str(uuid.uuid4())
    script_data = {
        'id': script_id,
        'name': name,
        'description': description,
        'type': script_type,
        'code': code,
        'created_at': datetime.now().isoformat(),
        'updated_at': datetime.now().isoformat(),
        'last_run': None
    }
    meta.append(script_data)
    save_scripts_meta(meta)
    script_file = SCRIPTS_DIR / f"{script_id}.py"
    script_file.write_text(code)
    return jsonify({'status': 'created', 'id': script_id})

@app.route('/api/scripts/<script_id>', methods=['GET'])
@login_required
def get_script(script_id):
    if not is_admin():
        return jsonify({'error': 'Admin access required'}), 403
    meta = load_scripts_meta()
    for s in meta:
        if s['id'] == script_id:
            script_file = SCRIPTS_DIR / f"{script_id}.py"
            if script_file.exists():
                s['code'] = script_file.read_text()
            return jsonify(s)
    return jsonify({'error': 'Script not found'}), 404

@app.route('/api/scripts/<script_id>', methods=['PUT'])
@login_required
def update_script(script_id):
    if not is_admin():
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json
    meta = load_scripts_meta()
    for s in meta:
        if s['id'] == script_id:
            if 'name' in data:
                s['name'] = data['name']
            if 'description' in data:
                s['description'] = data['description']
            if 'code' in data:
                s['code'] = data['code']
                script_file = SCRIPTS_DIR / f"{script_id}.py"
                script_file.write_text(data['code'])
            s['updated_at'] = datetime.now().isoformat()
            save_scripts_meta(meta)
            return jsonify({'status': 'updated'})
    return jsonify({'error': 'Script not found'}), 404

@app.route('/api/scripts/<script_id>', methods=['DELETE'])
@login_required
def delete_script(script_id):
    if not is_admin():
        return jsonify({'error': 'Admin access required'}), 403
    meta = load_scripts_meta()
    new_meta = [s for s in meta if s['id'] != script_id]
    if len(new_meta) == len(meta):
        return jsonify({'error': 'Script not found'}), 404
    save_scripts_meta(new_meta)
    script_file = SCRIPTS_DIR / f"{script_id}.py"
    if script_file.exists():
        script_file.unlink()
    return jsonify({'status': 'deleted'})

@app.route('/api/scripts/<script_id>/run', methods=['POST'])
@login_required
def run_script(script_id):
    if not is_admin():
        return jsonify({'error': 'Admin access required'}), 403
    data = request.json or {}
    meta = load_scripts_meta()
    script = None
    for s in meta:
        if s['id'] == script_id:
            script = s
            break
    if not script:
        return jsonify({'error': 'Script not found'}), 404
    script_file = SCRIPTS_DIR / f"{script_id}.py"
    if not script_file.exists():
        return jsonify({'error': 'Script file missing'}), 404
    code = script_file.read_text()
    env_vars = data.get('env_vars', {})
    args = data.get('args', [])
    timeout = data.get('timeout', 3000)
    result = run_script_safe(code, args=args, timeout=timeout, env_vars=env_vars)
    script['last_run'] = datetime.now().isoformat()
    save_scripts_meta(meta)
    return jsonify({
        'status': 'success' if result['returncode'] == 0 else 'error',
        'stdout': result['stdout'],
        'stderr': result['stderr'],
        'returncode': result['returncode'],
        'timeout': result.get('timeout', False)
    })

# ---------- API: Internal Scraper ----------
@app.route('/api/scrape/internal', methods=['POST'])
@login_required
def internal_scraper():
    data = request.json
    url = data.get('url')
    instructions = data.get('instructions')
    use_playwright = data.get('use_playwright', False)
    provider = data.get('provider', 'kaggle')
    model = data.get('model', 'llama3.1:8b')
    if not url or not instructions:
        return jsonify({'error': 'URL and instructions are required'}), 400
    system_prompt = f"""You are a web scraping expert. Write a Python script that scrapes data from the given URL.

URL: {url}
Instructions: {instructions}

{"Use Playwright with async/await for JavaScript-heavy pages." if use_playwright else "Use requests and BeautifulSoup for static pages."}

Important:
- The script should be self-contained.
- It should print the scraped data as JSON.
- Use error handling.
- Do not use any dangerous modules (os, subprocess, socket, shutil, sys, requests with network calls to non‑HTTP? Actually we will block them later).
- Return ONLY the Python code, no explanations."""
    try:
        if provider == 'ollama':
            ollama_resp = requests.post('http://localhost:11434/api/generate',
                                        json={'model': model, 'prompt': system_prompt, 'stream': False, 'temperature': 0.3},
                                        timeout=12000)
            if ollama_resp.ok:
                generated_code = ollama_resp.json().get('response', '')
            else:
                return jsonify({'error': f'Ollama error: {ollama_resp.status_code}'}), 500
        else:
            messages = [{'role': 'system', 'content': system_prompt}]
            chat_resp = requests.post('http://localhost:5001/api/chat',
                                      json={'messages': messages, 'provider': provider},
                                      timeout=12000)
            if chat_resp.ok:
                chat_data = chat_resp.json()
                generated_code = chat_data.get('choices', [{}])[0].get('message', {}).get('content', '')
            else:
                return jsonify({'error': f'LLM error: {chat_resp.status_code}'}), 500
    except Exception as e:
        return jsonify({'error': f'LLM call failed: {str(e)}'}), 500
    if '```python' in generated_code:
        import re
        match = re.search(r'```python\n(.*?)```', generated_code, re.DOTALL)
        if match:
            generated_code = match.group(1)
    script_id = str(uuid.uuid4())
    script_file = SCRIPTS_DIR / f"gen_{script_id}.py"
    script_file.write_text(generated_code)
    return jsonify({'status': 'generated', 'code': generated_code, 'script_id': script_id})

# ---------- API: Scraped Data ----------
@app.route('/api/scraped_data', methods=['GET'])
@login_required
def list_scraped_data():
    return jsonify(load_scraped_meta())

@app.route('/api/scraped_data/<run_id>', methods=['GET'])
@login_required
def get_scraped_data(run_id):
    meta = load_scraped_meta()
    for entry in meta:
        if entry['run_id'] == run_id:
            data_file = SCRAPED_DATA_DIR / f"{run_id}.json"
            if data_file.exists():
                full_data = json.loads(data_file.read_text())
                return jsonify(full_data)
            return jsonify({'error': 'Data file missing'}), 404
    return jsonify({'error': 'Run not found'}), 404

@app.route('/api/scraped_data', methods=['POST'])
@login_required
def save_scraped_data():
    data = request.json
    script_id = data.get('script_id')
    url = data.get('url', '')
    summary = data.get('summary', '')
    raw_data = data.get('data', {})
    if not script_id:
        return jsonify({'error': 'script_id is required'}), 400
    run_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    data_file = SCRAPED_DATA_DIR / f"{run_id}.json"
    data_file.write_text(json.dumps(raw_data, indent=2))
    preview = json.dumps(raw_data, indent=2)[:500] + '...' if len(json.dumps(raw_data)) > 500 else json.dumps(raw_data, indent=2)
    meta = load_scraped_meta()
    entry = {'run_id': run_id, 'script_id': script_id, 'timestamp': timestamp, 'url': url, 'summary': summary,
             'preview': preview, 'destination': None, 'file_path': str(data_file)}
    meta.append(entry)
    save_scraped_meta(meta)
    return jsonify({'status': 'saved', 'run_id': run_id})

@app.route('/api/scraped_data/<run_id>/rag', methods=['POST'])
@login_required
def add_scraped_to_rag(run_id):
    meta = load_scraped_meta()
    entry = None
    for e in meta:
        if e['run_id'] == run_id:
            entry = e
            break
    if not entry:
        return jsonify({'error': 'Run not found'}), 404
    data_file = SCRAPED_DATA_DIR / f"{run_id}.json"
    if not data_file.exists():
        return jsonify({'error': 'Data file missing'}), 404
    data = json.loads(data_file.read_text())
    if not EMBEDDER_AVAILABLE:
        return jsonify({'error': 'Embedder not available'}), 500
    text_content = json.dumps(data, indent=2)
    chunks = [text_content[i:i+500] for i in range(0, len(text_content), 500)]
    embeddings = embedder.encode(chunks).tolist()
    ids = [f"scraped_{run_id}_{i}" for i in range(len(chunks))]
    collection.add(ids=ids, embeddings=embeddings,
                   metadatas=[{"source": f"Scraped: {entry.get('url', 'unknown')}"}] * len(chunks),
                   documents=chunks)
    entry['destination'] = 'rag'
    save_scraped_meta(meta)
    return jsonify({'status': 'added_to_rag', 'chunks': len(chunks)})

@app.route('/api/scraped_data/<run_id>/llm_context', methods=['POST'])
@login_required
def add_scraped_to_llm_context(run_id):
    meta = load_scraped_meta()
    entry = None
    for e in meta:
        if e['run_id'] == run_id:
            entry = e
            break
    if not entry:
        return jsonify({'error': 'Run not found'}), 404
    data_file = SCRAPED_DATA_DIR / f"{run_id}.json"
    if not data_file.exists():
        return jsonify({'error': 'Data file missing'}), 404
    data = json.loads(data_file.read_text())
    if not hasattr(app, 'scraped_context'):
        app.scraped_context = {}
    app.scraped_context[run_id] = {'data': data, 'timestamp': datetime.now().isoformat(),
                                   'source': entry.get('url', 'unknown')}
    entry['destination'] = 'llm_context'
    save_scraped_meta(meta)
    return jsonify({'status': 'added_to_llm_context'})

@app.route('/api/scraped_data/<run_id>', methods=['DELETE'])
@login_required
def delete_scraped_data(run_id):
    meta = load_scraped_meta()
    new_meta = [e for e in meta if e['run_id'] != run_id]
    if len(new_meta) == len(meta):
        return jsonify({'error': 'Run not found'}), 404
    save_scraped_meta(new_meta)
    data_file = SCRAPED_DATA_DIR / f"{run_id}.json"
    if data_file.exists():
        data_file.unlink()
    if hasattr(app, 'scraped_context') and run_id in app.scraped_context:
        del app.scraped_context[run_id]
    return jsonify({'status': 'deleted'})

@app.route('/api/kaggle/models', methods=['GET'])
@login_required
def kaggle_models():
    """Return the list of models available on the Kaggle server."""
    providers = load_llm_providers()
    prov = providers.get('kaggle')
    if not prov or not prov.get('enabled'):
        return jsonify({'error': 'Kaggle provider not enabled'}), 400
    url = prov.get('url')
    api_key = prov.get('api_key', '')
    if not url:
        return jsonify({'error': 'Kaggle URL not set'}), 400

    try:
        target = f"{url}/v1/models"
        headers = {'X-API-Key': api_key}
        resp = requests.get(target, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return jsonify({'models': data.get('models', [])})
        else:
            return jsonify({'error': f'Kaggle server error: {resp.status_code}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500
        
def periodic_sync():
    while True:
        time.sleep(300)  # 5 minutes
        with app.app_context():
            for user_dir in USERS_DIR.iterdir():
                if user_dir.is_dir():
                    username = user_dir.name
                    workspaces = list_workspaces(username)
                    for ws in workspaces:
                        # Call background_sync for each workspace
                        threading.Thread(target=background_sync, args=(username, ws['id']), daemon=True).start()

# Start the periodic sync thread
threading.Thread(target=periodic_sync, daemon=True).start()

# ---------- Run ----------
if __name__ == '__main__':
    resume_pending_tasks()
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'False'
    app.run(debug=debug_mode, port=5001, host='127.0.0.1')
