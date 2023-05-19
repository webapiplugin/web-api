from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.openapi.utils import get_openapi
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response, JSONResponse, RedirectResponse
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from pydantic import BaseModel, HttpUrl, ValidationError
from RestrictedPython import safe_builtins, compile_restricted, limited_builtins, utility_builtins
from html_sanitizer import Sanitizer
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import httpx
import requests
from requests.exceptions import RequestException
from typing import List, Dict
import subprocess
import shutil
import resources as rsrc
import time
import asyncio
import uvicorn
import os
from urllib.parse import quote, urlparse
import uuid
import json
import logging
import bandit

app = FastAPI(debug=True)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        logger.info(f"Processing request: {request.method} {request.url}")
        response = await call_next(request)
        logger.info(f"Response status: {response.status_code}")
        return response
app.add_middleware(LoggingMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["localhost", "0.0.0.0", "chat.openai.com", "https://webapiplugin-1-d3545675.deta.app/"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"]
)

@app.middleware("http")
async def add_cors_header(request: Request, call_next):
    response = await call_next(request)
    allowed_origin = request.headers.get("Origin")
    response.headers["Access-Control-Allow-Origin"] = allowed_origin or "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def read_root():
    return RedirectResponse(url="https://github.com/webapiplugin/web-api")

@app.route("/.well-known/ai-plugin.json", methods=["GET", "OPTIONS"])
async def options_handler(request: Request):
    if request.method == "GET":
        try:
            return FileResponse("./.well-known/ai-plugin.json")
        except FileNotFoundError:
            response = JSONResponse(content={"error": "File not found"}, status_code=404)
            response.headers["Access-Control-Allow-Origin"] = request.headers["Host"]
            return response
    elif request.method == "OPTIONS":
        try:
            with open("./.well-known/ai-plugin.json") as f:
                text = f.read()
                response = JSONResponse(content=text, media_type="text/json")
                response.headers["Access-Control-Allow-Origin"] = request.headers["Host"]
                return response
        except FileNotFoundError:
            return JSONResponse(content={"error": "File not found"}, status_code=404)

def sanitize(data):
    if isinstance(data, str):
        return data.encode('charmap', 'ignore').decode('charmap')
    elif isinstance(data, dict):
        return {key: sanitize(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [sanitize(element) for element in data]
    else:
        return data
sanitizer = Sanitizer()

@app.get("/openapi.yaml")
async def openapi_spec():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Web API Plugin",
        version="1.0",
        description="Integrate web API access with OpenAI ChatGPT",
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema
app.openapi = openapi_spec

async def proxy_request(url: str, method: str, data: str, headers: str):
    try:
        if method.lower() == 'get':
            response = requests.get(url, headers=headers)
        elif method.lower() == 'post':
            response = requests.post(url, data=data, headers=headers)
        elif method.lower() == 'put':
            response = requests.put(url, data=data, headers=headers)
        elif method.lower() == 'delete':
            response = requests.delete(url, headers=headers)
        else:
            raise HTTPException(status_code=400, detail="Invalid method")
    except RequestException:
        raise HTTPException(status_code=500, detail="Error occurred during request")

    # Sanitize the response body to prevent potential XSS attacks.
    sanitized_body = sanitizer.sanitize(response.text)

    return {"status_code": response.status_code, "response_body": sanitized_body}

@app.post("/wrapper_request")
async def wrapper_request(url: str, method: str, data: str = None, headers: str = None):
    # Sanitize inputs
    url = sanitizer.sanitize(url)
    method = sanitizer.sanitize(method)
    data = sanitizer.sanitize(data) if data else None
    headers = sanitizer.sanitize(headers) if headers else None
    
    # Validate url and method
    if method.lower() not in ['get', 'post', 'put', 'delete']:
        raise HTTPException(status_code=400, detail="Invalid method")
    
    # Check if the URL includes a scheme and netloc
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        raise HTTPException(status_code=400, detail="Invalid URL")

    response = await proxy_request(url, method, data, headers)

    # Truncate the response if it exceeds the maximum length
    max_length = 65536
    if len(response["response_body"]) > max_length:
        response["response_body"] = response["response_body"][:max_length - 3] + '...'

    return response

lock = asyncio.Lock()

@app.post("/execute/")
async def execute_code(code: str):
    async with lock:
        # Validate the code
        if not validate_code(code):
            raise HTTPException(status_code=400, detail="Code invalid or not allowed")

        # Set up a unique jail directory and filename
        unique_id = uuid.uuid4()
        jail_dir = f"/tmp/jail/{unique_id}"
        os.makedirs(jail_dir, exist_ok=True)
        file_path = os.path.join(jail_dir, f'{unique_id}.py')

        try:
            # Limit rsrcs
            rsrc.setrlimit(rsrc.RLIMIT_CPU, (20, 20))
            rsrc.setrlimit(rsrc.RLIMIT_NPROC, (2, 2))

            # Write the code to a file
            with open(file_path, 'w') as f:
                f.write(code)

            # Execute the code in a Docker container with security options
            result = subprocess.run([
                'docker', 'run', '--rm', '--net=none', '--userns=host', '--security-opt', 'no-new-privileges', '--security-opt', 'seccomp=unconfined', 
                '--read-only', '--cpus=.2', '--memory=50m', '--pids-limit=2', '-v', f'{jail_dir}:/code', 'python:3.9', 'python', f'/code/{unique_id}.py'
            ], capture_output=True, text=True, timeout=60)

            if result.stderr:
                raise HTTPException(status_code=500, detail="Execution error")
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=408, detail="Execution timeout")
        except Exception as e:
            logging.error(f"Error executing code: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")
        finally:
            # Delete the jail directory
            shutil.rmtree(jail_dir)

        return {"result": result.stdout}

def validate_code(code):
    # Static code analysis with Bandit
    b_mgr = bandit.core.manager.BanditManager(bandit.core.config.BanditConfig(), 'file')
    b_mgr.discover_files([code], 'python')
    b_mgr.run_tests()
    if b_mgr.results_count() > 0:
        return False

    return True

if __name__ == '__main__':
    os.system("uvicorn main:app --host 0.0.0.0 --port 5003 --reload")