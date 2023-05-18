from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.openapi.utils import get_openapi
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response, JSONResponse, RedirectResponse
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from pydantic import HttpUrl, ValidationError
from html_sanitizer import Sanitizer
import json
import httpx
import requests
from requests.exceptions import RequestException
from typing import List, Dict
import asyncio
import uvicorn
import os
from urllib.parse import quote
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(debug=True)

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
    
    # Check if the URL includes a scheme
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        raise HTTPException(status_code=400, detail="URL must include a scheme (e.g., http, https)")

    try:
        HttpUrl(url=url)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return await proxy_request(url, method, data, headers)


if __name__ == '__main__':
    os.system("uvicorn main:app --host 0.0.0.0 --port 5003 --reload")