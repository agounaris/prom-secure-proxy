from fastapi import FastAPI, Request, Response, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import httpx
import secrets
import re
from urllib.parse import parse_qs

app = FastAPI()
security = HTTPBasic()

# Configuration
PROMETHEUS_URL = "http://localhost:9090"
PROXY_USERNAME = "admin"
PROXY_PASSWORD = "admin"

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    """Verify basic authentication credentials."""
    correct_username = secrets.compare_digest(credentials.username, PROXY_USERNAME)
    correct_password = secrets.compare_digest(credentials.password, PROXY_PASSWORD)
    
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

def inject_label_into_query(query: str, tenant_id: str) -> str:
    """Inject tenant_id label into PromQL query."""
    if not query or not tenant_id:
        return query
    
    pattern = r'\b([a-zA-Z_:][a-zA-Z0-9_:]*)\s*(\{[^}]*\})?'
    
    keywords = {'sum', 'rate', 'avg', 'max', 'min', 'count', 'by', 'without', 
                'and', 'or', 'unless', 'on', 'ignoring', 'group_left', 'group_right',
                'bool', 'offset', 'irate', 'increase', 'histogram_quantile'}
    
    def replace_metric(match):
        metric_name = match.group(1)
        labels = match.group(2) or ''
        
        if metric_name.lower() in keywords:
            return match.group(0)
        
        tenant_label = f'tenant_id=~"{tenant_id}|default-tenant|"'
        
        if labels:
            labels = labels.replace('{', '{' + tenant_label + ',', 1)
            return f'{metric_name}{labels}'
        else:
            return f'{metric_name}{{{tenant_label}}}'
    
    return re.sub(pattern, replace_metric, query)

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_to_prometheus(
    request: Request,
    path: str,
    username: str = Depends(verify_credentials)
):
    """Proxy requests to Prometheus with basic auth and X-Scope-OrgID handling."""
    url = f"{PROMETHEUS_URL}/{path}"
    tenant_id = request.headers.get("X-Scope-OrgID")
    
    # Prepare headers
    excluded_headers = {
        "host", "connection", "content-length", 
        "transfer-encoding", "authorization", "accept-encoding"
    }
    
    headers = {
        key: value 
        for key, value in request.headers.items() 
        if key.lower() not in excluded_headers
    }
    
    if tenant_id:
        headers["X-Scope-OrgID"] = tenant_id
    
    # Initialize params and body
    params = {}
    body = b""
    
    # Check content type
    content_type = request.headers.get("content-type", "")
    
    if request.method == "POST" and "application/x-www-form-urlencoded" in content_type:
        # Parse form-encoded data manually
        body_bytes = await request.body()
        body_str = body_bytes.decode('utf-8')
        
        # Parse query string format
        parsed = parse_qs(body_str)
        
        # Convert lists to single values
        params = {
            key: value[0] if isinstance(value, list) and len(value) == 1 else value 
            for key, value in parsed.items()
        }
        
        # Inject tenant_id into query
        if tenant_id and "query" in params:
            params["query"] = inject_label_into_query(params["query"], tenant_id)
        
        body = b""
        
    elif request.method == "GET":
        # GET requests - params in URL
        params = dict(request.query_params)
        
        if tenant_id and "query" in params:
            params["query"] = inject_label_into_query(params["query"], tenant_id)
    else:
        # Other methods
        params = dict(request.query_params)
        body = await request.body()
        
        if tenant_id and "query" in params:
            params["query"] = inject_label_into_query(params["query"], tenant_id)
    
    # Forward to Prometheus
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.request(
                method=request.method,
                url=url,
                headers=headers,
                params=params,
                content=body,
                follow_redirects=False
            )
            
            # Filter response headers
            response_excluded = {
                "content-encoding", "content-length", 
                "transfer-encoding", "connection"
            }
            
            response_headers = {
                key: value 
                for key, value in response.headers.items() 
                if key.lower() not in response_excluded
            }
            
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=response_headers,
                media_type=response.headers.get("content-type")
            )
            
        except httpx.RequestError as e:
            raise HTTPException(
                status_code=502,
                detail=f"Error connecting to Prometheus: {str(e)}"
            )

@app.get("/")
async def health_check(username: str = Depends(verify_credentials)):
    """Health check endpoint."""
    return {"status": "ok", "message": "Prometheus proxy is running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8082)
