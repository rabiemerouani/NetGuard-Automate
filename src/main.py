from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from src.analyzer import analyze_configuration 
from src.database import init_db, save_audit_result, get_all_audits, get_audit_with_vulnerabilities

# 1. Define the Modern Application Lifespan Context Manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    # This block executes strictly ON STARTUP when Uvicorn is fired up
    print("[SERVER] FastAPI infrastructure booting up...")
    init_db() 
    yield
    # This block executes ON SHUTDOWN when the server terminates gracefully
    print("[SERVER] FastAPI infrastructure shutting down safely...")

# 2. Instantiate the web service with embedded lifespan hooks
app = FastAPI(
    title="NetGuard Automate API",
    description="Security auditing API for Cisco network equipment (CIS Benchmarks)",
    version="1.0.0",
    lifespan=lifespan
)

# Pydantic Data Model for Request Validation
class AuditRequest(BaseModel):
    device_name: str
    device_ip: str
    router_config: str

# Root route for Health Check
@app.get("/")
def read_root():
    return {"status": "ok", "message": "NetGuard API is running"}

# POST Route: Processes configuration and logs findings
@app.post("/api/audit")
def run_audit(payload: AuditRequest):
    try:
        if not payload.device_name.strip():
            raise HTTPException(status_code=400, detail="Device name cannot be empty.")
        if not payload.device_ip.strip():
            raise HTTPException(status_code=400, detail="Device IP address cannot be empty.")
        if not payload.router_config.strip():
            raise HTTPException(status_code=400, detail="Router configuration cannot be empty.")
        
        results = analyze_configuration(payload.device_name, payload.router_config)
        audit_id = save_audit_result(payload.device_name, payload.device_ip, results)
        
        # Standardized return envelope payload shape
        return {
            "success": True,
            "data": {
                "audit_id": audit_id,
                "device": payload.device_name,
                "ip_address": payload.device_ip,
                "total_vulnerabilities": len(results),
                "findings": results
            }
        }
        
    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# GET Route: Fetches audit history overview (Harmonized wrapper)
@app.get("/api/audits")
def fetch_audit_history():
    try:
        history = get_all_audits()
        return {
            "success": True,
            "data": history  # Perfectly consistent with single audit schema endpoints!
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database retrieval failure: {str(e)}")

# GET Route (Parameterized): Deep-dives into individual reports (Harmonized wrapper)
@app.get("/api/audits/{audit_id}")
def fetch_single_audit(audit_id: int):
    try:
        detailed_report = get_audit_with_vulnerabilities(audit_id)
        
        if detailed_report is None:
            raise HTTPException(status_code=404, detail=f"Audit report with ID {audit_id} not found.")
            
        return {
            "success": True,
            "data": detailed_report
        }
    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal query failure: {str(e)}")