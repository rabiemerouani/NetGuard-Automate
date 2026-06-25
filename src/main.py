from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from src.analyzer import analyze_configuration 

app = FastAPI(
    title="NetGuard Automate API",
    description="Security auditing API for Cisco network equipment (CIS Benchmarks)",
    version="1.0.0"
)

# 1. Pydantic Data Model for Request Validation
class AuditRequest(BaseModel):
    device_name: str
    router_config: str

# Root route for Health Check
@app.get("/")
def read_root():
    return {"status": "ok", "message": "NetGuard API is running"}

# 2. POST Route to receive and process network configurations
@app.post("/api/audit")
def run_audit(payload: AuditRequest):
    try:
        # Input validation for empty fields
        if not payload.device_name.strip():
            raise HTTPException(status_code=400, detail="Device name cannot be empty.")
        
        if not payload.router_config.strip():
            raise HTTPException(status_code=400, detail="Router configuration cannot be empty.")
        
        # Passing both required arguments to the core analyzer engine
        results = analyze_configuration(payload.device_name, payload.router_config)
        
        return {
            "success": True,
            "device": payload.device_name,
            "total_vulnerabilities": len(results),
            "findings": results
        }
        
    except HTTPException as http_err:
        # Forwarding client/validation errors (400) exactly as they are
        raise http_err
        
    except Exception as e:
        # Catching unexpected system or logic runtime crashes as a 500 Server Error
        raise HTTPException(status_code=500, detail=f"Internal server error during analysis: {str(e)}")