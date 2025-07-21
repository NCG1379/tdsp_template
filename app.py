from scripts.utils.react_agent_openai import react_openai
from scripts.utils.react_agent_claude import react_claude
from scripts.utils.react_agent_deepseek import react_deepseek
from fastapi.middleware.cors import CORSMiddleware
from scripts.preprocessing.data_summary import vt_summary, whois_summary, abuseipdb_summary

from fastapi import FastAPI
from pydantic import BaseModel




class ApiInput(BaseModel):
    ioc: str

class ApiOutput(BaseModel):
    response: dict

app = FastAPI()

# Allow CORS for frontend on localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/v1/openai")
async def get_open_ai_response(ioc: ApiInput) -> ApiOutput:
    return ApiOutput(response=react_openai(ioc))

@app.post("/api/v1/claude")
async def get_claude_response(ioc: ApiInput) -> ApiOutput:
    return ApiOutput(response=react_claude(ioc))

@app.post("/api/v1/deepseek")
async def get_deepseek_response(ioc: ApiInput) -> ApiOutput:
    return ApiOutput(response=react_deepseek(ioc))

@app.post("/api/v1/virustotal")
async def get_vt_response(ioc: ApiInput) -> ApiOutput:
    return ApiOutput(response=vt_summary(ioc))

@app.post("/api/v1/whois")
async def get_whois_response(ioc: ApiInput) -> ApiOutput:
    return ApiOutput(response=whois_summary(ioc))

@app.post("/api/v1/abuseipdb")
async def get_abuseipdb_response(ioc: ApiInput) -> ApiOutput:
    return ApiOutput(response=abuseipdb_summary(ioc))

