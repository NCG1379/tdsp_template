from scripts.utils.react_agent_openai import react_openai
# from scripts.utils.react_agent_deepseek import run_agent as react_deepseek
from scripts.utils.react_agent_claude import react_claude

from scripts.utils.react_agent_deepseek import react_deepseek

from fastapi import FastAPI
from pydantic import BaseModel

class ApiInput(BaseModel):
    ioc: str

class ApiOutput(BaseModel):
    response: dict

app = FastAPI()

@app.post("/api/v1/openai")
async def get_open_ai_response(ioc: ApiInput) -> ApiOutput:
    return ApiOutput(response=react_openai(ioc))

@app.post("/api/v1/claude")
async def get_claude_response(ioc: ApiInput) -> ApiOutput:
    return ApiOutput(response=react_claude(ioc))

@app.post("/api/v1/deepseek")
async def get_deepseek_response(ioc: ApiInput) -> ApiOutput:
    return ApiOutput(response=react_deepseek(ioc))
