from typing import List, Annotated
from typing_extensions import TypedDict
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import tools_condition, ToolNode
from langchain_core.messages import HumanMessage, SystemMessage, BaseMessage
from langchain_openai import ChatOpenAI

import os
from pathlib import Path
from dotenv import load_dotenv

from scripts.data_acquisition.dtaq_main import VirusTotal, AbuseIPDB, WHOIS_RDAP, ShodanIO

current_dir = Path(__file__).resolve().parent
dotenv_path = current_dir.parent.parent / '.env'

load_dotenv(dotenv_path=dotenv_path)

class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], lambda x, y: x + y]


def get_vt_data(ioc: str) -> str:
    """Get data from VT associated to an IP or Domain."""
    virustotal = VirusTotal(ioc=ioc)
    try:
        return virustotal.display_domain_info()
    except Exception as e:
        print(e)
        return virustotal.display_ip_info()


def get_abuseipdb_data(ioc: str) -> dict:
    """Get data from AbuseIPDB associated to an IP."""
    abuseipdb = AbuseIPDB(ioc=ioc).check_ip()
    return abuseipdb

def get_whois_data(ioc: str):
    """Get data from whois associated to an IP or Domain."""
    whois_arin = WHOIS_RDAP(ioc=ioc)
    return whois_arin

def get_shodan_data(ioc: str) -> str:
    """Get data from shodan associated to an IP or Domain."""
    shodan = ShodanIO(ioc=ioc).search_data_in_shodan()
    return shodan


tools = [get_vt_data, get_abuseipdb_data, get_whois_data, get_shodan_data]

llm = ChatOpenAI(model="gpt-4.1-nano", api_key=os.getenv("OPENAI_KEY"))
llm_with_tools = llm.bind_tools(tools)


def assistant_node(state: AgentState):
    messages = state["messages"]
    system_message = SystemMessage(
        content="You are a cybersecurity researcher. You can use the provided tools to gather information. One way communication.")

    response = llm_with_tools.invoke([system_message] + messages)

    return {"messages": [response]}


tool_node = ToolNode(tools)

builder = StateGraph(AgentState)
builder.add_node("assistant", assistant_node)
builder.add_node("tools", tool_node)

builder.add_edge(START, "assistant")
builder.add_conditional_edges(
    "assistant",
    tools_condition,
    {"tools": "tools", END: END}
)
builder.add_edge("tools", "assistant")

graph = builder.compile()

try:
    graph.get_graph().draw_png(output_file_path="graph_agent.png")
    print("Graph exported to graph_agent.png")
except Exception as e:
    print(f"Could not export graph as PNG. Ensure 'pygraphviz' and 'graphviz' system package are installed. Error: {e}")

messages_input = [HumanMessage(content="What is the reputation of 179.43.176.38?")]
final_state = graph.invoke({"messages": messages_input})

print("\nFinal Conversation:")
for m in final_state['messages']:
    m.pretty_print()
