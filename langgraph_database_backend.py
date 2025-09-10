from langgraph.graph import StateGraph, START, END
from typing import TypedDict, Annotated
from langchain_core.messages import BaseMessage, HumanMessage
from langchain_groq import ChatGroq
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph.message import add_messages
import sqlite3
from dotenv import load_dotenv
load_dotenv()

llm = ChatGroq(groq_api_key="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", model="llama-3.3-70b-versatile")


class ChatState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]

# def chat_node(state: ChatState):
#     messages = state['messages']
#     response = llm.invoke(messages)
#     return {"messages": [response]}

from langchain_core.messages import SystemMessage

def chat_node(state: ChatState):
    messages = state['messages']
    # Ensure system message is always the first
    if not messages or messages[0].type != "system":
        messages = [SystemMessage(content="You are Kshitij AI, a friendly AI assistant. You were developed by Ashish Gupta.")] + messages
    response = llm.invoke(messages)
    return {"messages": [response]}

conn = sqlite3.connect(database='chatbot.db', check_same_thread=False)
# Checkpointer
checkpointer = SqliteSaver(conn=conn)

graph = StateGraph(ChatState)
graph.add_node("chat_node", chat_node)
graph.add_edge(START, "chat_node")
graph.add_edge("chat_node", END)

chatbot = graph.compile(checkpointer=checkpointer)

def retrieve_all_threads():
    all_threads = set()
    for checkpoint in checkpointer.list(None):
        all_threads.add(checkpoint.config['configurable']['thread_id'])

    return list(all_threads)





