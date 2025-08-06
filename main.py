"""
FastAPI Application for Make a python UI with Tkinter to implement restaurant billing system

Task: LAB-103
Description: Make a python UI with Tkinter to implement restaurant billing system

TODO: Implement FastAPI application with the following features:
- Create FastAPI app instance
- Add authentication endpoints
- Include request/response models
- Add proper error handling
- Include API documentation
"""

from fastapi import FastAPI

# TODO: Implement the FastAPI application
app = FastAPI(title="Make a python UI with Tkinter to implement restaurant billing system")

@app.get("/")
def read_root():
    return {"message": "Hello World"}

# TODO: Add more endpoints as required
