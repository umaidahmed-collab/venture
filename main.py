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

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

class Item(BaseModel):
    name: str
    price: float
    quantity: int

class Bill(BaseModel):
    total: float

app = FastAPI(title="Restaurant Billing System")

@app.post("/bill", response_model=Bill)
def calculate_bill(item: Item):
    try:
        total = item.price * item.quantity
        return {"total": total}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/")
def read_root():
    return {"message": "Hello World"}

# TODO: Add more endpoints as required
