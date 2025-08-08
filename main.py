from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI()

class BMIRequest(BaseModel):
    weight_kg: float = Field(..., gt=1, lt=500)
    height_cm: float = Field(..., gt=50, lt=300)

class BMIResponse(BaseModel):
    bmi: float
    category: str

@app.post("/api/v1/bmi", response_model=BMIResponse)
def calculate_bmi(request: BMIRequest):
    # TODO: Implement the BMI calculation and category determination
    pass

@app.get("/health")
def health_check():
    return {"status": "ok"}
