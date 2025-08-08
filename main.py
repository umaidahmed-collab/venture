from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI()

class BMIRequest(BaseModel):
    weight_kg: float = Field(..., gt=1, lt=500)
    height_cm: float = Field(..., gt=50, lt=300)

class BMIResponse(BaseModel):
    bmi: float
    category: str

from fastapi import HTTPException

@app.post("/api/v1/bmi", response_model=BMIResponse)
def calculate_bmi(request: BMIRequest):
    height_m = request.height_cm / 100
    if height_m == 0:
        raise HTTPException(status_code=400, detail="Height cannot be zero")
    bmi = request.weight_kg / (height_m ** 2)
    if bmi < 18.5:
        category = "underweight"
    elif 18.5 <= bmi < 25:
        category = "normal"
    elif 25 <= bmi < 30:
        category = "overweight"
    else:
        category = "obese"
    return BMIResponse(bmi=round(bmi, 2), category=category)

@app.get("/health")
def health_check():
    return {"status": "ok"}
