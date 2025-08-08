from pydantic import BaseModel, Field

class BMIRequest(BaseModel):
    weight_kg: float = Field(..., gt=1, lt=500)
    height_cm: float = Field(..., gt=50, lt=300)

class BMIResponse(BaseModel):
    bmi: float
    category: str
