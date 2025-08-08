# venture
The venture tasker is the process of spawning a dev-container based on the given tasks

## FastAPI BMI Calculator

This application provides an API endpoint to calculate BMI from weight (kg) and height (cm).

### Running the Application

1. Install the requirements: `pip install fastapi uvicorn pydantic pytest`
2. Run the application: `uvicorn main:app --reload`

### Testing the Application

Run the tests with pytest: `pytest`

### API Usage

#### Calculate BMI

POST /api/v1/bmi

Request:
```json
{
  "weight_kg": 80,
  "height_cm": 180
}
```

Input validation:
weight_kg: 1–500
height_cm: 50–300
Return 422 with details on invalid input

BMI categories:
<18.5: underweight
18.5–24.9: normal
25.0–29.9: overweight
>=30.0: obese

Response:
```json
{
  "bmi": 24.69,
  "category": "normal"
}
```

#### Health Check

GET /health

Response:
```json
{
  "status": "ok"
}
```
