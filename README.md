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
