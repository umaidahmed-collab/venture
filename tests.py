import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_bmi_endpoint():
    # Test with valid input
    response = client.post("/api/v1/bmi", json={"weight_kg": 80, "height_cm": 180})
    assert response.status_code == 200
    assert response.json() == {"bmi": 24.69, "category": "normal"}

    # Test with invalid input (weight_kg out of range)
    response = client.post("/api/v1/bmi", json={"weight_kg": 0, "height_cm": 180})
    assert response.status_code == 422

    # Test with invalid input (height_cm out of range)
    response = client.post("/api/v1/bmi", json={"weight_kg": 80, "height_cm": 0})
    assert response.status_code == 422

    # Test with invalid input (weight_kg and height_cm out of range)
    response = client.post("/api/v1/bmi", json={"weight_kg": 0, "height_cm": 0})
    assert response.status_code == 422

    # Test with invalid input (weight_kg is negative)
    response = client.post("/api/v1/bmi", json={"weight_kg": -80, "height_cm": 180})
    assert response.status_code == 422

    # Test with invalid input (height_cm is negative)
    response = client.post("/api/v1/bmi", json={"weight_kg": 80, "height_cm": -180})
    assert response.status_code == 422

def test_health_check_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
