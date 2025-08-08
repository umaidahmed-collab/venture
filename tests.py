import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_bmi_endpoint():
    # TODO: Implement tests for the BMI endpoint
    pass

def test_health_check_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
