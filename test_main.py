import pytest
from fastapi.testclient import TestClient
from main import app, Item, Bill

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello World"}

def test_calculate_bill():
    # Test with valid input
    response = client.post("/bill", json={"name": "Burger", "price": 5.0, "quantity": 2})
    assert response.status_code == 200
    assert response.json() == {"total": 10.0}

    # Test with invalid input (negative price)
    response = client.post("/bill", json={"name": "Burger", "price": -5.0, "quantity": 2})
    assert response.status_code == 422

    # Test with invalid input (zero quantity)
    response = client.post("/bill", json={"name": "Burger", "price": 5.0, "quantity": 0})
    assert response.status_code == 422
