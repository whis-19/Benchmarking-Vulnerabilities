# test_app.py
    import pytest
    from your_app import app  # Replace with your app's name

    @pytest.fixture
    def client():
        with app.test_client() as client:
            yield client

    def test_index_route(client):
        response = client.get("/")
        assert response.status_code == 200

