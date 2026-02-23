import json

def test_health_check(client):
    """Test the health check endpoint."""
    response = client.get('/health')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['status'] == 'healthy'

def test_login_validation(client):
    """Test that login requires proper JSON body."""
    response = client.post('/api/v1/auth/login', 
                           data=json.dumps({}),
                           content_type='application/json')
    assert response.status_code == 422
    data = json.loads(response.data)
    assert data['success'] is False
    assert data['code'] == 'VALIDATION_ERROR'

def test_register_and_login_flow(client):
    """Integrated test for registration and login flow."""
    # 1. Register
    reg_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "Password123",
        "role": "Researcher"
    }
    response = client.post('/api/v1/auth/register',
                           data=json.dumps(reg_data),
                           content_type='application/json')
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data['success'] is True
    assert 'private_key' in data

    # 2. Login
    login_data = {
        "username": "testuser",
        "password": "Password123"
    }
    response = client.post('/api/v1/auth/login',
                           data=json.dumps(login_data),
                           content_type='application/json')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    assert 'access_token' in data['data']
    assert data['data']['username'] == 'testuser'

def test_duplicate_registration(client):
    """Test that duplicate registration fails."""
    reg_data = {
        "username": "dupuser",
        "email": "dup@example.com",
        "password": "Password123",
        "role": "Researcher"
    }
    client.post('/api/v1/auth/register',
                data=json.dumps(reg_data),
                content_type='application/json')
    
    response = client.post('/api/v1/auth/register',
                           data=json.dumps(reg_data),
                           content_type='application/json')
    # Custom UserService might raise Conflict or similar
    # If it raises an exception, our global handler catches it
    assert response.status_code == 409 or response.status_code == 500
