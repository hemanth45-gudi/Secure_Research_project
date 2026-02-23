import json
from io import BytesIO

def test_list_datasets_unauthorized(client):
    """Test listing datasets without authentication."""
    # Ensure it returns 401 JSON, not 302 redirect
    response = client.get('/api/v1/datasets/', headers={'Accept': 'application/json'})
    assert response.status_code == 401
    data = json.loads(response.data)
    assert data['success'] is False
    assert 'message' in data

def test_list_datasets_authorized(client):
    """Test listing datasets with a Reviewer role."""
    # 1. Register a reviewer
    reg_data = {
        "username": "reviewer1",
        "email": "rev@example.com",
        "password": "Password123",
        "role": "Reviewer"
    }
    reg_resp = client.post('/api/v1/auth/register',
                           data=json.dumps(reg_data),
                           content_type='application/json')
    assert reg_resp.status_code == 201
    
    # 2. Login
    login_data = {"username": "reviewer1", "password": "Password123"}
    login_resp = client.post('/api/v1/auth/login',
                             data=json.dumps(login_data),
                             content_type='application/json')
    assert login_resp.status_code == 200, f"Login failed: {login_resp.data}"
    data = json.loads(login_resp.data)
    token = data['data']['access_token']
    
    # 3. List datasets
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }
    response = client.get('/api/v1/datasets/', headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    assert 'datasets' in data['data']

def test_upload_dataset_validation(client):
    """Test dataset upload validation."""
    # 1. Register a researcher
    reg_data = {
        "username": "res1",
        "email": "res@example.com",
        "password": "Password123",
        "role": "Researcher"
    }
    reg_resp = client.post('/api/v1/auth/register',
                           data=json.dumps(reg_data),
                           content_type='application/json')
    assert reg_resp.status_code == 201
    
    # 2. Login
    login_data = {"username": "res1", "password": "Password123"}
    login_resp = client.post('/api/v1/auth/login',
                             data=json.dumps(login_data),
                             content_type='application/json')
    assert login_resp.status_code == 200
    token = json.loads(login_resp.data)['data']['access_token']
    
    # 3. Upload without files or description
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }
    
    # Missing everything
    response = client.post('/api/v1/datasets/upload', headers=headers, data={})
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'Missing' in data['message']

    # Missing files but has description
    response = client.post('/api/v1/datasets/upload', 
                           headers=headers, 
                           data={'description': 'Test'})
    assert response.status_code == 400
