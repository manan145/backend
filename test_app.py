import json
import app  # Ensure app.py is imported correctly

def test_register_and_login():
    tester = app.app.test_client()
    
    # Register a new user
    register_data = {
        "name": "Test User 1",
        "email": "testuser1@example.com",
        "password": "testpassword"
    }
    reg_response = tester.post('/register', 
                                 data=json.dumps(register_data),
                                 content_type='application/json')
    print("Register response:", reg_response.data.decode())
    assert reg_response.status_code == 201
    
    # Login with the new user
    login_data = {
        "email": "testuser1@example.com",
        "password": "testpassword"
    }
    login_response = tester.post('/login', 
                                 data=json.dumps(login_data),
                                 content_type='application/json')
    assert login_response.status_code == 200
    token = json.loads(login_response.data.decode())["token"]
    
    # Use token to analyze text
    headers = {"Authorization": f"Bearer {token}"}
    analyze_data = {"text": "This is amazing!"}
    analyze_response = tester.post('/analyze', 
                                   data=json.dumps(analyze_data),
                                   headers=headers,
                                   content_type='application/json')
    print("Analyze response:", analyze_response.data.decode())
    assert analyze_response.status_code == 200

def test_history():
    tester = app.app.test_client()
    
    # Login to get a token
    login_data = {
        "email": "testuser1@example.com",
        "password": "testpassword"
    }
    login_response = tester.post('/login', 
                                 data=json.dumps(login_data),
                                 content_type='application/json')
    token = json.loads(login_response.data.decode())["token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Retrieve analysis history
    history_response = tester.get('/history', headers=headers)
    assert history_response.status_code == 200
    history = json.loads(history_response.data.decode())
    assert isinstance(history, list)
    
if __name__ == '__main__':
    test_register_and_login()
    test_history()
    print("Backend tests passed!")
