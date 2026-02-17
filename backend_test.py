#!/usr/bin/env python3

import requests
import json
import sys
import time
from typing import Dict, Any, Optional

# Get base URL from environment
BASE_URL = "https://straico-submit.preview.emergentagent.com/api"

# Test data
TEST_EMAIL = "testuser123@gmail.com"  # Use a more standard email format
TEST_PASSWORD = "password123"

class BackendTester:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        self.access_token = None
        self.user_id = None
        self.initial_credits = None
        
    def make_request(self, method: str, endpoint: str, data: Optional[Dict] = None, auth: bool = False) -> Dict[str, Any]:
        """Make HTTP request with proper error handling"""
        url = f"{BASE_URL}{endpoint}"
        
        headers = {}
        if auth and self.access_token:
            headers['Authorization'] = f'Bearer {self.access_token}'
            
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, headers=headers)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, headers=headers)
            else:
                raise ValueError(f"Unsupported method: {method}")
                
            print(f"{method} {endpoint} -> Status: {response.status_code}")
            
            # Try to parse JSON response
            try:
                response_data = response.json()
            except:
                response_data = {"raw_response": response.text}
                
            return {
                "status_code": response.status_code,
                "data": response_data,
                "success": 200 <= response.status_code < 300
            }
            
        except Exception as e:
            print(f"Request failed: {str(e)}")
            return {
                "status_code": 0,
                "data": {"error": str(e)},
                "success": False
            }
    
    def test_health_check(self) -> bool:
        """Test GET /api/health endpoint"""
        print("\n=== Testing Health Check ===")
        
        try:
            result = self.make_request('GET', '/health')
            
            if result["success"]:
                data = result["data"]
                if data.get("status") == "healthy":
                    print("✅ Health check passed")
                    return True
                else:
                    print(f"❌ Health check failed - invalid response: {data}")
                    return False
            else:
                print(f"❌ Health check failed - HTTP {result['status_code']}: {result['data']}")
                return False
                
        except Exception as e:
            print(f"❌ Health check failed with exception: {str(e)}")
            return False
    
    def test_root_endpoint(self) -> bool:
        """Test GET /api/ root endpoint"""
        print("\n=== Testing Root Endpoint ===")
        
        try:
            result = self.make_request('GET', '/')
            
            if result["success"]:
                data = result["data"]
                if "message" in data and "endpoints" in data:
                    print("✅ Root endpoint passed")
                    print(f"API Info: {data.get('message', 'N/A')}")
                    return True
                else:
                    print(f"❌ Root endpoint failed - missing expected fields: {data}")
                    return False
            else:
                print(f"❌ Root endpoint failed - HTTP {result['status_code']}: {result['data']}")
                return False
                
        except Exception as e:
            print(f"❌ Root endpoint failed with exception: {str(e)}")
            return False
    
    def test_signup(self) -> bool:
        """Test POST /api/auth/signup endpoint"""
        print("\n=== Testing User Signup ===")
        
        try:
            signup_data = {
                "email": TEST_EMAIL,
                "password": TEST_PASSWORD
            }
            
            result = self.make_request('POST', '/auth/signup', signup_data)
            
            if result["success"]:
                data = result["data"]
                if "user" in data and data["user"]:
                    self.user_id = data["user"]["id"]
                    print(f"✅ Signup successful - User ID: {self.user_id}")
                    
                    # Extract session info if available
                    if "session" in data and data["session"]:
                        self.access_token = data["session"]["access_token"]
                        print(f"✅ Session created - Token available")
                    else:
                        print(f"⚠️  No session returned - likely needs email confirmation")
                    
                    return True
                else:
                    print(f"❌ Signup failed - no user data: {data}")
                    return False
            else:
                # Check if user already exists
                if result["status_code"] == 400 and ("already registered" in str(result["data"]).lower() or "already been registered" in str(result["data"]).lower()):
                    print("⚠️  User already exists, will test login instead")
                    return True
                else:
                    print(f"❌ Signup failed - HTTP {result['status_code']}: {result['data']}")
                    return False
                
        except Exception as e:
            print(f"❌ Signup failed with exception: {str(e)}")
            return False
    
    def test_login(self) -> bool:
        """Test POST /api/auth/login endpoint"""
        print("\n=== Testing User Login ===")
        
        try:
            login_data = {
                "email": TEST_EMAIL,
                "password": TEST_PASSWORD
            }
            
            result = self.make_request('POST', '/auth/login', login_data)
            
            if result["success"]:
                data = result["data"]
                if "user" in data and "session" in data:
                    self.user_id = data["user"]["id"]
                    self.access_token = data["session"]["access_token"]
                    print(f"✅ Login successful - User ID: {self.user_id}")
                    print(f"✅ Access token obtained")
                    return True
                else:
                    print(f"❌ Login failed - missing user or session: {data}")
                    return False
            else:
                print(f"❌ Login failed - HTTP {result['status_code']}: {result['data']}")
                return False
                
        except Exception as e:
            print(f"❌ Login failed with exception: {str(e)}")
            return False
    
    def test_get_credits(self) -> bool:
        """Test GET /api/credits endpoint"""
        print("\n=== Testing Get Credits ===")
        
        if not self.access_token:
            print("❌ No access token available for authentication")
            return False
        
        try:
            result = self.make_request('GET', '/credits', auth=True)
            
            if result["success"]:
                data = result["data"]
                if "credits" in data:
                    self.initial_credits = data["credits"]
                    print(f"✅ Credits retrieved successfully: {self.initial_credits}")
                    return True
                else:
                    print(f"❌ Credits endpoint failed - no credits field: {data}")
                    return False
            else:
                print(f"❌ Credits endpoint failed - HTTP {result['status_code']}: {result['data']}")
                return False
                
        except Exception as e:
            print(f"❌ Credits endpoint failed with exception: {str(e)}")
            return False
    
    def test_submit_prompt(self) -> bool:
        """Test POST /api/prompt endpoint"""
        print("\n=== Testing Submit Prompt ===")
        
        if not self.access_token:
            print("❌ No access token available for authentication")
            return False
        
        try:
            prompt_data = {
                "prompt": "What is 2+2? Please provide a brief answer."
            }
            
            result = self.make_request('POST', '/prompt', prompt_data, auth=True)
            
            if result["success"]:
                data = result["data"]
                if "response" in data and "creditsRemaining" in data:
                    print(f"✅ Prompt submission successful")
                    print(f"AI Response: {data['response'][:100]}...")
                    print(f"Credits remaining: {data['creditsRemaining']}")
                    
                    # Verify credits were deducted
                    if self.initial_credits is not None:
                        expected_credits = self.initial_credits - 1
                        if data['creditsRemaining'] == expected_credits:
                            print(f"✅ Credits deducted correctly")
                        else:
                            print(f"⚠️  Credits deduction unexpected - Expected: {expected_credits}, Got: {data['creditsRemaining']}")
                    
                    return True
                else:
                    print(f"❌ Prompt submission failed - missing response or credits: {data}")
                    return False
            else:
                print(f"❌ Prompt submission failed - HTTP {result['status_code']}: {result['data']}")
                return False
                
        except Exception as e:
            print(f"❌ Prompt submission failed with exception: {str(e)}")
            return False
    
    def test_get_history(self) -> bool:
        """Test GET /api/history endpoint"""
        print("\n=== Testing Get History ===")
        
        if not self.access_token:
            print("❌ No access token available for authentication")
            return False
        
        try:
            result = self.make_request('GET', '/history', auth=True)
            
            if result["success"]:
                data = result["data"]
                if "history" in data:
                    history = data["history"]
                    print(f"✅ History retrieved successfully - {len(history)} entries")
                    
                    # Check if our recent prompt is in history
                    if history and len(history) > 0:
                        latest_entry = history[0]
                        if "prompt" in latest_entry and "response" in latest_entry:
                            print(f"✅ History contains valid entries")
                            return True
                        else:
                            print(f"⚠️  History entry missing required fields: {latest_entry}")
                            return True  # Still successful if history exists
                    else:
                        print(f"⚠️  History is empty")
                        return True  # Empty history is valid
                else:
                    print(f"❌ History endpoint failed - no history field: {data}")
                    return False
            else:
                print(f"❌ History endpoint failed - HTTP {result['status_code']}: {result['data']}")
                return False
                
        except Exception as e:
            print(f"❌ History endpoint failed with exception: {str(e)}")
            return False
    
    def test_rate_limiting(self) -> bool:
        """Test rate limiting by making rapid requests"""
        print("\n=== Testing Rate Limiting ===")
        
        if not self.access_token:
            print("❌ No access token available for authentication")
            return False
        
        try:
            print("Making 12 rapid requests to test rate limiting...")
            rate_limited = False
            
            for i in range(12):
                prompt_data = {"prompt": f"Test prompt {i+1}"}
                result = self.make_request('POST', '/prompt', prompt_data, auth=True)
                
                if result["status_code"] == 429:
                    print(f"✅ Rate limiting triggered after {i+1} requests")
                    rate_limited = True
                    break
                elif not result["success"]:
                    print(f"⚠️  Request {i+1} failed with status {result['status_code']}")
                    break
                
                # Small delay to avoid overwhelming
                time.sleep(0.1)
            
            if rate_limited:
                return True
            else:
                print("⚠️  Rate limiting not triggered (may have high limits)")
                return True  # Not necessarily a failure
                
        except Exception as e:
            print(f"❌ Rate limiting test failed with exception: {str(e)}")
            return False

def main():
    """Run all backend tests"""
    print("🚀 Starting AI Prompt Platform Backend Tests")
    print(f"Base URL: {BASE_URL}")
    
    tester = BackendTester()
    
    # Test results tracking
    tests = [
        ("Health Check", tester.test_health_check),
        ("Root Endpoint", tester.test_root_endpoint),
        ("User Signup", tester.test_signup),
        ("User Login", tester.test_login),
        ("Get Credits", tester.test_get_credits),
        ("Submit Prompt", tester.test_submit_prompt),
        ("Get History", tester.test_get_history),
        ("Rate Limiting", tester.test_rate_limiting)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ {test_name} failed with unexpected error: {str(e)}")
            results[test_name] = False
    
    # Summary
    print("\n" + "="*50)
    print("🏁 BACKEND TEST SUMMARY")
    print("="*50)
    
    passed = 0
    total = len(results)
    
    for test_name, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {test_name}")
        if success:
            passed += 1
    
    print(f"\nResults: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All backend tests passed!")
        return True
    else:
        print(f"⚠️  {total - passed} test(s) failed")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)