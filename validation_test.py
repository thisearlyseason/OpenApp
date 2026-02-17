#!/usr/bin/env python3

import requests
import json
import sys
from typing import Dict, Any, Optional

# Get base URL from environment
BASE_URL = "https://straico-submit.preview.emergentagent.com/api"

class ValidationTester:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
    def make_request(self, method: str, endpoint: str, data: Optional[Dict] = None, auth_header: str = None) -> Dict[str, Any]:
        """Make HTTP request with proper error handling"""
        url = f"{BASE_URL}{endpoint}"
        
        headers = {}
        if auth_header:
            headers['Authorization'] = auth_header
            
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

    def test_auth_validation(self) -> bool:
        """Test authentication endpoint validation"""
        print("\n=== Testing Auth Validation ===")
        
        validation_tests = [
            # Test missing fields
            ("signup_no_email", "POST", "/auth/signup", {"password": "test123"}, 400),
            ("signup_no_password", "POST", "/auth/signup", {"email": "test@example.com"}, 400),
            ("signup_short_password", "POST", "/auth/signup", {"email": "test@example.com", "password": "123"}, 400),
            ("login_no_email", "POST", "/auth/login", {"password": "test123"}, 400),
            ("login_no_password", "POST", "/auth/login", {"email": "test@example.com"}, 400),
        ]
        
        passed = 0
        total = len(validation_tests)
        
        for test_name, method, endpoint, data, expected_status in validation_tests:
            try:
                result = self.make_request(method, endpoint, data)
                if result["status_code"] == expected_status:
                    print(f"✅ {test_name}: Correct validation (HTTP {expected_status})")
                    passed += 1
                else:
                    print(f"❌ {test_name}: Expected {expected_status}, got {result['status_code']}")
            except Exception as e:
                print(f"❌ {test_name}: Exception - {str(e)}")
        
        return passed == total

    def test_auth_protection(self) -> bool:
        """Test that protected endpoints require authentication"""
        print("\n=== Testing Endpoint Protection ===")
        
        protected_endpoints = [
            ("GET", "/credits"),
            ("POST", "/prompt"),
            ("GET", "/history"),
        ]
        
        passed = 0
        total = len(protected_endpoints)
        
        for method, endpoint in protected_endpoints:
            try:
                # Test without auth header
                result = self.make_request(method, endpoint, {"prompt": "test"} if method == "POST" else None)
                
                if result["status_code"] == 401:
                    print(f"✅ {method} {endpoint}: Properly protected (HTTP 401)")
                    passed += 1
                else:
                    print(f"❌ {method} {endpoint}: Expected 401, got {result['status_code']}")
                    
                # Test with invalid auth header
                result = self.make_request(method, endpoint, 
                                        {"prompt": "test"} if method == "POST" else None, 
                                        "Bearer invalid_token")
                
                if result["status_code"] == 401:
                    print(f"✅ {method} {endpoint}: Invalid token rejected (HTTP 401)")
                    passed += 1
                else:
                    print(f"❌ {method} {endpoint}: Invalid token - Expected 401, got {result['status_code']}")
                    
            except Exception as e:
                print(f"❌ {method} {endpoint}: Exception - {str(e)}")
        
        return passed == total * 2  # Each endpoint tested twice
    
    def test_prompt_validation(self) -> bool:
        """Test prompt endpoint input validation"""
        print("\n=== Testing Prompt Validation ===")
        
        validation_tests = [
            # Test without auth (should fail with 401 first)
            ("no_auth", {"prompt": "test"}, 401),
            # These would require valid auth to test properly, but we can check structure
        ]
        
        passed = 0
        total = len(validation_tests)
        
        for test_name, data, expected_status in validation_tests:
            try:
                result = self.make_request("POST", "/prompt", data)
                if result["status_code"] == expected_status:
                    print(f"✅ prompt_{test_name}: Correct response (HTTP {expected_status})")
                    passed += 1
                else:
                    print(f"❌ prompt_{test_name}: Expected {expected_status}, got {result['status_code']}")
            except Exception as e:
                print(f"❌ prompt_{test_name}: Exception - {str(e)}")
        
        return passed == total

    def test_404_handling(self) -> bool:
        """Test 404 handling for unknown routes"""
        print("\n=== Testing 404 Handling ===")
        
        unknown_routes = [
            ("GET", "/unknown"),
            ("POST", "/api/unknown"),
            ("GET", "/auth/unknown"),
        ]
        
        passed = 0
        total = len(unknown_routes)
        
        for method, endpoint in unknown_routes:
            try:
                result = self.make_request(method, endpoint)
                if result["status_code"] == 404:
                    print(f"✅ {method} {endpoint}: Proper 404 response")
                    passed += 1
                else:
                    print(f"❌ {method} {endpoint}: Expected 404, got {result['status_code']}")
            except Exception as e:
                print(f"❌ {method} {endpoint}: Exception - {str(e)}")
        
        return passed == total

def main():
    """Run validation tests"""
    print("🧪 Starting AI Prompt Platform Validation Tests")
    print(f"Base URL: {BASE_URL}")
    
    tester = ValidationTester()
    
    tests = [
        ("Auth Validation", tester.test_auth_validation),
        ("Endpoint Protection", tester.test_auth_protection),
        ("Prompt Validation", tester.test_prompt_validation),
        ("404 Handling", tester.test_404_handling),
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
    print("🧪 VALIDATION TEST SUMMARY")
    print("="*50)
    
    passed = 0
    total = len(results)
    
    for test_name, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {test_name}")
        if success:
            passed += 1
    
    print(f"\nValidation Results: {passed}/{total} test suites passed")
    
    if passed == total:
        print("🎉 All validation tests passed!")
        return True
    else:
        print(f"⚠️  {total - passed} validation test(s) failed")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)