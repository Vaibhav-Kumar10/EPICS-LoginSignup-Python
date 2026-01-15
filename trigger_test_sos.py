#!/usr/bin/env python3
"""
Test script to simulate a nearby SOS alert.
This will trigger a notification on your phone if you're logged into the app.
"""
import requests
import sys

# Backend URL
BACKEND_URL = "http://10.235.8.136:5000"

def simulate_nearby_sos(lat=None, lng=None, user_name="Test User"):
    """Send a test SOS alert to the backend"""
    
    # Default coordinates ~600m north of Bhopal location
    data = {
        "user_name": user_name
    }
    
    if lat and lng:
        data["latitude"] = lat
        data["longitude"] = lng
    
    print(f"🧪 Simulating SOS alert from '{user_name}'...")
    
    try:
        response = requests.post(
            f"{BACKEND_URL}/test/simulate_nearby_sos",
            json=data,
            timeout=5
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Success!")
            print(f"   Broadcasted to {result['broadcast_to']} connected users")
            print(f"   Location: {result['alert_data']['latitude']}, {result['alert_data']['longitude']}")
            print(f"\n📱 Check your phone for the nearby emergency alert!")
        else:
            print(f"❌ Error: {response.status_code}")
            print(response.text)
            
    except requests.exceptions.ConnectionError:
        print(f"❌ Cannot connect to backend at {BACKEND_URL}")
        print("   Make sure the backend server is running!")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Usage: python trigger_test_sos.py "John Doe"
        user_name = sys.argv[1]
        simulate_nearby_sos(user_name=user_name)
    else:
        # Default test
        simulate_nearby_sos()
