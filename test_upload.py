#!/usr/bin/env python3
"""Quick test script to verify file upload scanning works."""
import requests
import sys
import os

def test_upload(file_path):
    """Test uploading a file to the scan endpoint."""
    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        return False
    
    url = "http://127.0.0.1:5000/api/upload_scan"
    
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            print(f"Uploading {file_path}...")
            response = requests.post(url, files=files, timeout=30)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("\n✅ Upload successful!")
            print(f"Status: {data.get('status')}")
            print(f"File: {data.get('file', {}).get('name')}")
            print(f"Size: {data.get('file', {}).get('size')} bytes")
            print(f"Type: {data.get('file', {}).get('type')}")
            
            yara = data.get('yara', [])
            heuristics = data.get('heuristics', [])
            
            if yara:
                print(f"\n🔍 YARA Matches ({len(yara)}):")
                for match in yara:
                    print(f"  - {match}")
            
            if heuristics:
                print(f"\n⚠️  Heuristic Findings ({len(heuristics)}):")
                for finding in heuristics:
                    print(f"  - {finding}")
            
            if not yara and not heuristics:
                print("\n✓ No threats detected")
            
            analysis = data.get('analysis', [])
            if analysis:
                print(f"\n📝 Analysis Notes:")
                for note in analysis:
                    print(f"  - {note}")
            
            return True
        else:
            print(f"❌ Error: {response.status_code}")
            try:
                error_data = response.json()
                print(f"Error message: {error_data.get('error', 'Unknown error')}")
            except:
                print(f"Response: {response.text}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Error: Could not connect to server.")
        print("   Make sure the server is running: python run_integrated_system.py")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == '__main__':
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
    else:
        # Default to EICAR test file
        test_file = 'test_eicar.txt'
    
    success = test_upload(test_file)
    sys.exit(0 if success else 1)


