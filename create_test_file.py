# create_test_file.py
import os

# Generate 1MB of pure, random bytes (guaranteed high entropy)
random_data = os.urandom(1024 * 1024) 

# Write these bytes to a new test file
with open("random_test.exe", "wb") as f:
    f.write(random_data)

print("Created 'random_test.exe' successfully. You can now test this file in Kavach.")