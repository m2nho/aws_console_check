import sys
import os

print("Running template syntax test...")
os.system('python test_template.py')

print("\nRunning application tests...")
os.system('python run_test_fix.py')