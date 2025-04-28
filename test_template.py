from jinja2 import Environment, FileSystemLoader
import os

# Create a Jinja2 environment
env = Environment(loader=FileSystemLoader('templates'))

try:
    # Try to load and parse the consolidated.html template
    template = env.get_template('consolidated.html')
    print("Template loaded successfully! No syntax errors found.")
except Exception as e:
    print(f"Error loading template: {str(e)}")