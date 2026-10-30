"""
Root Convenience Launcher
=========================
Allows running 'python app.py' directly from the workspace root folder.
Delegates to sql-data-leak-detector/app.py.
"""
import sys
import os

project_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sql-data-leak-detector')
sys.path.insert(0, project_dir)
os.chdir(project_dir)

from app import app

if __name__ == '__main__':
    print("Starting SQL-Based Data Leak Detection System from workspace root...")
    app.run(host='127.0.0.1', port=5000, debug=True)
