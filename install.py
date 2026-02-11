#!/usr/bin/env python3
"""
Quorra SIEM Installation Script
"""

import os
import sys
import subprocess
import shutil

def run_command(cmd, check=True):
    """Run a shell command."""
    print(f"➜ {cmd}")
    try:
        subprocess.run(cmd, shell=True, check=check)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}")
        return False

def main():
    print("🔧 Installing Quorra SIEM Tool...")
    print("=" * 50)
    
    # Check Python version
    python_version = sys.version_info
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 8):
        print(f"Error: Python 3.8+ required. Found Python {python_version.major}.{python_version.minor}")
        sys.exit(1)
    
    print(f"Python {python_version.major}.{python_version.minor}.{python_version.micro} detected")
    
    # Create necessary directories
    print("\n📁 Creating directories...")
    os.makedirs("data", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    os.makedirs("templates", exist_ok=True)
    
    # Create virtual environment
    if not os.path.exists("venv"):
        print("\n Creating virtual environment...")
        run_command("python -m venv venv")
    else:
        print("\n Virtual environment already exists")
    
    # Determine activation command
    if os.name == 'nt':  # Windows
        python_cmd = "venv\\Scripts\\python"
        pip_cmd = "venv\\Scripts\\pip"
    else:  # Linux/Mac
        python_cmd = "venv/bin/python"
        pip_cmd = "venv/bin/pip"
    
    # Install dependencies
    print("\n📦 Installing dependencies...")
    run_command(f"{pip_cmd} install --upgrade pip")
    run_command(f"{pip_cmd} install -r requirements.txt")
    
    # Make main script executable
    if os.name != 'nt':  # Not Windows
        print("\n⚙️  Setting up permissions...")
        run_command("chmod +x quorra.py")
    
    # Install globally
    print("\n🔗 Installing globally...")
    run_command(f"{pip_cmd} install -e .")
    
    # Create initial database
    print("\n🗃️  Initializing database...")
    run_command(f"{python_cmd} -c \"from app.database import db; from app import app; with app.app_context(): db.create_all()\"")
    
    print("\n" + "=" * 50)
    print("Installation complete!")
    print("\n To start Quorra SIEM:")
    print("   1. First start Block Fortress on port 5000")
    print("   2. Run: quorra")
    print("\n Login Credentials:")
    print("   Username: user-quorra")
    print("   Password: quorra@1000")
    print("\n Login page will be available at: http://localhost:5001/login")
    print("\n  Troubleshooting:")
    print("   - Make sure port 5001 is available")
    print("   - Check if Block Fortress is running on port 5000")
    print("   - If login fails, check the database in data/quorra.db")

if __name__ == "__main__":
    main()
