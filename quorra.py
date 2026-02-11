#!/usr/bin/env python3
"""
Quorra SIEM Tool - Main Entry Point
Command-line interface for Block Fortress integration
"""

import sys
import os
import webbrowser
import socket
import signal
from pathlib import Path
from app.main import app

def find_free_port(start_port=5001, max_port=5010):
    """Find a free port to run the application."""
    for port in range(start_port, max_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                return port
        except OSError:
            continue
    return start_port

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    print("\n\n Shutting down Quorra SIEM...")
    sys.exit(0)

def main():
    """Main entry point for Quorra SIEM tool."""
    signal.signal(signal.SIGINT, signal_handler)
    
    print("""
    ╔═══════════════════════════════════════╗
    ║            QUORRA SIEM                ║
    ║      Block Fortress Integration       ║
    ╚═══════════════════════════════════════╝
    """)
    
    # Check if running from terminal with command
    if len(sys.argv) > 1 and sys.argv[1] == "help":
        print("\nUsage: quorra [command]")
        print("\nCommands:")
        print("  start     - Start Quorra SIEM dashboard")
        print("  stop      - Stop Quorra SIEM")
        print("  status    - Check Quorra status")
        print("  help      - Show this help message")
        return
    
    # Find a free port
    port = find_free_port()
    
    print(f" Starting Quorra SIEM on port {port}...")
    print(" Connecting to Block Fortress on port 5000...")
    print(" Initializing security monitoring...")
    
    # Set environment variables
    os.environ['QUORRA_PORT'] = str(port)
    os.environ['BLOCK_FORTRESS_URL'] = 'http://localhost:5000'
    
    # Print the URL for easy access
    url = f"http://localhost:{port}"
    print(f"\n Quorra is running!")
    print(f" Open your browser and visit: {url}")
    print(f" Copy this link: {url}")
    
    # Ask if user wants to open browser automatically
    response = input("\n Open in browser now? (y/n): ").strip().lower()
    if response in ['y', 'yes', '']:
        webbrowser.open(url)
    
    print("\n Monitoring Block Fortress security logs...")
    print(" Detection Rules Active:")
    print("  1. Brute Force (10 failed logins in 2 mins)")
    print("  2. Geo-velocity (same user, different countries)")
    print("  3. Admin privilege escalation")
    print("  4. OS Command Injection")
    print("  5. Blocked IP detection")
    
    print("\n Press Ctrl+C to stop Quorra\n")
    
    # Run the application
    app.run(host='0.0.0.0', port=port, debug=True, use_reloader=False)

if __name__ == "__main__":
    main()
