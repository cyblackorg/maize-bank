#!/usr/bin/env python3
"""
Test script to demonstrate database and system protections
"""

from protections import db_protection, system_protection
from database import execute_query
import subprocess

def test_database_protections():
    """Test database protection mechanisms"""
    print("=== Testing Database Protections ===\n")
    
    # Test dangerous SQL queries (only the specific ones we want to block)
    dangerous_queries = [
        "DROP DATABASE maze_bank",
        "DROP TABLE users",
        "TRUNCATE TABLE users",
        "DELETE FROM users",
        "ALTER TABLE users DROP COLUMN password",
        "DROP SCHEMA public",
    ]
    
    for query in dangerous_queries:
        print(f"Testing query: {query}")
        is_safe, error_msg = db_protection.check_sql_safety(query)
        if is_safe:
            print(f"  ❌ FAILED: Query should be blocked but was allowed")
        else:
            print(f"  ✅ PASSED: Query blocked - {error_msg}")
        print()
    
    # Test safe queries (including SQL injection vulnerable ones)
    safe_queries = [
        "SELECT * FROM users",
        "INSERT INTO users (username, password) VALUES ('test', 'test')",
        "UPDATE users SET balance = 1000 WHERE id = 1",
        "SELECT COUNT(*) FROM users",
        # These should still be vulnerable to SQL injection
        "DELETE FROM users WHERE id = 1 OR id = 2",  # Should be allowed for SQL injection testing
        "UPDATE users SET balance = 0 WHERE id = 1 OR id = 2",  # Should be allowed for SQL injection testing
    ]
    
    print("Testing safe queries:")
    for query in safe_queries:
        print(f"Testing query: {query}")
        is_safe, error_msg = db_protection.check_sql_safety(query)
        if is_safe:
            print(f"  ✅ PASSED: Query allowed")
        else:
            print(f"  ❌ FAILED: Query should be allowed but was blocked - {error_msg}")
        print()

def test_system_protections():
    """Test system command protection mechanisms"""
    print("=== Testing System Command Protections ===\n")
    
    # Test dangerous system commands (only system failure ones)
    dangerous_commands = [
        "docker-compose down",
        "docker stop $(docker ps -q)",
        "systemctl stop nginx",
        "shutdown -h now",
        "halt",
        "poweroff",
        "reboot",
        "init 0",
        "service stop nginx",
    ]
    
    for command in dangerous_commands:
        print(f"Testing command: {command}")
        is_safe, error_msg = system_protection.is_safe_to_execute(command)
        if is_safe:
            print(f"  ❌ FAILED: Command should be blocked but was allowed")
        else:
            print(f"  ✅ PASSED: Command blocked - {error_msg}")
        print()
    
    # Test safe commands (including command injection vulnerable ones)
    safe_commands = [
        "ls -la",
        "pwd",
        "whoami",
        "echo 'Hello World'",
        "cat /etc/passwd",
        "ps aux",
        "df -h",
        "free -h",
        "uptime",
        "date",
        # These should still be vulnerable to command injection
        "rm -rf /tmp/test",  # Should be allowed for command injection testing
        "killall python",     # Should be allowed for command injection testing
        "pkill -f app.py",    # Should be allowed for command injection testing
        "echo 'test' | rm",   # Should be allowed for command injection testing
        "echo 'test' && rm -rf /tmp",  # Should be allowed for command injection testing
    ]
    
    print("Testing safe commands:")
    for command in safe_commands:
        print(f"Testing command: {command}")
        is_safe, error_msg = system_protection.is_safe_to_execute(command)
        if is_safe:
            print(f"  ✅ PASSED: Command allowed")
        else:
            print(f"  ❌ FAILED: Command should be allowed but was blocked - {error_msg}")
        print()

def test_database_execution():
    """Test actual database execution with protections"""
    print("=== Testing Database Execution with Protections ===\n")
    
    try:
        # Test safe query
        print("Testing safe SELECT query:")
        result = execute_query("SELECT COUNT(*) FROM users")
        print(f"  ✅ PASSED: Safe query executed successfully - {result}")
        print()
        
        # Test dangerous query (should be blocked)
        print("Testing dangerous DROP query:")
        try:
            result = execute_query("DROP TABLE users")
            print(f"  ❌ FAILED: Dangerous query should be blocked but executed")
        except Exception as e:
            print(f"  ✅ PASSED: Dangerous query blocked - {str(e)}")
        print()
        
    except Exception as e:
        print(f"Database connection error: {e}")

def test_system_execution():
    """Test actual system command execution with protections"""
    print("=== Testing System Command Execution with Protections ===\n")
    
    # Test safe command
    print("Testing safe command (ls):")
    success, stdout, stderr = system_protection.safe_execute("ls -la")
    if success:
        print(f"  ✅ PASSED: Safe command executed successfully")
        print(f"  Output: {stdout[:100]}...")
    else:
        print(f"  ❌ FAILED: Safe command failed - {stderr}")
    print()
    
    # Test dangerous command (should be blocked)
    print("Testing dangerous command (rm -rf):")
    success, stdout, stderr = system_protection.safe_execute("rm -rf /tmp/test")
    if success:
        print(f"  ❌ FAILED: Dangerous command should be blocked but executed")
    else:
        print(f"  ✅ PASSED: Dangerous command blocked - {stderr}")
    print()

if __name__ == "__main__":
    print("🔒 Database and System Protection Test Suite\n")
    print("This script tests the protection mechanisms implemented to prevent:")
    print("1. Database deletion and dangerous operations")
    print("2. System commands that could lead to system failure\n")
    
    test_database_protections()
    test_system_protections()
    test_database_execution()
    test_system_execution()
    
    print("✅ Protection test suite completed!") 