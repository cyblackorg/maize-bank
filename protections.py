import re
import subprocess
import os
from typing import List, Tuple, Optional

class DatabaseProtection:
    """Protection class to prevent database deletion and dangerous operations"""
    
    # Dangerous SQL patterns that should be blocked
    # ONLY blocking specific dangerous operations, preserving SQL injection vulnerabilities
    DANGEROUS_SQL_PATTERNS = [
        r'\bDROP\s+DATABASE\b',
        r'\bDROP\s+TABLE\b', 
        r'\bTRUNCATE\s+TABLE\b',
        r'\bDELETE\s+FROM\s+users\b',
        r'\bALTER\s+TABLE\s+users\s+DROP\b',
        r'\bDROP\s+SCHEMA\b',
    ]
    
    # Dangerous system commands that should be blocked
    # ONLY blocking system failure commands, preserving command injection vulnerabilities
    DANGEROUS_SYSTEM_COMMANDS = [
        'docker-compose down',
        'docker stop',
        'docker kill',
        'systemctl stop',
        'systemctl disable',
        'service stop',
        'shutdown',
        'halt',
        'poweroff',
        'reboot',
        'init 0',
        'init 6',
    ]
    
    @classmethod
    def check_sql_safety(cls, query: str) -> Tuple[bool, Optional[str]]:
        """
        Check if SQL query is safe to execute
        
        Args:
            query: SQL query to check
            
        Returns:
            Tuple of (is_safe, error_message)
        """
        query_upper = query.upper().strip()
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_SQL_PATTERNS:
            if re.search(pattern, query_upper, re.IGNORECASE):
                return False, f"Blocked dangerous SQL operation: {pattern}"
        
        # Additional checks for specific dangerous operations
        if 'DROP' in query_upper and ('DATABASE' in query_upper or 'TABLE' in query_upper):
            return False, "DROP operations are not allowed"
        
        if 'TRUNCATE' in query_upper:
            return False, "TRUNCATE operations are not allowed"
        
        if 'DELETE FROM USERS' in query_upper:
            return False, "Deleting users is not allowed"
        
        return True, None
    
    @classmethod
    def check_system_command_safety(cls, command: str) -> Tuple[bool, Optional[str]]:
        """
        Check if system command is safe to execute
        
        Args:
            command: Command to check
            
        Returns:
            Tuple of (is_safe, error_message)
        """
        command_lower = command.lower().strip()
        
        # Check for dangerous commands
        for dangerous_cmd in cls.DANGEROUS_SYSTEM_COMMANDS:
            if dangerous_cmd.lower() in command_lower:
                return False, f"Blocked dangerous system command: {dangerous_cmd}"
        
        # Only block specific system failure commands, preserve command injection vulnerabilities
        # This allows SQL injection and command injection to still work for educational purposes
        
        return True, None
    
    @classmethod
    def sanitize_sql_query(cls, query: str) -> str:
        """
        Minimal sanitization - only removes comments, preserves SQL injection vulnerabilities
        for educational purposes
        
        Args:
            query: Original SQL query
            
        Returns:
            Sanitized query (minimal changes)
        """
        # Only remove comments, preserve all other vulnerabilities
        query = re.sub(r'--.*$', '', query, flags=re.MULTILINE)
        query = re.sub(r'/\*.*?\*/', '', query, flags=re.DOTALL)
        
        return query

class SystemProtection:
    """Protection class to prevent dangerous system operations"""
    
    @classmethod
    def is_safe_to_execute(cls, command: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a command is safe to execute
        
        Args:
            command: Command to check
            
        Returns:
            Tuple of (is_safe, error_message)
        """
        return DatabaseProtection.check_system_command_safety(command)
    
    @classmethod
    def safe_execute(cls, command: str, timeout: int = 30) -> Tuple[bool, str, str]:
        """
        Safely execute a command with protection checks
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        # Check if command is safe
        is_safe, error_msg = cls.is_safe_to_execute(command)
        if not is_safe:
            return False, "", f"Command blocked: {error_msg}"
        
        try:
            # Execute command with timeout
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command execution timed out"
        except Exception as e:
            return False, "", f"Command execution failed: {str(e)}"

# Global protection instances
db_protection = DatabaseProtection()
system_protection = SystemProtection() 