# Database and System Protections

This document describes the protection mechanisms implemented to prevent database deletion and dangerous system commands.

## Overview

The application now includes **targeted protection** against:
1. **Database deletion and dangerous operations** - Only prevents specific dangerous operations
2. **System commands that could lead to system failure** - Only prevents system shutdown/stopping commands

**Important**: These protections are designed to prevent catastrophic failures while **preserving all intentional vulnerabilities** for educational purposes. SQL injection and command injection vulnerabilities remain intact.

## Database Protections

### Protected Operations

The following database operations are now blocked:

- `DROP DATABASE` - Prevents database deletion
- `DROP TABLE` - Prevents table deletion  
- `TRUNCATE TABLE` - Prevents table truncation
- `DELETE FROM users` - Prevents user deletion
- `ALTER TABLE users DROP` - Prevents user table structure changes
- `DROP SCHEMA` - Prevents schema deletion

**Note**: SQL injection vulnerabilities are preserved. Queries like `DELETE FROM users WHERE id = 1 OR id = 2` are still allowed to demonstrate SQL injection attacks.

### Implementation

The protection is implemented in `protections.py` and integrated into `database.py`:

```python
# Check if query is safe before execution
is_safe, error_msg = db_protection.check_sql_safety(query)
if not is_safe:
    raise Exception(f"Database protection: {error_msg}")
```

### Protected Functions

- `execute_query()` - All database queries go through protection checks
- `execute_transaction()` - Transaction queries are protected
- AI agent database access - AI queries are also protected

## System Command Protections

### Blocked Commands

The following system commands are blocked:

- `docker-compose down` - Prevents stopping containers
- `docker stop` / `docker kill` - Prevents container stopping
- `systemctl stop` / `systemctl disable` - Prevents service stopping
- `shutdown` / `halt` / `poweroff` / `reboot` - Prevents system shutdown
- `init 0` / `init 6` - Prevents system initialization changes

**Note**: Command injection vulnerabilities are preserved. Commands like `rm -rf`, `killall`, and command separators (`;`, `|`, `&&`) are still allowed to demonstrate command injection attacks.

### Implementation

System command protection is implemented in `protections.py`:

```python
# Check if command is safe before execution
is_safe, error_msg = system_protection.is_safe_to_execute(command)
if not is_safe:
    return False, "", f"Command blocked: {error_msg}"
```

### Protected Endpoints

- `/api/system/execute` - Protected system command execution endpoint
- AI agent system access - AI system commands are protected

## Testing

Run the protection test suite:

```bash
python test_protections.py
```

This will test:
- Database protection mechanisms
- System command protection mechanisms
- Actual execution with protections

## Example Protection in Action

### Database Protection Example

```python
# This will be blocked
try:
    execute_query("DROP TABLE users")
except Exception as e:
    print(f"Blocked: {e}")
    # Output: "Blocked: Database protection: Blocked dangerous SQL operation: DROP TABLE"

# This will be allowed
result = execute_query("SELECT * FROM users")
```

### System Command Protection Example

```python
# This will be blocked
success, stdout, stderr = system_protection.safe_execute("rm -rf /")
# success = False, stderr = "Command blocked: Blocked dangerous system command: rm -rf"

# This will be allowed
success, stdout, stderr = system_protection.safe_execute("ls -la")
# success = True, stdout contains directory listing
```

## Integration Points

### Database Layer
- `database.py` - All query execution goes through protection
- `execute_query()` - Protected query execution
- `execute_transaction()` - Protected transaction execution

### Application Layer
- `app.py` - System command endpoint with protection
- AI agent database access - Protected database queries

### AI Agent
- `ai_agent_deepseek.py` - Database queries protected
- System command access protected

## Security Benefits

1. **Prevents Data Loss**: Database deletion operations are blocked
2. **Prevents System Failure**: Dangerous system commands are blocked
3. **Maintains Application Stability**: Critical operations are protected
4. **Audit Trail**: Blocked operations are logged with error messages
5. **Preserves Educational Value**: All intentional vulnerabilities remain for learning purposes

## Configuration

The protection patterns can be modified in `protections.py`:

- `DANGEROUS_SQL_PATTERNS` - Add/remove SQL patterns to block
- `DANGEROUS_SYSTEM_COMMANDS` - Add/remove system commands to block

## Monitoring

Blocked operations will throw exceptions with descriptive messages:

```python
# Database protection error
"Database protection: Blocked dangerous SQL operation: DROP TABLE"

# System command protection error  
"Command blocked: Blocked dangerous system command: rm -rf"
```

These errors can be logged and monitored for security analysis. 