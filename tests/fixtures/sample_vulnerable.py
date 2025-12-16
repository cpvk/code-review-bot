"""Sample file with intentional vulnerabilities for testing."""

import os
import subprocess


def get_user(username):
    """SQL injection vulnerability."""
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query)


def render_page(user_input):
    """XSS vulnerability."""
    return f"<html><body>{user_input}</body></html>"


def run_command(cmd):
    """Command injection vulnerability."""
    os.system(cmd)


def read_file(filename):
    """Path traversal vulnerability."""
    path = "/data/" + filename
    with open(path) as f:
        return f.read()


def process_data(data):
    """Insecure deserialization."""
    import pickle
    return pickle.loads(data)


API_KEY = "sk-1234567890abcdef"  # Hardcoded secret


def divide(a, b):
    """Potential ZeroDivisionError - no check."""
    return a / b


def get_items(items):
    """Potential None dereference."""
    first = items[0]
    return first.name


def fetch_all_users():
    """N+1 query problem."""
    users = db.query("SELECT * FROM users")
    for user in users:
        user.posts = db.query(f"SELECT * FROM posts WHERE user_id = {user.id}")
    return users


def process_list(items):
    """Unnecessary nested loop."""
    result = []
    for i in items:
        for j in items:
            if i == j:
                result.append(i)
    return result
