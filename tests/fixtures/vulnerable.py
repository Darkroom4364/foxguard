# Vulnerable Python file — triggers all 11 foxguard Python rules

import os
import pickle
import hashlib
import yaml
import subprocess

# 1. py/no-eval (Critical)
user_input = "print('hacked')"
eval(user_input)

# 2. py/no-hardcoded-secret (High)
password = "super_secret_password_123"

# 3. py/no-sql-injection — f-string (Critical)
user_id = "1"
query1 = f"SELECT * FROM users WHERE id = {user_id}"

# 4. py/no-sql-injection — % formatting (Critical)
query2 = "SELECT * FROM users WHERE id = %s" % user_id

# 5. py/no-sql-injection — .format() (Critical)
query3 = "SELECT * FROM users WHERE id = {}".format(user_id)

# 6. py/no-command-injection (Critical)
os.system(f"ls {user_input}")

# 7. py/no-path-traversal (High)
data = open(user_input)

# 8. py/no-weak-crypto (Medium)
h = hashlib.md5()

# 9. py/no-pickle (High)
obj = pickle.loads(b"data")

# 10. py/no-yaml-load (High)
config = yaml.load(open("config.yml"))

# 11. py/no-debug-true (Medium)
DEBUG = True

# 12. py/no-open-redirect (Medium)
redirect(user_input)

# 13. py/no-cors-star (Medium)
CORS_ALLOW_ALL_ORIGINS = True
