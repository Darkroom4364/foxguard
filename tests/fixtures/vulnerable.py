import sqlite3

password = "supersecret123"
api_key = "not_a_password"

def run_query(user_input):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + user_input + "'")
    return cursor.fetchall()

def dangerous():
    eval(input("Enter code: "))
    exec("print('hello')")

def safe():
    x = 1 + 2
    print(x)
