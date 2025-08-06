from flask import Flask, request

app = Flask(__name__)

correct_username = "admin"
correct_password = "letmein"

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if username == correct_username and password == correct_password:
        return "Welcome, admin!"  # Success indicator
    else:
        return "Login failed."

if __name__ == '__main__':
    app.run(debug=True)
