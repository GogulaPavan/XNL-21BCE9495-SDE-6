
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import hashlib
import datetime
import streamlit as st
import requests
import os

# Initialize Flask App
app = Flask(__name__)
CORS(app, supports_credentials=True)
app.config['JWT_SECRET_KEY'] = 'supersecretkey'
jwt = JWTManager(app)

# Mock User Database
users = {
    "admin": hashlib.sha256("admin123".encode()).hexdigest(),
    "user": hashlib.sha256("user123".encode()).hexdigest()
}

# Security Headers Middleware
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Frame-Options'] = "DENY"
    response.headers['X-Content-Type-Options'] = "nosniff"
    response.headers['Strict-Transport-Security'] = "max-age=31536000; includeSubDomains"
    return response

@app.after_request
def apply_security_headers(response):
    return set_security_headers(response)

# Login Route
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = hashlib.sha256(data.get("password").encode()).hexdigest()
    if username in users and users[username] == password:
        access_token = create_access_token(identity=username, expires_delta=datetime.timedelta(hours=1))
        response = make_response(jsonify({"access_token": access_token}))
        response.set_cookie("access_token", access_token, httponly=True, secure=True)
        return response
    return jsonify({"message": "Invalid credentials"}), 401

# Protected Route
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Welcome {current_user}, this is a protected route!"})

# Streamlit UI
st.title("ULTRA‑ADVANCED SECURITY IMPLEMENTATION & PENETRATION TESTING")

if 'access_token' not in st.session_state:
    username = st.text_input("Username")
    password = st.text_input("Password", type='password')
    if st.button("Login"):
        response = requests.post("http://127.0.0.1:5000/login", json={"username": username, "password": password})
        if response.status_code == 200:
            st.session_state['access_token'] = response.cookies.get("access_token")
            st.success("Login successful!")
        else:
            st.error("Invalid credentials")
else:
    headers = {"Authorization": f"Bearer {st.session_state['access_token']}"}
    protected_response = requests.get("http://127.0.0.1:5000/protected", headers=headers)
    if protected_response.status_code == 200:
        st.success(protected_response.json()["message"])
    else:
        st.error("Session expired. Please log in again.")

# Run Flask App
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
