import os
import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import bcrypt
from bson import ObjectId
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager

app = Flask(__name__)
CORS(app)

# --- CONFIGURATION ---
# Use the correct key that Flask-JWT-Extended expects
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
jwt = JWTManager(app)

# MongoDB connection
MONGO_URI = os.environ.get("MONGO_URI")
client = MongoClient(MONGO_URI)
# --- END CONFIGURATION ---

db = client["SmartSaver"]
users = db["users"]
goals = db["goals"]
transactions = db["transactions"]

# ------------------ Routes ------------------

# Health check route for Render
@app.route("/")
def index():
    return jsonify({"status": "API is running!"})

# --- Auth Routes ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not all([name, email, password]):
        return jsonify({"error": "Missing name, email, or password"}), 400

    if users.find_one({"email": email}):
        return jsonify({"error": "User already exists"}), 400

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users.insert_one({"name": name, "email": email, "password": hashed_pw})

    return jsonify({"message": "User registered successfully!"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({"error": "Missing email or password"}), 400

    user = users.find_one({"email": email})
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({"error": "Invalid email or password"}), 401

    # Create token using Flask-JWT-Extended
    access_token = create_access_token(identity=str(user["_id"]))
    return jsonify(access_token=access_token)

# --- User Profile Routes ---
@app.route('/me', methods=['GET'])
@jwt_required()
def get_profile():
    current_user_id = get_jwt_identity()
    user = users.find_one({"_id": ObjectId(current_user_id)})
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"email": user['email'], "name": user['name']})

@app.route('/me', methods=['PUT'])
@jwt_required()
def update_profile():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    if not data or 'name' not in data or not data['name'].strip():
        return jsonify({"error": "Name field is required"}), 400

    update_data = {'name': data['name'].strip()}
    users.update_one({"_id": ObjectId(current_user_id)}, {"$set": update_data})
    return jsonify({"message": "Profile updated successfully"})

@app.route('/me/password', methods=['PUT'])
@jwt_required()
def change_password():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not all([current_password, new_password]):
        return jsonify({"error": "Current and new password are required"}), 400

    user = users.find_one({"_id": ObjectId(current_user_id)})
    if not user or not bcrypt.checkpw(current_password.encode('utf-8'), user['password']):
        return jsonify({"error": "Current password is incorrect"}), 400

    hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    users.update_one({"_id": ObjectId(current_user_id)}, {"$set": {"password": hashed_new_password}})
    return jsonify({"message": "Password changed successfully"})

@app.route('/me', methods=['DELETE'])
@jwt_required()
def delete_account():
    current_user_id = get_jwt_identity()
    # cascade delete goals and transactions
    user_goals = list(goals.find({"user_id": current_user_id}))
    goal_ids = [str(goal["_id"]) for goal in user_goals]
    if goal_ids:
        transactions.delete_many({"goal_id": {"$in": goal_ids}})
    goals.delete_many({"user_id": current_user_id})
    users.delete_one({"_id": ObjectId(current_user_id)})
    return jsonify({"message": "Account deleted successfully"})

# --- Goal Routes ---
@app.route('/goals', methods=['POST'])
@jwt_required()
def create_goal():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    goal = {
        "user_id": current_user_id,
        "name": data["name"],
        "target": data["target"],
        "saved": 0,
        "icon": data.get("icon", "🎯"),
        "created_at": datetime.datetime.now(datetime.timezone.utc)
    }
    result = goals.insert_one(goal)
    goal["_id"] = str(result.inserted_id)
    return jsonify(goal), 201

@app.route('/goals', methods=['GET'])
@jwt_required()
def get_goals():
    current_user_id = get_jwt_identity()
    user_goals = list(goals.find({"user_id": current_user_id}))
    for g in user_goals:
        g["_id"] = str(g["_id"])
    return jsonify(user_goals)

@app.route('/goals/<goal_id>', methods=['GET'])
@jwt_required()
def get_goal(goal_id):
    current_user_id = get_jwt_identity()
    goal = goals.find_one({"_id": ObjectId(goal_id), "user_id": current_user_id})
    if not goal:
        return jsonify({"error": "Goal not found"}), 404

    goal["_id"] = str(goal["_id"])
    txns = list(transactions.find({"goal_id": goal_id}).sort("date", -1))
    for t in txns:
        t["_id"] = str(t["_id"])
    return jsonify({"goal": goal, "transactions": txns})

@app.route('/goals/<goal_id>/add', methods=['POST'])
@jwt_required()
def add_money(goal_id):
    current_user_id = get_jwt_identity()
    data = request.get_json()
    amount = data.get("amount", 0)

    result = goals.update_one(
        {"_id": ObjectId(goal_id), "user_id": current_user_id},
        {"$inc": {"saved": amount}}
    )

    if result.modified_count == 0:
        return jsonify({"error": "Goal not found or not updated"}), 404

    txn = {
        "goal_id": goal_id,
        "amount": amount,
        "date": datetime.datetime.now(datetime.timezone.utc)
    }
    transactions.insert_one(txn)
    return jsonify({"message": "Money added!"})

# Add a withdraw money route
@app.route('/goals/<goal_id>/withdraw', methods=['POST'])
@jwt_required()
def withdraw_money(goal_id):
    current_user_id = get_jwt_identity()
    data = request.get_json()
    amount = data.get("amount", 0)

    # Ensure withdrawal amount is positive
    if amount <= 0:
        return jsonify({"error": "Amount must be positive"}), 400

    goal = goals.find_one({"_id": ObjectId(goal_id), "user_id": current_user_id})
    if not goal:
        return jsonify({"error": "Goal not found"}), 404
    
    if amount > goal['saved']:
        return jsonify({"error": "Withdrawal amount exceeds saved amount"}), 400

    result = goals.update_one(
        {"_id": ObjectId(goal_id)},
        {"$inc": {"saved": -amount}}
    )

    if result.modified_count == 0:
        return jsonify({"error": "Failed to withdraw money"}), 400

    txn = {
        "goal_id": goal_id,
        "amount": -amount,  # Store withdrawal as a negative amount
        "date": datetime.datetime.now(datetime.timezone.utc)
    }
    transactions.insert_one(txn)
    return jsonify({"message": "Money withdrawn!"})

# ------------------ Run ------------------
if __name__ == '__main__':
    app.run(debug=True)
