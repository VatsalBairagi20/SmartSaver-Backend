import os
import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import bcrypt
from bson import ObjectId
from bson.errors import InvalidId
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager

app = Flask(__name__)
CORS(app)

# --- CONFIGURATION & STARTUP CHECKS ---
# NEW: Check for required environment variables on startup for failsafe deployment
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
MONGO_URI = os.environ.get("MONGO_URI")

if not JWT_SECRET_KEY or not MONGO_URI:
    raise RuntimeError("FATAL: JWT_SECRET_KEY and MONGO_URI must be set in the environment.")

app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
jwt = JWTManager(app)

# NEW: Establish and test MongoDB connection within a try-except block
try:
    client = MongoClient(MONGO_URI)
    # The ismaster command is cheap and does not require auth.
    client.admin.command('ismaster')
    print("MongoDB connection successful.")
except ConnectionFailure as e:
    raise RuntimeError(f"MongoDB connection failed: {e}")

db = client["SmartSaver"]
users = db["users"]
goals = db["goals"]
transactions = db["transactions"]
# --- END CONFIGURATION ---

# ------------------ Routes ------------------

# Health check route for Render
@app.route("/")
def index():
    return jsonify({"status": "API is running!"})

# --- Auth Routes ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    # IMPROVED: Use .get() for safer access and check for missing data
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
    # IMPROVED: Don't return the full user object, just the necessary fields
    return jsonify({
        "id": str(user["_id"]),
        "email": user['email'],
        "name": user['name']
    })

# --- Goal Routes ---
@app.route('/goals', methods=['POST'])
@jwt_required()
def create_goal():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    name = data.get("name")
    target = data.get("target")

    if not name or target is None:
        return jsonify({"error": "Goal name and target are required"}), 400
    
    try:
        target_amount = float(target)
        if target_amount <= 0:
             return jsonify({"error": "Target must be a positive number"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "Target must be a valid number"}), 400
    
    goal = {
        "user_id": current_user_id,
        "name": name,
        "target": target_amount,
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
    # IMPROVED: Add error handling for invalid ID formats
    try:
        obj_goal_id = ObjectId(goal_id)
    except InvalidId:
        return jsonify({"error": "Invalid goal ID format"}), 400

    goal = goals.find_one({"_id": obj_goal_id, "user_id": current_user_id})
    if not goal:
        return jsonify({"error": "Goal not found"}), 404

    goal["_id"] = str(goal["_id"])
    # Find transactions related to this goal's string ID
    txns = list(transactions.find({"goal_id": goal_id}).sort("date", -1))
    for t in txns:
        t["_id"] = str(t["_id"])
    return jsonify({"goal": goal, "transactions": txns})

# --- Transaction Routes ---
@app.route('/goals/<goal_id>/transaction', methods=['POST'])
@jwt_required()
def add_transaction(goal_id):
    current_user_id = get_jwt_identity()
    data = request.get_json()
    amount = data.get("amount", 0)

    try:
        transaction_amount = float(amount)
    except (ValueError, TypeError):
        return jsonify({"error": "Amount must be a valid number"}), 400

    try:
        obj_goal_id = ObjectId(goal_id)
    except InvalidId:
        return jsonify({"error": "Invalid goal ID format"}), 400

    goal = goals.find_one({"_id": obj_goal_id, "user_id": current_user_id})
    if not goal:
        return jsonify({"error": "Goal not found"}), 404
    
    # Prevent withdrawing more than available
    if goal['saved'] + transaction_amount < 0:
        return jsonify({"error": "Transaction amount exceeds saved balance"}), 400

    result = goals.update_one(
        {"_id": obj_goal_id},
        {"$inc": {"saved": transaction_amount}}
    )

    if result.modified_count == 0:
        return jsonify({"error": "Goal not found or not updated"}), 404

    txn = {
        "goal_id": goal_id,
        "amount": transaction_amount,
        "date": datetime.datetime.now(datetime.timezone.utc)
    }
    transactions.insert_one(txn)
    return jsonify({"message": f"Transaction of {transaction_amount} recorded!"})

# --- Dashboard Route ---
# NEW: A route to get overall stats for the dashboard screen
@app.route('/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    current_user_id = get_jwt_identity()
    
    pipeline = [
        {"$match": {"user_id": current_user_id}},
        {"$group": {
            "_id": None,
            "total_saved": {"$sum": "$saved"},
            "total_target": {"$sum": "$target"},
            "goals_count": {"$sum": 1}
        }}
    ]
    
    stats = list(goals.aggregate(pipeline))
    
    if not stats:
        return jsonify({
            "total_saved": 0,
            "total_target": 0,
            "goals_count": 0,
        })
    
    return jsonify(stats[0])

# ------------------ Run ------------------
if __name__ == '__main__':
    # This block is for local development only. Gunicorn will run the app in production.
    app.run(debug=True, port=5000)
