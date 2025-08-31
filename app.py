from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import bcrypt
import jwt
import datetime
from bson import ObjectId

app = Flask(__name__)
CORS(app)

# Secret key for JWT
app.config['SECRET_KEY'] = "yoursecretkey"

# MongoDB connection
client = MongoClient("mongodb+srv://VatsalBairagi:Vatsal2004@vatsal.vgheuph.mongodb.net/")
db = client["SmartSaver"]
users = db["users"]
goals = db["goals"]
transactions = db["transactions"]

# ------------------ Helpers ------------------
def decode_token(token):
    try:
        # Handle both "Bearer <token>" and plain token formats
        if token and token.startswith("Bearer "):
            token = token[7:]  # Remove "Bearer " prefix
        
        return jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    except Exception as e:
        print(f"Token decode error: {e}")
        return None


# ------------------ Auth ------------------
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data['name']
    email = data['email']
    password = data['password']

    if users.find_one({"email": email}):
        return jsonify({"error": "User already exists"}), 400

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users.insert_one({"name": name, "email": email, "password": hashed_pw})

    return jsonify({"message": "User registered successfully!"})


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']

    user = users.find_one({"email": email})
    if not user:
        return jsonify({"error": "Invalid email"}), 401

    if bcrypt.checkpw(password.encode('utf-8'), user['password']):
        token = jwt.encode({
            "user_id": str(user["_id"]),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({"token": token})
    else:
        return jsonify({"error": "Invalid password"}), 401


@app.route('/me', methods=['GET'])
def get_profile():
    token = request.headers.get("Authorization")
    decoded = decode_token(token)
    if not decoded:
        return jsonify({"error": "Invalid or missing token"}), 401

    user = users.find_one({"_id": ObjectId(decoded['user_id'])})
    return jsonify({"email": user['email'], "name": user['name']})


@app.route('/me', methods=['PUT'])
def update_profile():
    try:
        token = request.headers.get("Authorization")
        decoded = decode_token(token)
        if not decoded:
            return jsonify({"error": "Invalid or missing token"}), 401

        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        update_data = {}
        if 'name' in data and data['name'].strip():
            update_data['name'] = data['name'].strip()

        if not update_data:
            return jsonify({"error": "No valid fields to update"}), 400

        result = users.update_one(
            {"_id": ObjectId(decoded['user_id'])},
            {"$set": update_data}
        )

        if result.modified_count == 0:
            return jsonify({"error": "Profile not updated"}), 400

        return jsonify({"message": "Profile updated successfully"})
    except Exception as e:
        print(f"Update profile error: {e}")
        return jsonify({"error": "Failed to update profile"}), 500


@app.route('/me/password', methods=['PUT'])
def change_password():
    try:
        token = request.headers.get("Authorization")
        decoded = decode_token(token)
        if not decoded:
            return jsonify({"error": "Invalid or missing token"}), 401

        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')

        if not current_password or not new_password:
            return jsonify({"error": "Current and new password are required"}), 400

        if len(new_password) < 6:
            return jsonify({"error": "New password must be at least 6 characters"}), 400

        # Get user and verify current password
        user = users.find_one({"_id": ObjectId(decoded['user_id'])})
        if not user:
            return jsonify({"error": "User not found"}), 404

        if not bcrypt.checkpw(current_password.encode('utf-8'), user['password']):
            return jsonify({"error": "Current password is incorrect"}), 400

        # Hash new password and update
        hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        result = users.update_one(
            {"_id": ObjectId(decoded['user_id'])},
            {"$set": {"password": hashed_new_password}}
        )

        if result.modified_count == 0:
            return jsonify({"error": "Password not updated"}), 400

        return jsonify({"message": "Password changed successfully"})
    except Exception as e:
        print(f"Change password error: {e}")
        return jsonify({"error": "Failed to change password"}), 500


@app.route('/me', methods=['DELETE'])
def delete_account():
    try:
        token = request.headers.get("Authorization")
        decoded = decode_token(token)
        if not decoded:
            return jsonify({"error": "Invalid or missing token"}), 401

        user_id = decoded['user_id']

        # Delete user's goals
        goals.delete_many({"user_id": user_id})

        # Delete user's transactions (get goal IDs first)
        user_goals = list(goals.find({"user_id": user_id}))
        goal_ids = [str(goal["_id"]) for goal in user_goals]
        if goal_ids:
            transactions.delete_many({"goal_id": {"$in": goal_ids}})

        # Delete user
        result = users.delete_one({"_id": ObjectId(user_id)})
        if result.deleted_count == 0:
            return jsonify({"error": "User not found"}), 404

        return jsonify({"message": "Account deleted successfully"})
    except Exception as e:
        print(f"Delete account error: {e}")
        return jsonify({"error": "Failed to delete account"}), 500


# ------------------ Goals ------------------
@app.route('/goals', methods=['POST'])
def create_goal():
    print("Received goal creation request")
    token = request.headers.get("Authorization")
    print(f"Token received: {token[:20] if token else 'None'}...")
    
    decoded = decode_token(token)
    if not decoded:
        print("Token decode failed")
        return jsonify({"error": "Invalid or missing token"}), 401

    print(f"Token decoded successfully for user: {decoded['user_id']}")
    
    data = request.get_json()
    print(f"Request data: {data}")
    
    goal = {
        "user_id": decoded["user_id"],
        "name": data["name"],
        "target": data["target"],
        "saved": 0,
        "icon": data.get("icon", "🎯"),
        "created_at": datetime.datetime.utcnow()
    }
    
    print(f"Goal object to insert: {goal}")
    
    result = goals.insert_one(goal)
    goal["_id"] = str(result.inserted_id)
    print(f"Goal created with ID: {goal['_id']}")
    
    return jsonify(goal), 201


@app.route('/goals', methods=['GET'])
def get_goals():
    print("Received get goals request")
    token = request.headers.get("Authorization")
    print(f"Token received: {token[:20] if token else 'None'}...")
    
    decoded = decode_token(token)
    if not decoded:
        print("Token decode failed")
        return jsonify({"error": "Invalid or missing token"}), 401

    print(f"Token decoded successfully for user: {decoded['user_id']}")
    
    user_goals = list(goals.find({"user_id": decoded["user_id"]}))
    print(f"Found {len(user_goals)} goals for user")
    
    for g in user_goals:
        g["_id"] = str(g["_id"])
        print(f"Goal: {g['name']} - Target: {g['target']} - Saved: {g['saved']}")
    
    return jsonify(user_goals)


@app.route('/goals/<goal_id>', methods=['GET'])
def get_goal(goal_id):
    token = request.headers.get("Authorization")
    decoded = decode_token(token)
    if not decoded:
        return jsonify({"error": "Invalid or missing token"}), 401

    goal = goals.find_one({"_id": ObjectId(goal_id), "user_id": decoded["user_id"]})
    if not goal:
        return jsonify({"error": "Goal not found"}), 404

    goal["_id"] = str(goal["_id"])

    txns = list(transactions.find({"goal_id": goal["_id"]}).sort("date", -1))
    for t in txns:
        t["_id"] = str(t["_id"])
    return jsonify({"goal": goal, "transactions": txns})


@app.route('/goals/<goal_id>/add', methods=['POST'])
def add_money(goal_id):
    token = request.headers.get("Authorization")
    decoded = decode_token(token)
    if not decoded:
        return jsonify({"error": "Invalid or missing token"}), 401

    data = request.get_json()
    amount = data.get("amount", 0)

    result = goals.update_one(
        {"_id": ObjectId(goal_id), "user_id": decoded["user_id"]},
        {"$inc": {"saved": amount}}
    )

    if result.modified_count == 0:
        return jsonify({"error": "Goal not found or not updated"}), 404

    txn = {
        "goal_id": goal_id,
        "amount": amount,
        "date": datetime.datetime.utcnow()
    }
    transactions.insert_one(txn)

    return jsonify({"message": "Money added!"})


# ------------------ Run ------------------
@app.errorhandler(Exception)
def handle_exception(e):
    print(f"Unhandled exception: {e}")
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(debug=True)
