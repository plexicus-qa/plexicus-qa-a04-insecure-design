import random
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

users = {
    1: {'id': 1, 'username': 'admin', 'password': 'admin123', 'email': 'admin@example.com',
        'role': 'admin', 'balance': 10000.0, 'failed_logins': 0, 'internal_notes': 'DO NOT SHARE - internal admin account'},
    2: {'id': 2, 'username': 'alice', 'password': 'alice123', 'email': 'alice@example.com',
        'role': 'user', 'balance': 500.0, 'failed_logins': 0, 'internal_notes': 'VIP customer'},
}
password_reset_tokens = {}
otps = {}
orders = {}
next_order_id = 1

# VULNERABILITY: No rate limiting on login - unlimited brute force
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    for user in users.values():
        if user['username'] == username and user['password'] == password:
            user['failed_logins'] = 0
            return jsonify({'token': f'token_{user["id"]}', 'user_id': user['id']})
    # Increment counter but never lock - no account lockout
    return jsonify({'error': 'invalid credentials'}), 401

# VULNERABILITY: 6-digit OTP, no expiry, returned in response, no rate limit
@app.route('/api/password_reset/request', methods=['POST'])
def request_password_reset():
    email = request.get_json().get('email')
    otp = str(random.randint(100000, 999999))
    otps[email] = {'otp': otp, 'created_at': None}
    return jsonify({'message': 'OTP sent', 'debug_otp': otp})  # OTP leaked in response!

@app.route('/api/password_reset/verify', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    # No rate limit, no expiry check - 1,000,000 attempts possible
    if email in otps and otps[email]['otp'] == otp:
        reset_token = f'reset_{email}_{otp}'  # Predictable token
        password_reset_tokens[reset_token] = email
        return jsonify({'reset_token': reset_token})
    return jsonify({'error': 'invalid OTP'}), 400

# VULNERABILITY: Client-supplied price, negative quantity for "refunds"
@app.route('/api/checkout', methods=['POST'])
def checkout():
    global next_order_id
    data = request.get_json()
    user_id = data.get('user_id')
    items = data.get('items', [])
    discount_code = data.get('discount_code', '')

    total = 0
    for item in items:
        price = item.get('price')      # Client-supplied price, not server-side
        quantity = item.get('quantity', 1)  # Negative quantity = steal money
        total += price * quantity

    if discount_code == 'SAVE50':     # No single-use tracking, can stack
        total *= 0.5

    order_id = next_order_id
    next_order_id += 1
    orders[order_id] = {'user_id': user_id, 'total': total, 'items': items}
    return jsonify({'order_id': order_id, 'total': total})

# VULNERABILITY: No MIME type or extension validation
@app.route('/api/upload', methods=['POST'])
def upload_file():
    uploaded_file = request.files.get('file')
    if not uploaded_file:
        return jsonify({'error': 'no file'}), 400
    filename = uploaded_file.filename  # User-controlled filename
    upload_path = os.path.join('/var/www/uploads', filename)
    uploaded_file.save(upload_path)
    return jsonify({'message': 'uploaded', 'path': upload_path, 'url': f'/uploads/{filename}'})

# VULNERABILITY: Excessive data exposure - returns internal fields
@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({'error': 'not found'}), 404
    return jsonify(user)  # Returns password, internal_notes, failed_logins

# VULNERABILITY: Mass assignment - attacker sets role=admin, balance=99999
@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    data = request.get_json()
    user = users.get(user_id)
    if not user:
        return jsonify({'error': 'not found'}), 404
    user.update(data)  # No whitelist - all fields writable
    return jsonify({'message': 'updated', 'user': user})

# VULNERABILITY: Sequential IDs = enumerable invoices, no auth check
@app.route('/api/invoices/<int:invoice_id>', methods=['GET'])
def get_invoice(invoice_id):
    return jsonify({
        'invoice_id': invoice_id,
        'amount': 100.0 * invoice_id,
        'pdf_url': f'/invoices/{invoice_id}.pdf',
        'customer_email': f'user{invoice_id}@example.com'
    })

# VULNERABILITY: 4-digit OTP, no lockout, unlimited attempts
@app.route('/api/otp/verify', methods=['POST'])
def verify_payment_otp():
    data = request.get_json()
    otp = data.get('otp')
    expected_otp = '1234'
    if otp == expected_otp:
        return jsonify({'authorized': True, 'token': 'payment_auth_token'})
    return jsonify({'authorized': False}), 401

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5004)
