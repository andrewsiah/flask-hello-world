from authlib.integrations.flask_client import OAuth
from flask import Flask, render_template, url_for, redirect, session, jsonify, request
from authlib.common.security import generate_token
import os
import openai
import dotenv

app = Flask(__name__)
app.secret_key = os.urandom(12)

oauth = OAuth(app)
dotenv.load_dotenv()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/google/')
def google():

    
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
    CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url=CONF_URL,
        client_kwargs={
            'scope': 'openid email profile'
        }
    )

    # Redirect to google_auth function
    redirect_uri = url_for('google_auth', _external=True)
    print(redirect_uri)
    session['nonce'] = generate_token()
    return oauth.google.authorize_redirect(redirect_uri, nonce=session['nonce'])

@app.route('/google/auth/')
def google_auth():
    token = oauth.google.authorize_access_token()
    user = oauth.google.parse_id_token(token, nonce=session['nonce'])
    session['user'] = user
    print(" Google User ", user)
    return redirect('/')


@app.route('/api/testcomplete/', methods=['POST'])
def testcomplete():
    data = request.get_json()
    if not data or 'messages' not in data:
        return jsonify({"error": "Bad request"}), 400
    messages = data.get('messages')
    return jsonify(messages)


@app.route('/test/')
def test():
    print("Hello World")
    return "Hello World"


@app.route('/api/complete/', methods=['POST'])
def complete():
    if 'user_id' not in session:  # Assuming 'user_id' is set in session upon successful login
        return redirect(url_for('login'))  # Redirect to login if user not authenticated

    data = request.get_json()
    if not data or 'messages' not in data:
        return jsonify({"error": "Bad request"}), 400
    messages = data.get('messages')
    return jsonify(messages)
