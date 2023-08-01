import sqlite3
from flask import Flask, request, session, url_for
from flask_session import Session
from twilio.twiml.messaging_response import MessagingResponse
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from dotenv import load_dotenv
import uuid
import logging
import os


load_dotenv()

# Setting up SQLite database
conn = sqlite3.connect('tokens.db', check_same_thread=False)
c = conn.cursor()
c.execute('''
    CREATE TABLE IF NOT EXISTS tokens(
        sender TEXT PRIMARY KEY,
        token TEXT NOT NULL,
        refresh_token TEXT,
        id_token TEXT,
        token_uri TEXT NOT NULL,
        client_id TEXT NOT NULL,
        client_secret TEXT NOT NULL,
        expiry TEXT
    );
''')
c.execute('''
    CREATE TABLE IF NOT EXISTS sender_state_mapping(
        sender TEXT PRIMARY KEY,
        state TEXT
    )
''')


# Google OAuth 2.0 settings
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
SCOPES = ['https://www.googleapis.com/auth/tasks']

logging.basicConfig(level=logging.DEBUG,
                    format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
                    handlers=[logging.StreamHandler()])

# Flask settings
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Flask-Session
SESSION_TYPE = 'filesystem'
app.config.from_object(__name__)
Session(app)

# # Initialize session data
# if not session.get("tokens"):
#     session['tokens'] = {}
# session['state'] = None

mapping = {}
sender_to_state_mapping = {}
state_to_sender_mapping = {}


@app.route('/bot', methods=['POST'])
def bot():
    incoming_msg = request.values.get('Body', '')
    sender = request.values.get('WaId', '')
    logging.info(f'Received message from: {sender} with body: {incoming_msg}')

    resp = MessagingResponse()
    msg = resp.message()

    c.execute(
        'SELECT token, refresh_token, client_id, client_secret, token_uri FROM tokens WHERE sender = ?', (sender,))
    result = c.fetchone()

    def create_state_value():
        return str(uuid.uuid4())

    if result is None:
        c.execute(
            'SELECT state FROM sender_state_mapping WHERE sender = ?', (sender,))
        state_row = c.fetchone()
        state = state_row[0] if state_row else create_state_value()

        c.execute('''
            INSERT OR REPLACE INTO sender_state_mapping(sender, state)
            VALUES (?, ?)''', (sender, state))
        conn.commit()

        logging.info(f"New state '{state}' created for sender '{sender}'.")

        redirect_uri = url_for('google_auth', _external=True)
        logging.info(
            "Access token doesn't exist, redirecting the user to authenticate.")

        flow = Flow.from_client_config(
            client_config={
                'web': {
                    'client_id': GOOGLE_CLIENT_ID,
                    'client_secret': GOOGLE_CLIENT_SECRET,
                    'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                    'token_uri': 'https://accounts.google.com/o/oauth2/token'
                }
            },
            scopes=SCOPES,
            state=state  # Pass the state here
        )

        flow.redirect_uri = url_for('google_auth', _external=True)

        authorization_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent',
            login_hint=sender
        )

        logging.info(
            f"The current sender-state dictionary is: {sender_to_state_mapping}")
        state_to_sender_mapping[state] = sender
        logging.info(
            f"The updated state-sender dictionary is: {state_to_sender_mapping}")

        msg.body(
            f"Welcome! Please authenticate your Google account: {authorization_url}")
    else:
        logging.info("Access token exists for this sender. Creating task.")
        # fetch the token_uri from the result
        token, refresh_token, client_id, client_secret, token_uri = result
        credentials = Credentials.from_authorized_user_info(
            {'token': token,
             'refresh_token': refresh_token,
             'client_id': client_id,
             'client_secret': client_secret,
             'token_uri': token_uri})  # include the token_uri when creating the Credentials object
        service = build('tasks', 'v1', credentials=credentials)
        task = service.tasks().insert(tasklist='@default',
                                      body={'title': incoming_msg}).execute()
        msg.body(f"Task created: {task['title']}")

    return str(resp)


@app.route('/google-auth')
def google_auth():
    state = request.args.get('state', None)

    c.execute('SELECT sender FROM sender_state_mapping WHERE state = ?', (state,))
    sender_row = c.fetchone()
    if sender_row:
        sender = sender_row[0]
        flow = Flow.from_client_config(
            client_config={
                'web': {
                    'client_id': GOOGLE_CLIENT_ID,
                    'client_secret': GOOGLE_CLIENT_SECRET,
                    'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                    'token_uri': 'https://accounts.google.com/o/oauth2/token'
                }
            },
            scopes=SCOPES,
            state=state
        )

        flow.redirect_uri = url_for('google_auth', _external=True)

        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)

        credentials = flow.credentials
        credentials_dict = credentials_to_dict(credentials)
        refresh_token = credentials_dict.get('_refresh_token')

        # If the refresh token is None, fetch the previous one from the database
        if not refresh_token:
            c.execute(
                'SELECT refresh_token FROM tokens WHERE sender = ?', (sender,))
            result = c.fetchone()
            if result:
                refresh_token = result[0]

        logging.info("Before INSERT operation on tokens table.")
        c.execute('''
            INSERT OR REPLACE INTO tokens(sender, token, refresh_token, token_uri, client_id, client_secret, expiry)
            VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (sender,
                   credentials_dict['token'],
                   refresh_token,
                   credentials_dict['_token_uri'],
                   credentials_dict['_client_id'],
                   credentials_dict['_client_secret'],
                   credentials_dict['expiry']))
        conn.commit()

        logging.info("After INSEsRT operation on tokens table.")

        if sender_row is not None:
            c.execute(
                'DELETE FROM sender_state_mapping WHERE sender = ?', (sender,))
            conn.commit()

        logging.info(f"State mapping for sender '{sender}' deleted.")

        # Initialize session data
        if not session.get("tokens"):
            session['tokens'] = {}
        session['state'] = None

        logging.info(
            f'Saving credentials in session for state {state}: {session["tokens"]}')
        logging.info(
            f"The updated state-sender dictionary after authorization is: {state_to_sender_mapping}")

        return 'Google authentication succeeded!'
    else:
        return 'Invalid state parameter. Google authentication failed!', 400


def credentials_to_dict(credentials):
    cred_dict = {key: vars(credentials)[key] for key in vars(credentials)}
    print(cred_dict)  # Or use logging.info(cred_dict) if print does not work
    return cred_dict


if __name__ == '__main__':
    app.run(debug=True, port=5002, ssl_context='adhoc')
