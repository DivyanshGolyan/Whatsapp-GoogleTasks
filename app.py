import sqlite3
import uuid
import logging
import os
from flask import Flask, request, session, url_for
from flask_session import Session
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from dotenv import load_dotenv
from twilio.twiml.messaging_response import MessagingResponse

load_dotenv()

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
SCOPES = ['https://www.googleapis.com/auth/tasks']

# Google OAuth 2.0 settings
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")


class DBHandler:
    def __init__(self):
        self.conn = sqlite3.connect('tokens.db', check_same_thread=False)
        self.c = self.conn.cursor()
        self.initialize_tables()

    def initialize_tables(self):
        self.c.execute('''
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

        self.c.execute('''
            CREATE TABLE IF NOT EXISTS sender_state_mapping(
                sender TEXT PRIMARY KEY,
                state TEXT
            )
        ''')

    def fetch_token(self, query, values):
        self.c.execute(query, values)
        return self.c.fetchone()

    def insert_data(self, query, values):
        self.c.execute(query, values)
        self.conn.commit()


class AuthHandler:
    def __init__(self, db_handler):
        self.db = db_handler

    def create_state_value(self):
        return str(uuid.uuid4())

    def setup_google_auth(self, state):
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

        return flow

    def handle_google_auth(self, sender, flow):
        authorization_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent',
            login_hint=sender)
        return authorization_url


app = Flask(__name__)
app.secret_key = 'your_secret_key'
Session(app)
db = DBHandler()
auth = AuthHandler(db)


@app.route("/bot", methods=['POST'])
def bot():
    incoming_msg = request.values.get('Body', '')
    sender = request.values.get('WaId', '')
    logging.info(f'Received message from: {sender} with body: {incoming_msg}')

    resp = MessagingResponse()
    msg = resp.message()

    result = db.fetch_token(
        'SELECT token, refresh_token, client_id, client_secret, token_uri FROM tokens WHERE sender = ?', (sender,))

    state = ''
    if result is None:
        state_row = db.fetch_token(
            'SELECT state FROM sender_state_mapping WHERE sender = ?', (sender,))
        state = state_row[0] if state_row else auth.create_state_value()

        db.insert_data(
            '''INSERT OR REPLACE INTO sender_state_mapping(sender, state) VALUES (?, ?)''', (sender, state))

        logging.info(f"New state '{state}' created for sender '{sender}'.")
        logging.info(
            "Access token doesn't exist, redirecting the user to authenticate.")

        flow = auth.setup_google_auth(state)
        authorization_url = auth.handle_google_auth(sender, flow)

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
             'token_uri': token_uri})
        service = build('tasks', 'v1', credentials=credentials)
        task = service.tasks().insert(tasklist='@default',
                                      body={'title': incoming_msg}).execute()
        msg.body(f"Task created: {task['title']}")

    return str(resp)


@app.route('/google-auth')
def google_auth():
    state = request.args.get('state', None)

    sender_row = db.fetch_token(
        'SELECT sender FROM sender_state_mapping WHERE state = ?', (state,))
    if sender_row:
        sender = sender_row[0]
        flow = auth.setup_google_auth(state)

        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)

        credentials = flow.credentials
        credentials_dict = credentials_to_dict(credentials)
        refresh_token = credentials_dict.get('_refresh_token')

        # If the refresh token is None, fetch the previous one from the database
        if not refresh_token:
            result = db.fetch_token(
                'SELECT refresh_token FROM tokens WHERE sender = ?', (sender,))
            if result:
                refresh_token = result[0]

        logging.info("Before INSERT operation on tokens table.")
        db.insert_data('''
            INSERT OR REPLACE INTO tokens(sender, token, refresh_token, token_uri, client_id, client_secret, expiry)
            VALUES (?, ?, ?, ?, ?, ?, ?)''',
                       (sender,
                        credentials_dict['token'],
                        refresh_token,
                        credentials_dict['_token_uri'],
                        credentials_dict['_client_id'],
                        credentials_dict['_client_secret'],
                        credentials_dict['expiry']))

        logging.info("After INSERT operation on tokens table.")

        if sender_row is not None:
            db.insert_data(
                'DELETE FROM sender_state_mapping WHERE sender = ?', (sender,))

        logging.info(f"State mapping for sender '{sender}' deleted.")

        return 'Google authentication succeeded!'
    else:
        return 'Invalid state parameter. Google authentication failed!', 400


def credentials_to_dict(credentials):
    return {key: vars(credentials)[key] for key in vars(credentials)}


if __name__ == '__main__':
    app.run(debug=True, port=5002, ssl_context='adhoc')
