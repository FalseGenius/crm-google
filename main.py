from fastapi import FastAPI, Depends, HTTPException, status, Query
from starlette.middleware.sessions import SessionMiddleware
from fastapi.security import OAuth2AuthorizationCodeBearer
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from starlette.responses import RedirectResponse
from starlette.requests import Request
from starlette.middleware.cors import CORSMiddleware
from dotenv import dotenv_values
import uuid
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import requests
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime, timedelta
import json

from google.auth.exceptions import RefreshError


origins = ['http://127.0.0.1:8080']

SECRET_KEY = "your-secret-key"
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth = OAuth()
config = dotenv_values(".env")
client_id = config['CLIENT_ID']
client_secret = config['CLIENT_SECRET']
redirect_uri = 'http://127.0.0.1:8000/oauth/google/callback'

# mongoDBConfig = config['MONGO_DB_CONNECTION']
# client = MongoClient(mongoDBConfig)
# db = client['crmGoogleservices']
# emails_collection = db['emails']

oauth.register(
    name='google',
    client_id=client_id,
    client_secret=client_secret,
    access_token_url='https://oauth2.googleapis.com/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://www.googleapis.com/oauth2/v3/userinfo',
    client_kwargs={'scope': 'openid profile email https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/contacts.readonly'},
)


@app.get("/oauth/google/authorize")
async def login(request: Request):
    google = oauth.create_client('google')
    state = str(uuid.uuid4())
    request.session['state'] = state
    redirect_url = await google.authorize_redirect(request, redirect_uri, state=state)
    return redirect_url


@app.get("/oauth/google/callback")
async def google_callback(request: Request, code: str = Query(None), state: str = Query(None)):
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not found")

    data = {
        'code': code,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code'
    }

    try:
        response = requests.post('https://oauth2.googleapis.com/token', data=data)
        response_data = response.json()
        access_token = response_data.get('access_token')
        refresh_token = response_data.get('refresh_token')
        id_token_str = response_data.get('id_token')
        if id_token_str:
            id_info = id_token.verify_oauth2_token(id_token_str, GoogleRequest(), client_id)
            iat_tolerance = 5  # seconds
            current_time = datetime.utcnow()
            iat_claim_time = datetime.utcfromtimestamp(id_info.get('iat', 0))
            if iat_claim_time > current_time + timedelta(seconds=iat_tolerance):
                raise HTTPException(status_code=400, detail="Invalid token: Token used too early")
            request.session['user'] = {"access_token": access_token, "refresh_token": refresh_token, "user_info": id_info}
            redirect_url = f"http://127.0.0.1:8001/api/oauth/response?access_token={access_token}&id_info={json.dumps(id_info)}"
            return RedirectResponse(url=redirect_url)
        # else:
        #     raise HTTPException(status_code=400, detail="Id token not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.get('/gmail/messages')
async def list_gmail_messages(request: Request):
    page_token = request.query_params.get('page_token', '')
    page_size = int(request.query_params.get('page_size', 10))
    access_token = request.query_params.get('access_token', '')
    jwt_token = request.query_params.get('jwt_token', '')
    label = request.query_params.get('label', 'INBOX')
    print(label)
    try:
        creds = Credentials(access_token)
        if creds and not creds.valid:
            creds.refres(GoogleRequest())
        service = build('gmail', 'v1', credentials=creds)
        results = service.users().messages().list(userId='me', maxResults=page_size, pageToken=page_token, labelIds=[label]).execute()
        
        messages = results.get('messages', [])
        next_page_token = results.get('nextPageToken', '')

        message_summaries = []
        for message in messages:
            message_id = message['id']
            message_data = service.users().messages().get(userId='me', id=message_id, format='metadata', metadataHeaders=['subject', 'from', 'date']).execute()
            headers = message_data['payload']['headers']
            summary = {h['name'].lower(): h['value'] for h in headers if h['name'].lower() in ['subject', 'from', 'date']}
            summary['id'] = message_id
            message_summaries.append(summary)
        
        try:
            new_access_token = creds.token
            requests.post('http://127.0.0.1:8001/api/save_token', headers={'Authorization': f'Bearer {jwt_token}'}, json={'new_token': new_access_token})
        except Exception as e:
            print(f'Error saving new access token: {e}')

        return {"Message": "Gmail messages fetched successfully", "messages": message_summaries, "nextPageToken": next_page_token}
    except RefreshError:
        redirect_url = 'http://127.0.0.1:8000/oauth/google/authorize'
        return RedirectResponse(redirect_url, status_code=302)

@app.get('/gmail/messages/{message_id}')
async def get_gmail_message(request:Request, message_id:str):
    # user = request.session.get('user')
    # if not user:
    #     raise HTTPException(status_code=400, detail="User is not logged in")
    access_token = config['ACCESS_TOKEN']
    print(f"access_token here: {access_token}")
    try:
        cred = Credentials(access_token)
        service = build('gmail', 'v1', credentials=cred)
        result = service.users().messages().get(userId='me', id=message_id).execute()
        return {'Message':'Gmail messages fetched successfully', "message":result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get('/userinfo')
async def get_user_info(request:Request):
    # user = request.session.get('user')
    # if not user:
    #     raise HTTPException(status_code=400, detail="User is not logged in")
    # creds = Credentials(user['access_token'])
    access_token = config['ACCESS_TOKEN']
    creds = Credentials(access_token)
    service = build('people', 'v1', credentials=creds)
    userinfo = service.people().get(resourceName='people/me', personFields='names,emailAddresses,organizations,addresses').execute()

    return {"Message":"User info fetched successfully", "User info": userinfo}

@app.get('/contacts')
async def get_contacts(request:Request):
    # user = request.session.get('user')
    # if not user:
    #     raise HTTPException(status_code=400, detail="User not found")
    access_token = config['ACCESS_TOKEN']
    creds = Credentials(access_token)
    service = build('people', 'v1', credentials=creds)
    results = service.people().connections().list(resourceName='people/me', pageSize=10, personFields='names,emailAddresses,organizations,addresses').execute()
    connections = results.get('connections', [])

    return {"Message":"Contacts fetched successfully", "Contacts":connections}