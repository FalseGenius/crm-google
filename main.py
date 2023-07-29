from fastapi import FastAPI, Depends, HTTPException, status, Query
from starlette.middleware.sessions import SessionMiddleware
from fastapi.security import OAuth2AuthorizationCodeBearer
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from starlette.responses import RedirectResponse
from starlette.requests import Request
from dotenv import dotenv_values
import uuid
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
import requests


SECRET_KEY = "your-secret-key"
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

oauth = OAuth()
config = dotenv_values(".env")
client_id = config['CLIENT_ID']
client_secret = config['CLIENT_SECRET']
redirect_uri = 'http://127.0.0.1:8000/auth/callback'

@app.get("/auth/login")
async def login(request: Request):
    state = str(uuid.uuid4())
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": state,
        "scope": "openid profile email",
        "access_type": "offline",
        "prompt": "consent"
    }
    url = "https://accounts.google.com/o/oauth2/v2/auth"
    response = RedirectResponse(url=url + "?" + "&".join([f"{key}={value}" for key, value in params.items()]))
    return response

from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token

@app.get("/auth/callback")
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
        id_token_str = response_data.get('id_token')

        if id_token_str:
            id_info = id_token.verify_oauth2_token(id_token_str, GoogleRequest(), client_id)
            return {"Message": "Google OAuth Callback successful", "access_token":access_token, "user_info": id_info}
        else:
            raise HTTPException(status_code=400, detail="Id token not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

