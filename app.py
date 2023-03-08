# from flask import Flask, redirect, url_for, session
# import requests
# from authlib.integrations.flask_client import OAuth
# from google.oauth2.credentials import Credentials

# app = Flask(__name__)
# app.secret_key = 'your_secret_key'
# oauth = OAuth(app)

# from authlib.jose import jwk, JsonWebKey

# # Get the Google OAuth provider's metadata
# google_metadata_url = 'https://accounts.google.com/.well-known/openid-configuration'
# google_metadata = requests.get(google_metadata_url).json()

# # Update the issuer URL in the metadata
# google_metadata['issuer'] = 'https://accounts.google.com'

# google = oauth.register(
#     name='google',
#     client_id='',
#     client_secret='',
#     access_token_url='https://accounts.google.com/o/oauth2/token',
#     access_token_params=None,
#     authorize_url='https://accounts.google.com/o/oauth2/auth',
#     authorize_params=None,
#     api_base_url='https://www.googleapis.com/oauth2/v1/',
#     userinfo_endpoint='http://openidconnect.googleapis.com/v1/userinfo',
#     client_kwargs={'scope': 'openid email'},
#     server_metadata_url=google_metadata_url,
#     client_metadata=google_metadata
# )

# @app.route('/')
# def home():
#     if 'google_token' in session:
#         credentials = Credentials.from_authorized_user_info(session['google_token'])
#         return f'Access Token: {credentials.token}'
#     else:
#         return redirect(url_for('google_login'))

# @app.route('/login/google')
# def google_login():
#     redirect_uri = url_for('google_authorize', _external=True)
#     return google.authorize_redirect(redirect_uri)

# @app.route('/authorize/google')
# def google_authorize():
#     token = google.authorize_access_token()
#     session['google_token'] = token
#     return redirect(url_for('home'))

# if __name__ == '__main__':
#     app.run(debug=True)
# from flask import Flask, redirect, url_for, session,request
# from authlib.integrations.flask_client import OAuth
# from authlib.jose import jwk, JsonWebKey
# import requests



# Get the Google OAuth provider's metadata
# google_metadata_url = 'https://accounts.google.com/.well-known/openid-configuration'
# google_metadata = requests.get(google_metadata_url).json()

# # Check if "jwks_uri" is already present in the metadata
# if 'jwks_uri' not in google_metadata:
#     # Add "jwks_uri" to the metadata
#     jwks_uri = 'https://www.googleapis.com/oauth2/v3/certs'
#     google_metadata['jwks_uri'] = jwks_uri



"""""""""""""""""""""""""""""""""""""""""'"""

# app = Flask(__name__)
# app.secret_key = 'secret'

# oauth = OAuth(app)

# google_metadata_url = 'https://accounts.google.com/.well-known/openid-configuration'
# google_metadata = requests.get(google_metadata_url).json()

# # Check if "jwks_uri" is already present in the metadata
# if 'jwks_uri' not in google_metadata:
#     # Retrieve the JWKS URI from Google's discovery document
#     jwks_uri = google_metadata['jwks_uri']
#     # Fetch the JWKS from the JWKS URI
#     jwks = requests.get(jwks_uri).json()
#     # Convert the JWKS to a JWK Set
#     jwk_set = JsonWebKey.import_key_set(jwks)
#     # Add the JWK Set to the metadata
#     google_metadata['jwks_uri'] = jwk_set
    
# google = oauth.register(
#     name='google',
#     client_id='858827062782-d63ot34op57kstc98hpfiid5581l0q20.apps.googleusercontent.com',
#     client_secret='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',
#     access_token_url='https://accounts.google.com/o/oauth2/token',
#     access_token_params=None,
#     authorize_url='https://accounts.google.com/o/oauth2/auth',
#     authorize_params=None,
#     api_base_url='https://www.googleapis.com/oauth2/v1/',
#     userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
#     client_kwargs={'scope': "openid email profile"},
#     server_metadata_url=google_metadata_url,
#     client_metadata=google_metadata,
#     issuer='https://accounts.google.com'
# )

# @app.route('/')
# def login():
#     redirect_uri = url_for('authorize', _external=True)
#     return google.authorize_redirect(redirect_uri)

# @app.route('/authorize')
# def authorize():
#     token = google.authorize_access_token()
#     if token is None:
#         return 'Access denied: reason=%s error=%s' % (
#             request.args['error_reason'],
#             request.args['error_description']
#         )
#     session['token'] = token
#     user_info = google.parse_id_token(token)
#     return 'Logged in as email=%s name=%s' % (
#         user_info['email'], user_info['name']
#     )

# if __name__ == '__main__':
#      app.run(debug=True)
     
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from flask import Flask, render_template, url_for, redirect,session
from authlib.integrations.flask_client import OAuth
import os
import secrets
import hashlib


 
app = Flask(__name__)
app.secret_key = 'klsownxdsalkdxnsalkslki'
 
'''
    Set SERVER_NAME to localhost as twitter callback
    url does not accept 127.0.0.1
    Tip : set callback origin(site) for facebook and twitter
    as http://domain.com (or use your domain name) as this provider
    don't accept 127.0.0.1 / localhost
'''
 
app.config['SERVER_NAME'] = 'localhost:5000'
oauth = OAuth(app)
 
# @app.route('/')
# def index():
#     return render_template('index.html')



 
@app.route('/google/')
def google():
   
    # Google Oauth Config
    # Get client_id and client_secret from environment variables
    # For developement purpose you can directly put it
    # here inside double quotes
    GOOGLE_CLIENT_ID = "858827062782-d63ot34op57kstc98hpfiid5581l0q20.apps.googleusercontent.com"
    GOOGLE_CLIENT_SECRET ="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"
    nonce = secrets.token_urlsafe(16)
    session['nonce'] = nonce

     
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
    return oauth.google.authorize_redirect(redirect_uri)
 
@app.route('/google/auth/')
def google_auth():
    token = oauth.google.authorize_access_token()
    print(token)
    # generate a random URL-safe string of length 16
    user = oauth.google.parse_id_token(token, nonce=session['nonce'])
    print(" Google User ", user)
    return redirect('/')
 
if __name__ == "__main__":
    app.run(debug=True)