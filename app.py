from functools import wraps
import json
import logging
import os
from datetime import datetime as dt
from typing import Union
from dotenv import load_dotenv, find_dotenv
from flask import Flask, request, send_file, abort
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = os.environ['secret_key']

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=os.environ['client_id'],
    client_secret=os.environ['client_secret'],
    api_base_url=os.environ['api_base_url'],
    access_token_url='https://dev-94xpl1w2.us.auth0.com/oauth/token',
    authorize_url='https://dev-94xpl1w2.us.auth0.com/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)


@app.route('/callback')
def callback_handling():
    # Handles response from token endpoint
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()
    # Store the user information in flask session.
    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }

    return redirect('/dashboard')


@app.route('/login')
def login():
    return auth0.authorize_redirect(
        # redirect_uri='http://localhost:8080/callback'
        redirect_uri='https://flask-auth0-sample-oqhc36hika-de.a.run.app/callback'
    )


def requires_auth(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    if 'profile' not in session:
      # Redirect to Login page here
      return redirect('/')
    return f(*args, **kwargs)

  return decorated


@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session['profile'],
                           userinfo_pretty=json.dumps(session['jwt_payload'], indent=4),
                           )


@app.route('/logout')
def logout():
    # Clear session stored data
    session.clear()
    # Redirect user to logout endpoint
    params = {'returnTo': url_for('home', _external=True, _scheme='https',), 'client_id': os.environ['client_id']}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))


@app.route('/')
def home():
    return render_template('home.html')


if __name__ == "__main__":
    app.run(debug=False, threaded=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
