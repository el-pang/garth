# %% Imports
import getpass
import importlib
import azure.identity
from azure.keyvault.secrets import SecretClient
import garth
import requests
import random
import datetime
import urllib.parse
import hashlib
import hmac
import base64

importlib.reload(garth)

# %% Constants
KEY_VAULT_URL = "https://healthhubvault.vault.azure.net/"
GARMIN_USERNAME_SECRET_NAME = "GarminUsername"
GARMIN_PASSWORD_SECRET_NAME = "GarminPassword"
username = input('Enter your username:')
password = getpass.getpass('Enter your password:')

# %% Fetch Garmin credentials from Azure Key Vault using Az PS credentials
credential = azure.identity.AzurePowerShellCredential()
key_vault_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)
username = key_vault_client.get_secret(GARMIN_USERNAME_SECRET_NAME).value
password = key_vault_client.get_secret(GARMIN_PASSWORD_SECRET_NAME).value

# %% Log into Garmin via garth (Should show a debug message)
print('Logging into Garmin...')
tokens = garth.login(username, password)
print('Log in complete.')

# %% Try to replicate Garmin login
session = requests.Session()
session.headers.update({'User-Agent': 'android.app.garmin.connectmobile'})
get_cookies_response = session.get('https://sso.garmin.com/sso/embed',
                                   params={'id': 'gauth-width',
                                           'embedWidget': 'true',
                                           'gauthHost': 'https://sso.garmin.com/sso'})
print(get_cookies_response.status_code)

session.headers.update({'referer': get_cookies_response.url})
get_csrf_token_response = session.get('https://sso.garmin.com/sso/signin',
                                      params={'id': 'gauth-width',
                                              'embedWidget': 'true',
                                              'gauthHost': 'https://sso.garmin.com/sso',
                                              'service': 'https://sso.garmin.com/sso/embed',
                                              'source': 'https://sso.garmin.com/sso/embed',
                                              'redirectAfterAccountLoginUrl': 'https://sso.garmin.com/sso/embed',
                                              'redirectAfterAccountCreationUrl': 'https://sso.garmin.com/sso/embed'})
print(get_csrf_token_response.status_code)
csrf_token_search_string = 'name="_csrf" value="'
csrf_token = get_csrf_token_response.text[get_csrf_token_response.text.find(csrf_token_search_string) + len(csrf_token_search_string):]
csrf_token = csrf_token[:csrf_token.find('"')]

session.headers.update({'referer': get_csrf_token_response.url})
submit_login_response = session.post('https://sso.garmin.com/sso/signin',
                                     params={'id': 'gauth-width',
                                             'embedWidget': 'true',
                                             'gauthHost': 'https://sso.garmin.com/sso',
                                             'service': 'https://sso.garmin.com/sso/embed',
                                             'source': 'https://sso.garmin.com/sso/embed',
                                             'redirectAfterAccountLoginUrl': 'https://sso.garmin.com/sso/embed',
                                             'redirectAfterAccountCreationUrl': 'https://sso.garmin.com/sso/embed'},
                                     data={'username': username,
                                           'password': password,
                                           'embed': 'true',
                                           '_csrf': csrf_token})
print(submit_login_response.status_code)

service_ticket_search_string = 'embed?ticket='
service_ticket = submit_login_response.text[submit_login_response.text.find(service_ticket_search_string) + len(service_ticket_search_string):]
service_ticket = service_ticket[:service_ticket.find('"')]

# %% Deconstruct OAuth1 auth
consumer_key = getpass.getpass('Enter the consumer key:')
consumer_secret = getpass.getpass('Enter the consumer secret:')

oauth_nonce = str(random.randint(1000000000, 9999999999))
oauth_timestamp = str(datetime.datetime.now().timestamp()).split('.')[0]

method = "GET"
url = "https://connectapi.garmin.com/oauth-service/oauth/preauthorized"
query_parameters = {
    'ticket': service_ticket,
    'login-url': 'https://sso.garmin.com/sso/embed',
    'accepts-mfa-tokens': 'true'
}
for key in query_parameters.keys():
    query_parameters[key] = urllib.parse.quote(query_parameters[key], safe='')

oauth_parameters = {
    'oauth_nonce': oauth_nonce,
    'oauth_timestamp': oauth_timestamp,
    'oauth_consumer_key': consumer_key,
    'oauth_signature_method': 'HMAC-SHA1',
    'oauth_version': '1.0',
}

parameters = {**query_parameters, **oauth_parameters}

signing_key = f"{urllib.parse.quote(consumer_secret, safe='')}&"
base_string = f"{method}&{urllib.parse.quote(url, safe='')}&{urllib.parse.quote('&'.join(sorted([f'{k}={v}' for k, v in parameters.items()])), safe='')}"

hashed = hmac.new(
    signing_key.encode('utf-8'),
    base_string.encode('utf-8'),
    hashlib.sha1
)
oauth_signature = base64.b64encode(hashed.digest()).decode()
oauth_parameters['oauth_signature'] = oauth_signature

# %%
oauth_signature

# %%

session = requests.Session()
session.headers.update({'User-Agent': 'com.garmin.android.apps.connectmobile'})
session.headers.update({'Authorization': f'OAuth ' + ', '.join([f'{k}="{urllib.parse.quote(v, safe="")}"' for k, v in oauth_parameters.items()])})

full_url = f'{url}?{"&".join([f"{k}={v}" for k, v in query_parameters.items()])}'
get_oauth1_token_response = session.get(full_url)

print(get_oauth1_token_response.status_code)
# %%
f'{url}?{"&".join([f"{k}={v}" for k, v in query_parameters.items()])}'

# %%
base_string
# %% Get heart rate zones 
garth.connectapi('/biometric-service/heartRateZones')
