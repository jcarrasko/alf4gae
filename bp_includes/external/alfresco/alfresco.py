#!/usr/bin/env python
##
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

__author__ = 'Jose Carrasco'
__website__ = 'http://www.asdelivered.com'

try: import simplejson as json
except ImportError: import json
import oauth_client as oauth2
import logging

# Alfresco OAuth Implementation
class AlfrescoAuth(object):
    
    def __init__(self, alfresco_server, alfresco_client_id, alfresco_client_secret, alfresco_redirect_uri, scope, alfresco_network):

        # load alfresco shizzle from config.py
        self.oauth_settings = {
            'client_id': alfresco_client_id,
            'client_secret': alfresco_client_secret,
            'access_token_url': 'https://api.%s/auth/oauth/versions/2/token' % alfresco_server,
            'authorization_url': 'https://api.%s/auth/oauth/versions/2/authorize' % alfresco_server,
            'redirect_url': '%s' % alfresco_redirect_uri,
            'scope': '%s' % scope,
            'response_type': 'code'
        }
        
        self.alfresco_network=alfresco_network

    # get our auth url and return to login handler
    def get_authorize_url(self):
        oauth_client = oauth2.Client( 
            self.oauth_settings['client_id'], 
            self.oauth_settings['client_secret'], 
            self.oauth_settings['authorization_url'] ,
            self.oauth_settings['response_type']
        )
        
        authorization_url = oauth_client.authorization_url( 
            redirect_uri=self.oauth_settings['redirect_url'],  
            params={'scope': self.oauth_settings['scope'],'response_type':self.oauth_settings['response_type']}
        )

        return authorization_url

    def get_access_token(self, code):
        oauth_client = oauth2.Client(
            self.oauth_settings['client_id'],
            self.oauth_settings['client_secret'],
            self.oauth_settings['access_token_url']
        )
        
        data = oauth_client.access_token(code, self.oauth_settings['redirect_url'])
        
        access_token = data.get('access_token')

        return access_token


    def get_user_info(self, access_token):

        oauth_client = oauth2.Client(
            self.oauth_settings['client_id'],
            self.oauth_settings['client_secret'],
            self.oauth_settings['access_token_url']
        )
        # Make the request for retrieve the user data
        # Notice that the Network is gived by configuration
        (headers, body) = oauth_client.request(
            'https://api.alfresco.com/%s/public/alfresco/versions/1/people/-me-' %self.alfresco_network,
            access_token=access_token,
            token_param='access_token'
        )
        return json.loads(body)