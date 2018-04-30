'''
    Copyright (c) 2016, Salesforce.org
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of Salesforce.org nor the names of
      its contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
    FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
    BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
    ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
'''

from pytest import fixture
from getpass import getpass
from collections import namedtuple
from salesforce_requests_oauthlib import SalesforceOAuth2Session
from oauthlib.oauth2 import ServiceApplicationClient

test_settings_path = 'test_settings'


@fixture(scope='module')
def get_oauth_info():
    # Yes, it's annoying that you can't see these that are not
    # secret echoed.  But getpass() is smart about where it opens the input
    # stream, so I'm using it for now.
    oauth_client_id = getpass(
        'Enter full path to a test config file, or '
        'enter an oauth2 client identifier: '
    )

    config_fileh = None
    try:
        config_fileh = open(oauth_client_id, 'r')
    except IOError:
        client_secret = getpass('Enter oauth2 client secret: ')
        username1 = getpass('Enter first username: ')
        sandbox = getpass('Enter yes if sandbox: ') == 'yes'
        custom_domain = getpass(
            'Enter your test org custom domain prefix '
            '(the first part, before .my.salesforce.com): '
        )
        key_file = getpass(
            'Enter path to private key file for X509 certificate: '
        )
    else:
        lines = config_fileh.readlines()
        oauth_client_id = lines[0].rstrip()
        client_secret = lines[1].rstrip()
        username1 = lines[2].rstrip()
        sandbox = lines[3].rstrip() == 'yes'
        custom_domain = lines[4].rstrip()
        key_file = lines[5].rstrip()

    oauth_info = namedtuple('oauth_info', [
        'oauth_client_id',
        'client_secret',
        'username',
        'sandbox',
        'custom_domain',
        'key_file',
    ])
    return oauth_info(
        oauth_client_id,
        client_secret,
        username1,
        sandbox,
        custom_domain,
        key_file,
    )


def test_jwt_bearer_token_flow(get_oauth_info):
    client = ServiceApplicationClient(
        get_oauth_info.oauth_client_id,
        open(get_oauth_info.key_file).read(),
        get_oauth_info.username,
        get_oauth_info.oauth_client_id,
        audience='https://{0}.salesforce.com'.format(
            'test' if get_oauth_info.sandbox else 'login'
        )
    )
    session = SalesforceOAuth2Session(
        get_oauth_info.oauth_client_id,
        None,
        get_oauth_info.username,
        sandbox=get_oauth_info.sandbox,
        oauth2client=client
    )
    response = session.get('/services/data/vXX.X/sobjects/Contact').json()
    assert u'objectDescribe' in response


def test_password_flow(get_oauth_info):
    session = SalesforceOAuth2Session(
        get_oauth_info.oauth_client_id,
        get_oauth_info.client_secret,
        get_oauth_info.username,
        sandbox=get_oauth_info.sandbox,
        password=getpass('Enter password for {0}: '.format(
            get_oauth_info.username
        )),
        ignore_cached_refresh_tokens=True
    )
    response = session.get('/services/data/vXX.X/sobjects/Contact').json()
    assert u'objectDescribe' in response


def test_webbrowser_flow(get_oauth_info):
    session = SalesforceOAuth2Session(
        get_oauth_info.oauth_client_id,
        get_oauth_info.client_secret,
        get_oauth_info.username,
        sandbox=get_oauth_info.sandbox,
        ignore_cached_refresh_tokens=True
    )
    newest_version = session.get('/services/data/').json()[-1]
    response = session.get('/services/data/vXX.X/sobjects/Contact').json()
    assert u'objectDescribe' in response

    # Test that refresh token recovery works
    session = SalesforceOAuth2Session(
        get_oauth_info.oauth_client_id,
        get_oauth_info.client_secret,
        get_oauth_info.username,
        sandbox=get_oauth_info.sandbox
    )
    response = session.get('/services/data/v{0}/sobjects/Contact'.format(
        newest_version['version']
    )).json()
    assert u'objectDescribe' in response


def test_webbrowser_flow_with_custom_domain(get_oauth_info):
    session = SalesforceOAuth2Session(
        get_oauth_info.oauth_client_id,
        get_oauth_info.client_secret,
        get_oauth_info.username,
        sandbox=get_oauth_info.sandbox,
        ignore_cached_refresh_tokens=True,
        custom_domain=get_oauth_info.custom_domain
    )
    newest_version = session.get('/services/data/').json()[-1]
    response = session.get('/services/data/vXX.X/sobjects/Contact').json()
    assert u'objectDescribe' in response
