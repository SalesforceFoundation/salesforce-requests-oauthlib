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
from salesforce_requests_oauthlib import SalesforceOAuth2Session

test_settings_path = 'test_settings'


@fixture(scope='module')
def get_oauth_info():
    # Yes, it's annoying that you can't see the three of these that are not
    # secret echoed.  But getpass() is smart about where it opens the input
    # stream, so I'm using it for now.
    return (
        getpass('Enter oauth2 client identifier: '),
        getpass('Enter oauth2 client secret: '),
        getpass('Enter username: '),
        getpass('Enter yes if sandbox: ') == 'yes'
    )


@fixture(scope='module')
def setup_local_webserver_key(tmpdir_factory, request):
    settings_dir = tmpdir_factory.mktemp(test_settings_path)
    SalesforceOAuth2Session.generate_local_webserver_key(
        settings_path=str(settings_dir)
    )

    def fin():
        settings_dir.remove()
    request.addfinalizer(fin)

    return str(settings_dir)


def test_password_flow(get_oauth_info, setup_local_webserver_key):
    session = SalesforceOAuth2Session(
        get_oauth_info[0],
        get_oauth_info[1],
        get_oauth_info[2],
        sandbox=get_oauth_info[3],
        password=getpass('Enter password for {0}: '.format(
            get_oauth_info[2]
        )),
        ignore_cached_refresh_tokens=True
    )
    newest_version = session.get('/services/data/').json()[-1]
    response = session.get('/services/data/v{0}/sobjects/Contact'.format(
        newest_version['version']
    )).json()
    assert u'objectDescribe' in response


def test_webbrowser_flow(get_oauth_info, setup_local_webserver_key):
    session = SalesforceOAuth2Session(
        get_oauth_info[0],
        get_oauth_info[1],
        get_oauth_info[2],
        setup_local_webserver_key,
        get_oauth_info[3],
        ignore_cached_refresh_tokens=True
    )
    newest_version = session.get('/services/data/').json()[-1]
    response = session.get('/services/data/v{0}/sobjects/Contact'.format(
        newest_version['version']
    )).json()
    assert u'objectDescribe' in response

    # Test that refresh token recovery works
    session = SalesforceOAuth2Session(
        get_oauth_info[0],
        get_oauth_info[1],
        get_oauth_info[2],
        setup_local_webserver_key,
        get_oauth_info[3]
    )
    response = session.get('/services/data/v{0}/sobjects/Contact'.format(
        newest_version['version']
    )).json()
    assert u'objectDescribe' in response
