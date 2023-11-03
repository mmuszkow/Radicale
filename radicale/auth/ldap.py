# This file is part of Radicale Server - Calendar Server
# Copyright © 2008 Nicolas Kandel
# Copyright © 2008 Pascal Halter
# Copyright © 2008-2017 Guillaume Ayoub
# Copyright © 2017-2018 Unrud<unrud@outlook.com>
# Copyright © 2019 Marco Fleckinger<marco.fleckinger@gmail.com>
# Copyright © 2023 Maciek Muszkowski
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Radicale.  If not, see <http://www.gnu.org/licenses/>.

import re

from radicale import auth
from datetime import datetime
from hashlib import sha256
from os import urandom

class Auth(auth.BaseAuth):
    def __init__(self, configuration):
        super().__init__(configuration)

        try:
            import ldap3
        except ImportError as e:
            raise RuntimeError(
               "LDAP authentication requires the ldap3 module") from e

        self.ldap3 = ldap3
        self.server_uri = configuration.get("auth", "ldap_server_uri")
        self.bind_dn_pattern = configuration.get("auth", "ldap_bind_dn")
        self.cache_time = int(configuration.get("auth", "ldap_cache_time"))
        self.cleanup_interval = int(configuration.get("auth", "ldap_cache_cleanup_time"))

        # not to bomb LDAP too much
        self.cache = {}
        self.nonce = urandom(32)
        self.last_cleanup = datetime.now()

    def login(self, login, password):
        """
            Validate credentials.
            Simply try to sign in into ldap server with given
            credentials using dn from configuration
        """

        # generate salted password hash
        digest = sha256()
        digest.update(login.encode('utf-8'))
        digest.update(self.nonce)
        digest.update(password.encode('utf-8'))
        login_hash = digest.hexdigest()

        # check first if hash is in cache
        now = datetime.now()
        if login in self.cache:
            cache_hash, last_login = self.cache[login]
            if cache_hash == login_hash:
                delta_login = (now - last_login).total_seconds()
                if delta_login < self.cache_time:
                    return login
            
                del self.cache[login]

        # recreate cache to remove old entries (this can be costful)
        if (now - self.last_cleanup).total_seconds() > self.cleanup_interval:
            self.cache = { u: (h, t) for u, (h, t) in self.cache.items()
                           if (now - t).total_seconds() < self.cache_time }
            self.last_cleanup = now

        def substitute(match_object):
            """
                substitutes:
                 * %d by the domain part
                 * %n by the local part
                 * %u by the whole given user name
            """
            patterns = {
                'd': '.+?@(.+)',
                'n': '(.+?)@.+',
                'u': '(.+)'
            }
            key = match_object.group(1)
            if key not in patterns:
                raise RuntimeError("'%s' is an unknown variable" % key)
            pattern = patterns[key]
            m = re.match(pattern, login)
            if m is None:
                return ''
            return m.group(1)

        # First get the distinguished name to connect with to the server
        bind_dn = re.sub('%([a-z])', substitute, self.bind_dn_pattern)

        # Try to connect to the LDAP server by using
        #   * the distinguished name
        #   * the given password
        try:
            server = self.ldap3.Server(self.server_uri)
            conn = self.ldap3.Connection(server, bind_dn, password=password)
            if conn.bind():
                self.cache[login] = (login_hash, now)
                conn.unbind()
                return login
        except self.ldap3.core.exceptions.LDAPSocketOpenError:
            raise RuntimeError("unable to reach ldap server")
        except Exception:
            pass
        return ""

