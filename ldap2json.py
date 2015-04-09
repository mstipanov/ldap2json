#!/usr/bin/python

'''ldap2json acts as a proxy between HTTP GET requests and an LDAP
directory.  Results are returned to the caller using JSON.'''

import os
import sys
import argparse
import ldap
import configobj
import pprint
import urllib
import json
import memcache
import logging
import itertools
import time

from bottle import route,run,request,response,HTTPError
import ldap.modlist as modlist


directory = None
cache = None
config = None


def normalize(kwargs):
    for k, v in kwargs.items():
        if isinstance(v, list) and len(v) == 1:
            kwargs[k] = v[0]
    return kwargs


class LDAPDirectory(object):
    '''A simple wrapper for LDAP connections that exposes a simplified
    search interface.  At the moment this class only supports anonymous
    binds.'''

    def __init__(self, uris,
                 basedn='',
                 scope=ldap.SCOPE_SUBTREE,
                 debug=False,
                 maxwait=120,
                 username=None,
                 password=None,
                 ):

        self.uris = itertools.cycle(uris)
        self.maxwait = maxwait

        self.basedn = basedn
        self.scope = scope
        self.debug = debug
        self.username = username
        self.password = password

        self.connect()

    def connect(self):
        uri = self.uris.next()
        logging.info('Connecting to %s' % uri)
        self.dir = ldap.initialize(uri)

    def signup(self, kwargs):
        if not kwargs:
            return None

        if "dn" not in kwargs:
            return None

        dn = kwargs.pop("dn")
        if not dn:
            return None

        try:
            if 'uidNumber' not in kwargs:
                msxuid = 1000
                data = self.search(**{'uidNumber': '*'})
                for user in data:
                    msxuid = max(msxuid, int(user[1]["uidNumber"][0]))

                self.dir.simple_bind_s(self.username, self.password)

                kwargs["uidNumber"] = [str(msxuid + 1)]

            # Convert our dict to nice syntax for the add-function using modlist-module
            ldif = modlist.addModlist(kwargs)
            # Do the actual synchronous add-operation to the ldapserver
            self.dir.add_s(dn, ldif)
            # Its nice to the server to disconnect and free resources when done
            self.dir.unbind_s()
            return ldif
        except ldap.LDAPError, e:
            logging.error("Can't connect to LDAP server")
            print e

        return None

    def login(self, **kwargs):
        if not kwargs:
            return None

        if "password" not in kwargs:
            return None

        password = kwargs.pop("password")

        res = self.search(**kwargs)
        if not res:
            return None
        username = res[0][0]

        try:
            self.dir.simple_bind_s(username, password)
            return res[0]
        except ldap.LDAPError, e:
            logging.error("Can't connect to LDAP server!")
            print e

        return None

    def search(self, **kwargs):
        '''Turns kwargs into an LDAP search filter, executes the search,
        and returns the results.  The keys in kwargs are ANDed together;
        only results meeting *all* criteria will be returned.
        
        If the connection to the LDAP server has been lost, search will try
        to reconnect with exponential backoff.  The wait time between
        reconnection attempts will grow no large than self.maxwait.'''

        if not kwargs:
            kwargs = {'objectclass': '*'}

        filter = self.build_filter(**kwargs)
        tries = 0

        while True:
            tries += 1

            try:
                res = self.dir.search_s(
                    self.basedn,
                    self.scope,
                    filterstr=filter)
                return res
            except ldap.SERVER_DOWN:
                interval = max(1, min(self.maxwait, (tries - 1) * 2))
                logging.error('Lost connection to LDAP server: '
                              'reconnecting in %d seconds.' % interval)
                time.sleep(interval)
                self.connect()

    def build_filter(self, **kwargs):
        '''Transform a dictionary into an LDAP search filter.'''

        filter = []
        for k, v in sorted(kwargs.items(), key=lambda x: x[0]):
            filter.append('(%s=%s)' % (k, v))

        if len(filter) > 1:
            return '(&%s)' % ''.join(filter)
        else:
            return filter[0]


class Cache(object):
    '''This is a very simple wrapper over memcache.Client that
    lets us specify a default lifetime for cache objects.'''

    def __init__(self, servers, lifetime=600):
        self.lifetime = lifetime
        self.cache = memcache.Client(servers)

    def set(self, k, v):
        self.cache.set(k, v, time=self.lifetime)

    def get(self, k):
        return self.cache.get(k)


@route('/ldap/login')
def ldaplogin():
    '''This method is where web clients interact with ldap2json.  Any
    request parameters are turned into an LDAP filter, and results are JSON
    encoded and returned to the caller.'''

    global directory
    global cache
    global config

    callback = None

    # This supports JSONP requests, which require that the JSON
    # data be wrapped in a function call specified by the
    # callback parameter.
    if 'callback' in request.GET:
        callback = request.GET['callback']
        del request.GET['callback']

    # jquery adds this to JSONP requests to prevent caching.
    if '_' in request.GET:
        del request.GET['_']

    key = urllib.quote('/ldap/%s/%s' % (
        directory.basedn,
        request.urlparts.query,
    ))

    res = cache.get(key)

    if res is None:
        res = directory.login(**request.GET)
        cache.set(key, res)

    if not res:
        raise HTTPError(401)

    response.content_type = 'application/json'
    text = json.dumps(res, indent=2)

    # wrap JSON data in function call for JSON responses.
    if callback:
        text = '%s(%s)' % (callback, text)

    return text


@route('/ldap/signup')
def ldapsignup():
    '''This method is where web clients interact with ldap2json.  Any
    request parameters are turned into an LDAP filter, and results are JSON
    encoded and returned to the caller.'''

    global directory
    global config

    callback = None

    # This supports JSONP requests, which require that the JSON
    # data be wrapped in a function call specified by the
    # callback parameter.
    if 'callback' in request.GET:
        callback = request.GET['callback']
        del request.GET['callback']

    # jquery adds this to JSONP requests to prevent caching.
    if '_' in request.GET:
        del request.GET['_']

    res = directory.signup(normalize(request.GET.dict))

    if not res:
        raise HTTPError(400)

    response.content_type = 'application/json'
    text = json.dumps(res, indent=2)

    # wrap JSON data in function call for JSON responses.
    if callback:
        text = '%s(%s)' % (callback, text)

    return text


@route('/ldap')
def ldapsearch():
    '''This method is where web clients interact with ldap2json.  Any
    request parameters are turned into an LDAP filter, and results are JSON
    encoded and returned to the caller.'''

    global directory
    global cache
    global config

    callback = None

    # This supports JSONP requests, which require that the JSON
    # data be wrapped in a function call specified by the
    # callback parameter.
    if 'callback' in request.GET:
        callback = request.GET['callback']
        del request.GET['callback']

    # jquery adds this to JSONP requests to prevent caching.
    if '_' in request.GET:
        del request.GET['_']

    key = urllib.quote('/ldap/%s/%s' % (
        directory.basedn,
        request.urlparts.query,
    ))

    res = cache.get(key)

    if res is None:
        res = directory.search(**request.GET)
        cache.set(key, res)

    if not res:
        raise HTTPError(404)

    response.content_type = 'application/json'
    text = json.dumps(res, indent=2)

    # wrap JSON data in function call for JSON responses.
    if callback:
        text = '%s(%s)' % (callback, text)

    return text


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('-d', '--debug', action='store_true',
                   default=None)
    p.add_argument('-f', '--config',
                   default='ldap2json.conf')
    return p.parse_args()


def init_memcache():
    global config
    global cache

    # Extract server list from config file.
    servers = config.get('memcache', {}).get(
        'servers', '127.0.0.1:11211')
    lifetime = config.get('memcache', {}).get('lifetime', 600)

    # Make sure we have a Python list of servers.
    if isinstance(servers, (str, unicode)):
        servers = [servers]

    # Make sure we have an integer.
    lifetime = int(lifetime)

    assert lifetime > 0
    assert isinstance(servers, list)

    if config.get('debug'):
        print >> sys.stderr, 'using memcache servers: %s' % (
            servers)

    cache = Cache(servers, lifetime=lifetime)


def init_directory():
    global directory
    global config

    uris = config.get('ldap', {}).get('uris', ['ldap://localhost'])
    basedn = config.get('ldap', {}).get('basedn', '')
    username = config.get('ldap', {}).get('username', '')
    password = config.get('ldap', {}).get('password', '')

    # Make sure we have a list of uris.
    if isinstance(uris, (str, unicode)):
        uris = [uris]

    directory = LDAPDirectory(
        uris,
        basedn=basedn,
        debug=config.get('debug'),
        username=username,
        password=password,
    )


def init_logging():
    logging.basicConfig(level=logging.INFO,
                        datefmt='%Y-%m-%d %H:%M:%S',
                        format='%(asctime)s %(name)s [%(levelname)s]: %(message)s',
                        )


def main():
    global directory
    global cache
    global config

    opts = parse_args()

    config = configobj.ConfigObj(opts.config)

    # Only override config file "debug" setting if --debug
    # was explicitly passed on the command line.
    if opts.debug is not None:
        config['debug'] = opts.debug

    if config.get('debug'):
        print >> sys.stderr, 'CONFIG:', pprint.pformat(dict(config))

    init_logging()
    init_memcache()
    init_directory()

    run(
        host=config.get('host', '127.0.0.1'),
        port=config.get('port', 8080),
        reloader=config.get('debug', False),
    )


if __name__ == '__main__':
    main()

