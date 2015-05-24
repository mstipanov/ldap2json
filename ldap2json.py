#!/usr/bin/python

'''ldap2json acts as a proxy between HTTP GET requests and an LDAP
directory.  Results are returned to the caller using JSON.'''

import sys
import argparse
import pprint
import json
import logging
import itertools
import time
import hashlib
from base64 import *

import ldap
import configobj
import memcache
from bottle import route,get,post,run,request,response,HTTPError
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
            self.connect()
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

    def login(self, kwargs):
        if not kwargs:
            return None

        if "password" not in kwargs:
            return None

        password = kwargs.pop("password")

        res = self.search(kwargs)
        if not res:
            return None
        username = res[0][0]

        try:
            self.connect()
            self.dir.simple_bind_s(username, password)
            return res[0]
        except ldap.LDAPError, e:
            logging.error("Can't connect to LDAP server!")
            print e

        return None

    def add_attribute(self, dn, key, value):
        try:
            self.connect()
            self.dir.simple_bind_s(self.username, self.password)
            self.dir.modify_s(dn, [(ldap.MOD_ADD, key, value)])
            self.dir.unbind_s()
        except ldap.LDAPError, e:
            logging.error("Can't connect to LDAP server!")
            print e

    def update_attribute(self, dn, old, new):
        try:
            self.connect()
            ldif = modlist.modifyModlist(old, new)
            self.dir.simple_bind_s(self.username, self.password)
            self.dir.modify_s(dn, ldif)
            self.dir.unbind_s()
        except ldap.LDAPError, e:
            logging.error("Can't connect to LDAP server!")
            print e

    def search(self, kwargs):
        '''Turns kwargs into an LDAP search filter, executes the search,
        and returns the results.  The keys in kwargs are ANDed together;
        only results meeting *all* criteria will be returned.
        
        If the connection to the LDAP server has been lost, search will try
        to reconnect with exponential backoff.  The wait time between
        reconnection attempts will grow no large than self.maxwait.'''

        returnAttr = None
        if "returnAttr" in kwargs:
            returnAttr = kwargs.pop("returnAttr")

        if returnAttr:
            if not type(returnAttr) is list:
                returnAttr = [returnAttr]

        if not kwargs:
            kwargs = {'objectclass': '*'}

        filter = self.build_filter(**kwargs)
        tries = 0

        self.connect()
        while True:
            tries += 1

            try:
                res = self.dir.search_s(
                    self.basedn,
                    self.scope,
                    filterstr=filter,
                    attrlist=returnAttr)
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

    res = directory.login(normalize(request.GET.dict))

    if not res:
        raise HTTPError(401)

    response.content_type = 'application/json'
    text = json.dumps(res, indent=2, ensure_ascii=False)

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
    text = json.dumps(res, indent=2, ensure_ascii=False)

    # wrap JSON data in function call for JSON responses.
    if callback:
        text = '%s(%s)' % (callback, text)

    return text

@post('/ldap/photo.jpeg')
def ldap_post_download_jpeg_photo():
    mail = request.forms.mail
    jpegPhoto = request.files.jpegPhoto
    if mail and jpegPhoto and jpegPhoto.file:
        res = directory.search(normalize({"mail": mail, "returnAttr": ["carLicense", "jpegPhoto"]}))
        if res:
            dn = None
            oldJpegPhoto = None
            oldJpegPhotoMD5 = None
            for r in res:
                if len(r) > 1:
                    dn = r[0]
                    if 'jpegPhoto' in r[1]:
                        if len(r[1]['jpegPhoto']) > 0:
                            oldJpegPhoto = r[1]['jpegPhoto'][0]
                    if 'carLicense' in r[1]:
                        if len(r[1]['carLicense']) > 0:
                            oldJpegPhotoMD5 = r[1]['carLicense'][0]
            if not dn:
                raise HTTPError(400)

            raw = jpegPhoto.file.read() # This is dangerous for big files
            if not oldJpegPhoto:
                directory.add_attribute(dn, 'jpegPhoto', raw)
            else:
                directory.update_attribute(dn, {'jpegPhoto': oldJpegPhoto}, {'jpegPhoto': raw})

            hash_object = hashlib.md5(raw)
            newMD5 = hash_object.hexdigest()
            if not oldJpegPhotoMD5:
                directory.add_attribute(dn, 'carLicense', newMD5)
            else:
                directory.update_attribute(dn, {'carLicense': oldJpegPhotoMD5}, {'carLicense': newMD5})

            response.content_type = 'application/json'
            text = json.dumps({"md5": newMD5, "filename": jpegPhoto.filename}, indent=2, ensure_ascii=False)
            return text

    raise HTTPError(400)

@get('/ldap/photo.jpeg')
def ldap_get_download_jpeg_photo():
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

    mail = None
    if 'mail' in request.GET:
        mail = request.GET['mail']
    if not mail:
        raise HTTPError(400)

    md5 = None
    if 'md5' in request.GET:
        md5 = request.GET['md5']

    jpegPhotoMD5 = None
    if md5:
        res = directory.search(normalize({"mail": mail, "returnAttr": ["carLicense"]}))
        if not res:
            raise HTTPError(404)

        for r in res:
            if len(r) > 1:
                if 'carLicense' in r[1]:
                    if len(r[1]['carLicense']) > 0:
                        jpegPhotoMD5 = r[1]['carLicense'][0]

        if md5 == jpegPhotoMD5:
            raise HTTPError(204)

    res = directory.search(normalize({"mail": mail, "returnAttr": ["jpegPhoto"]}))
    if not res:
        raise HTTPError(404)

    jpegPhoto = None
    dn = None
    for r in res:
        if len(r) > 1:
            dn = r[0]
            if 'jpegPhoto' in r[1]:
                if len(r[1]['jpegPhoto']) > 0:
                    jpegPhoto = r[1]['jpegPhoto'][0]
                    r[1]['jpegPhoto'][0] = None

    if not jpegPhoto:
        raise HTTPError(404)

    hash_object = hashlib.md5(jpegPhoto)
    newMD5 = hash_object.hexdigest()

    if not jpegPhotoMD5:
        directory.add_attribute(dn, 'carLicense', newMD5)
    elif not newMD5 == jpegPhotoMD5:
        directory.update_attribute(dn, {'carLicense': jpegPhotoMD5}, {'carLicense': newMD5})

    response.content_type = 'image/jpeg; charset=UTF-8'
    response.headers['Content-Disposition'] = 'attachment; filename="avatar.jpeg"'
    response.headers['Content-MD5'] = newMD5

    return jpegPhoto

    # res = directory.signup(normalize(request.GET.dict))

    # if not res:
    #     raise HTTPError(400)

    # response.content_type = 'application/json'
    # text = json.dumps(res, indent=2, ensure_ascii=False)

    # wrap JSON data in function call for JSON responses.
    # if callback:
    #     text = '%s(%s)' % (callback, text)

    # response.headers['Content-Type'] = 'image/jpeg; charset=UTF-8'
    # response.headers['Content-Disposition'] = 'attachment; filename="avatar.jpeg"'

    # jpeg_photo = "blah"
    #
    # return jpeg_photo

    # Same MD5, not returning image
    # raise HTTPError(204)

@route('/ldap/')
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

    res = directory.search(normalize(request.GET.dict))

    if not res:
        raise HTTPError(404)

    response.content_type = 'application/json'

    # TODO: investigate how to ignore jpegPhoto
    for r in res:
        if len(r) > 1:
            if 'jpegPhoto' in r[1]:
                if len(r[1]['jpegPhoto']) > 0:
                    # r[1]['jpegPhoto'][0] = b64encode(r[1]['jpegPhoto'][0])
                    r[1]['jpegPhoto'][0] = None

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

