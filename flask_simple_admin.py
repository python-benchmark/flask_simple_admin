##############################
#
# Flask Simple Admin - implements Admin class user interface
# for use with the Flask framework.
#
# There is some refactoring from Minimus_admin and Bottle_simple_admin.
# must have either MontyDB (stand-alone) or PyMongo (to a MongoDB instance)
# if you expect it to do anything
#
# License - MIT License, no guarantees of suitability for your app
#
# version 0.0.1
#   Added support for per collection schema
#   requires TEMPLATE_PATH to find jinja2 templates (that's good that they are separate)
#   TEMPLATE_PATH[:] = ['templates', 'bottle_simple_admin/templates']
#
# version 0.0.2
#  Added support for v2 schema handles UI labels (backward compatible)
#
# version 0.0.3 - Added support for v3 schema (backward compatible to all)
#   can add data via schema, schema supports JSON nesting with a
#   dot notation. (reflected in UI)
#   unfortunately more complex logic and Admin.edit_schema and Admin.edit_fields
#   Admin.edit_fields() - more complex since it handles all
#                    field-based and schema-based saves (new and existing)__
#      import known limitation - you cannot add a nested type without a schema!
#   This version also allows support of a number of HTML5 input types
#
# version 0.0.4 - Added support for list-views.
#    A list-view is a simple schema extension that allows the user to define
#    a list-view by using a simple caret ('^') prefix in front of the field
#    that will show up in a list view.  It paves the way for data required
#    type validation in the
#    next version by use of an asterisk ('*') in front of a required (validated) field
#
#
##################################
__author__ = 'Jeff Muday'
__version__ = '0.0.4'
__license__ = 'MIT'

from flask import Flask, redirect, abort, request, url_for, session
from jinja2 import Environment, FileSystemLoader

from montydb import MontyClient, set_storage
import json
from pymongo import MongoClient
from bson import ObjectId
import pathlib
from functools import wraps

import os
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["pbkdf2_sha256"],
                           default="pbkdf2_sha256",
                           pbkdf2_sha256__default_rounds=30000)


def encrypt_password(password):
    return pwd_context.encrypt(password)


def check_encrypted_password(password, hashed):
    return pwd_context.verify(password, hashed)


# hooks for database and app
_db = None
_app = None
_template_dirs = [pathlib.Path(__file__).resolve().parent.joinpath('templates')]

def jsonify(myjson):
    """jsonify() - makes it JSON similar to flask
    (in Bottle you don't have to do anything)
    """
    return myjson


class Admin:
    """
    Allow for CRUD of data in database
    TODO
	7. write up security documents.  Possibly combine with minimus_users module.
	8. document the hell out of this module, because I will forget it.
    """

    def __init__(
        self,
        app: Flask,
        url_prefix="/admin",
        db_uri=None,
        db_file='flask.db',
        admin_database='flask_admin',
        users_collection='admin_users',
        require_authentication=True,
    ):
        """__init__() - initialize the administration area"""
        global _db, _app
        _app = app  # global access to app

        self.app = app
        self.url_prefix = url_prefix
        self.users_collection = users_collection

        self.require_authentication = require_authentication

        self.template_path = os.path.dirname(__file__)

        ### set up the database ###
        if db_uri:
            app.client = MongoClient(db_uri)
        else:
            set_storage(db_file, use_bson=True)
            app.db_file = db_file
            app.client = MontyClient(db_file)

        app.db = app.client[admin_database]
        _db = app.db

        ### Add the routes ###
        app.add_url_rule(url_prefix + '/login',
                         endpoint='admin_login',
                         view_func=self.login,
                         methods=['GET', 'POST'])
        app.add_url_rule(url_prefix + '/logout', 
                         endpoint="admin_logout",
                         view_func=self.logout
                         )

        #### routes to add/modify/delete data
        app.add_url_rule(rule=url_prefix,
                         endpoint="admin_view_all",
                         view_func=self.view_all)
        app.add_url_rule(rule=url_prefix + '/view/<coll>',
                         endpoint="admin_view_collection",
                         view_func=self.view_collection)
        app.add_url_rule(rule=url_prefix + '/edit/<coll>/<id>',
                         endpoint="admin_edit_fields",
                         view_func=self.edit_fields,
                         methods=['GET', 'POST'])
        app.add_url_rule(rule=url_prefix + '/edit_schema/<coll>',
                         endpoint="admin_edit_schema",
                         view_func=self.edit_schema,
                         methods=['GET', 'POST'])
        app.add_url_rule(rule=url_prefix + '/edit_schema/<coll>/<id>',
                         endpoint="admin_edit_schema",
                         view_func=self.edit_schema,
                         methods=['GET', 'POST'])
        app.add_url_rule(rule=url_prefix + '/edit_raw/<coll>/<id>',
                         endpoint="admin_edit_json",
                         view_func=self.edit_json,
                         methods=['GET', 'POST'])
        app.add_url_rule(rule=url_prefix + '/delete/<coll>',
                         endpoint="admin_delete_collection",
                         view_func=self.delete_collection_prompt,
                         methods=['GET', 'POST'])
        app.add_url_rule(rule=url_prefix + '/delete/<coll>/<id>',
                         endpoint="admin_delete_collection_item",
                         view_func=self.delete_collection_item,
                         methods=['GET', 'POST'])
        app.add_url_rule(rule=url_prefix + '/add/<coll>',
                         endpoint="admin_add_collection_item",
                         view_func=self.add_collection_item,
                         methods=['GET', 'POST'])
        app.add_url_rule(rule=url_prefix + '/add',
                         endpoint="admin_add_collection",
                         view_func=self.add_mod_collection,
                         methods=['GET', 'POST'])
        app.add_url_rule(rule=url_prefix + '/modify/<coll>',
                         endpoint="admin_mod_collection",
                         view_func=self.add_mod_collection,
                         methods=['GET', 'POST'])

    def login(self, filename=None, next=None):
        """
        login() - simple login with bootstrap or a Jinja2 file of your choice
        :param filename: the filename of the template to use
        :param next: the next page to go to after login
        """
        if filename is None:
            html = self.render_login()

        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            user = self.get_user(username)
            if self.authenticate(username, password):
                user['_id'] = str(user['_id'])
                self.login_user(user)
                next = 'admin_view_all' if next is None else next
                return redirect(url_for(next))

        # if no filename the render internal
        if filename is None:
            return html

        # render external login
        return render_template(filename)

    def login_user(self, user):
        """
        login_user() - login the user
            sets the Session to the authenticated user
            :param user: the user to login
        """
        session['is_authenticated'] = True
        session['user'] = user

    def login_check(self):
        """
        login_check() - if require_authentication return user else None
        """

        if self.require_authentication:
            if session.get('is_authenticated'):
                return session['user']
            return None
        else:
            return True

    def login_required(self, f):
        """login_required(f) is a decorator for Flask routes that require a login
        : param {f} : function to decorate
        : return : decorated function
        """

        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                return redirect(url_for('admin_login'))
            return f(*args, **kwargs)

        return decorated_function

    def logout(self, next=None):
        """
        logout() - a simple logout, redirects to '/' or a next
        """
        self.logout_user()
        next = next if next else '/'
        return redirect(next)

    def logout_user(self):
        """logout_user() - pops the user out of the session"""
        if 'is_authenticated' in session:
            session['is_authenticated'] = False
        if 'user' in session:
            session.pop('user')

    def view_all(self):
        """
        view_all() - view all collections in the database
        """
        if not self.login_check():
            return redirect(url_for('admin_login'))
        collections = _db.list_collection_names()
        return render_template('admin/view_all.html', collections=collections)

    def view_collection(self, coll):
        """view_all(coll) - view a specific collection in the database"""
        if not self.login_check():
            return redirect(url_for('admin_login'))
        data = list(_db[coll].find())
        schema = _db['_meta'].find_one({'name': coll})
        # santize id to string
        for doc in data:
            doc['_id'] = str(doc['_id'])

        if schema:
            # check for list-view
            if '^' in schema['schema']:
                docs = []
                for raw_doc in data:
                    this_doc = _schema_transform(raw_doc, schema)
                    docs.append(this_doc)
                return render_template('admin/view_collection_list.html',
                                       docs=docs,
                                       coll=coll)

        return render_template('admin/view_collection.html',
                               coll=coll,
                               data=data,
                               schema=schema)

    def edit_json(self, coll, id):
        """render a specific record as JSON"""
        if not self.login_check():
            return abort(401)
        try:
            key = {'_id': ObjectId(id)}
            data = _db[coll].find_one(key)
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': 'Admin edit_json() key, ' + str(e)
            })

        if request.method == 'POST':
            try:
                raw = dict(request.form)
                text_format = raw.get('content')
                data = json.loads(text_format)
                #self.app.db[coll].update_one(key, {'$set': data})
                _db[coll].replace_one(key, data)
            except Exception as e:
                return jsonify({
                    'status':
                    'error',
                    'message':
                    'Admin edit_json() replace_one(), ' + str(e)
                })

            return redirect(url_for('admin_view_collection', coll=coll))

        else:
            # render the JSON
            if '_id' in data:
                data.pop('_id')
            return render_template('admin/edit_json.html',
                                   coll=coll,
                                   content=json.dumps(data),
                                   error=None)

    def edit_fields(self, coll, id, next=None):
        """
        edit_fields('collectionName', id) - render a specific record as fields
        ** combine with edit_schema() during refactor
        """
        if not self.login_check():
            return abort(401)
        next = request.args.get('next', None)
        if not id == 'new':
            try:
                key = {'_id': ObjectId(id)}
            except Exception as e:
                return jsonify({
                    'status':
                    'error',
                    'message':
                    f'Admin edit_fields(), id={id}, ' + str(e)
                })

        if request.method == 'POST':
            # write the data
            try:
                if id == 'new':
                    old_data = {}
                else:
                    # get existing data
                    old_data = _db[coll].find_one(key)

                # expand from flattened to nested
                data = expand_fields(request.form)

                # check which fields changed
                for k, v in old_data.items():
                    if k not in data.keys():
                        data[k] = ''

                # clean up
                if '_id' in data:
                    data.pop('_id')
                if 'csrf_token' in data:
                    data.pop('csrf_token')

                if id == 'new':
                    # write new data
                    _db[coll].insert_one(data)
                else:
                    # write existing data
                    _db[coll].update_one(key, {'$set': data})

                data['_id'] = id
            except Exception as e:
                return jsonify({
                    'status':
                    'error',
                    'message':
                    'Admin edit_fields() update_one, ' + str(e)
                })
            if next:
                return redirect(next)
            return redirect(url_for('admin_view_collection', coll=coll))
        else:
            # view the data
            try:
                data = _db[coll].find_one(key)
                data['_id'] = str(data['_id'])
                fields = _fields_transform(data)
            except Exception as e:
                return jsonify({
                    'status':
                    'error',
                    'message':
                    'Admin edit_fields(), find_one(), view ' + str(e)
                })

            return render_template('admin/edit_fields.html',
                                   coll=coll,
                                   fields=fields,
                                   id=data['_id'])

    def edit_schema(self, coll, id='new'):
        """
        edit_schema('collectionName', id) - edit collection item with based on a schema
        
        coll - collection name
        id - the database id
        
        supports GET and POST methods
        """
        if not self.login_check():
            return abort(401)

        # get query string, if present
        next = request.args.get('next', None)
        
        if id == 'new':
            data = {'_id': 'new'}
        else:
            try:
                key = {'_id': ObjectId(id)}
            except Exception as e:
                return jsonify({
                    'status':
                    'error',
                    'message':
                    'Admin edit_schema(), key error, ' + str(e)
                })

        # view the data
        try:
            schema = _db['_meta'].find_one({'name': coll})
            if not id == 'new':
                # get existing record
                data = _db[coll].find_one(key)
            fields = _schema_transform(data, schema)
            data['_id'] = str(data['_id'])
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': 'Admin edit_schema(), view ' + str(e)
            })

        return render_template('admin/edit_schema.html',
                               coll=coll,
                               fields=fields,
                               id=data['_id'],
                               next=next
                               )

    def add_collection_item(self, coll):
        """Add a new item to the collection, raw JSON"""
        if not self.login_check():
            return abort(401)
        if request.method == 'GET':
            return render_template('admin/add_json.html', coll=coll)
        else:
            raw = request.form.get('content')
            try:
                data = json.loads(raw)
            except:
                data = cook_data(raw)
            _db[coll].insert_one(data)
            data['_id'] = str(data['_id'])
        return redirect(url_for('admin_view_collection', coll=coll))

    def add_mod_collection(self, coll=None):
        """Add or Modify a collection name (and Schema)"""
        if not self.login_check():
            return abort(401)
        fields = {}
        key = None
        if coll:
            # find record of schema
            fields['name'] = coll
            rec = _db['_meta'].find_one({'name': coll})
            if rec:
                key = {'_id': rec['_id']}
                fields['schema'] = rec['schema']

        if request.method == 'POST':
            fields = dict(request.form)
            name = fields.get('name')
            if name is None:
                return redirect(url_for('admin_view_all'))

            schema = fields.get('schema')
            meta = {'name': name, 'schema': schema}
            if schema:
                if key:
                    # since it exists, replace
                    _db['_meta'].replace_one(key, meta)
                else:
                    # it's new insert
                    _db['_meta'].insert_one(meta)

            # create the collection if it doesn't exist
            if not name in _db.list_collection_names():
                id = _db[name].insert_one({}).inserted_id
                _db[name].delete_one({'_id': id})

            return redirect(url_for('admin_view_all'))

        return render_template('admin/add_mod_collection.html', fields=fields)

    def delete_collection_item(self, coll, id):
        if not self.login_check():
            return abort(401)
        try:
            key = {'_id': ObjectId(id)}
            old_data = _db[coll].find_one(key)
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': 'deleteJSON non-existent id, ' + str(e)
            })

        _db[coll].delete_one(key)
        return redirect(url_for('admin_view_collection', coll=coll))

    def delete_collection_prompt(self, coll):
        """delete collection with prompt"""
        if not self.login_check():
            return abort(401)
        fields = {}
        if request.method == 'POST':
            fields = dict(request.form)
            if fields.get('name') == coll and fields.get('agree') == 'on':
                _db[coll].drop()
            return redirect(url_for('admin_view_all'))

        return render_template('admin/delete_collection_prompt.html',
                               fields=fields,
                               coll=coll)

    def delete_collection(self, coll):
        """DANGER -- this method will delete a collection immediately"""
        if not self.login_check():
            return abort(401)
        _db[coll].drop()
        return redirect(url_for('admin_view_all'))

    def unit_tests(self):
        """simple test of connectivity.  more tests should be included in separate module"""
        name = '__test_collection'
        _id = _db[name].insert_one({}).inserted_id
        names = _db.list_collection_names()
        assert (name in names)
        _db[name].drop()
        print("*** All tests passed ***")

    def get_users(self):
        """get_users() - return a list of all users JSON records"""
        if _db is None:
            raise ValueError("Database not initialized!")
        return list(_db[self.users_collection].find())

    def get_user(self, username=None, uid=None):
        """get_user(username, uid) ==> find a user record by uid or username
        : param {username} : - a specific username (string)
        : param {uid} : - a specific user id (string) - note, this is actual '_id' in databse
        : return : a user record or None if not found
        """
        if _db is None:
            raise ValueError("Database not initialized!")
        # first try the username--
        user = None
        if username:
            user = _db[self.users_collection].find_one({'username': username})
        if uid:
            user = _db[self.users_collection].find_one({'_id': uid})
        return user

    def create_user(self, username, password, **kwargs):
        """
        create_user(username, password, **kwargs) ==> create a user --
        : param {username} and param {password} : REQUIRED
        : param **kwargs : python style (keyword arguments, optional)
        : return : Boolean True if user successfully created, False if exisiting username
        example
        create_user('joe','secret',display_name='Joe Smith',is_editor=True)
        """
        user = self.get_user(username=username)
        if user:
            # user exists, return failure
            return False
        # build a user record from scratch
        user = {'username': username, 'password': encrypt_password(password)}
        for key, value in kwargs.items():
            user[key] = value

        _db[self.users_collection].insert_one(user)
        return True

    def update_user(self, username, **kwargs):
        """
        update_user(username, **kwargs) - update a user record with keyword arguments
        : param {username} : an existing username in the database
        : param **kwargs : Python style keyword arguments.
        : return : True if existing username modified, False if no username exists.
        update a user with keyword arguments
        return True for success, False if fails
        if a keyword argument is EXPLICITLY set to None,
        the argument will be deleted from the record.
        NOTE THAT TinyMongo doesn't implement $unset
        """
        user = self.get_user(username)
        if user:
            idx = {'_id': user['_id']}
            for key, value in kwargs.items():
                if value is None and key in user:
                    # delete the key
                    _db[self.users_collection].update_one(
                        idx, {'$unset': {
                            key: ""
                        }})
                else:
                    # user[key] = value
                    if key == 'password':
                        value = encrypt_password(value)
                    _db[self.users_collection].update_one(
                        idx, {'$set': {
                            key: value
                        }})
            return True
        return False

    def delete_user(self, username=None, uid=None):
        """delete_user(username, uid) deletes a user record by username or uid
        : param {username} : string username on None
        : param {uid} : string database id or None
        : return : returns user record upon success, None if fails
        """
        user = None
        if username:
            user = self.get_user(username=username)
        if uid:
            user = self.get_user(uid=uid)
        if user:
            _db[self.users_collection].remove(user)
        return user

    def authenticate(self, username, password):
        """
        authenticate(username, password) ==> authenticate username, password against datastore
        : param {username} : string username
        : param {password} : string password in plain-text
        : return : Boolean True if match, False if no match
        """
        user = self.get_user(username)
        if user:
            if check_encrypted_password(password, user['password']):
                return True
        return False

    def render_login(self, login_filename=None):
        """
        render_login(login_filename=None) returns a login page as a string contained
        login_file if None, then if loads module level file login.html
        
        : param {login_filename} : string of filename of login page HTML document or None.
        If None, then the package level standard login.html is loaded.
        : return : string HTML of login page
        NOTE: this is an experimental feature
        """
        # use module level 'login.html''
        if login_filename is None:
            moduledir = os.path.dirname(__file__)
            login_filename = os.path.join(moduledir, 'login.html')
        if not isinstance(login_filename, str):
            raise TypeError(
                "ERROR: minmus_users.login_page() - login_filename must be a string"
            )
        with open(login_filename) as fp:
            data = fp.read()
        return data

    def user_services_cli(self, args):
        """command line interface for user services"""

        error = 0
        errors = []

        if '--createuser' in args:
            username = input('Username (required): ')
            realname = input('Real Name: ')
            email = input('Email: ')
            password = input('Password (required):')
            self.create_user(username,
                             password,
                             realname=realname,
                             email=email)
            print("*Created user*")
            return True

        if '--deleteuser' in args:
            print("Delete user--")
            username = input('Username (required): ')
            if self.delete_user(username):
                print("*Deleted user*")
                return True
            else:
                errors.append("No such user.")

        if '--listusers' in args:
            users = self.get_users()
            for user in users:
                print(user)
            return True

        if '--updateuser' in args:
            username = input('Username (required): ')
            realname = input('Real Name: ')
            email = input('Email: ')
            password = input('Password (required):')
            if self.get_user(username=username):
                self.update_user(username,
                                 password=password,
                                 realname=realname,
                                 email=email)
                print("*Updated user*")
                return True
            else:
                errors.append("No username exists.")

        host = '127.0.0.1'
        if '--host' in args:
            idx = args.index('--host')
            try:
                host = args[idx + 1]
            except:
                error = 1
                errors.append("Bad or missing host argument (e.g. --host 0.0.0.0)")

        port = 5000
        if '--port' in args:
            idx = args.index('--port')
            try:
                port = int(args[idx + 1])
            except:
                error = 1
                errors.append("Bad or missing 'port' value following '--port' argument. Expected integer (e.g. --port 5000).")

        server = "wsgiref"
        if '--server' in args:
            idx = args.index('--server')
            try:
                server = args[idx + 1]
            except:
                error = 1
                errors.append("No server argument supplied (e.g. --server wsgiref)")
                
        quiet = False
        if '--quiet' in args:
            quiet = True
            
        keyfile = None
        if '--keyfile' in args:
            keyfile = args[args.index('--keyfile')+1]
            
        certfile = None
        if '--certfile' in args:
            certfile = args[args.index('--certfile')+1]

        if '--runserver' in args:
            if not error:
                try:
                    if server == 'waitress':
                        # in case waitress is your server
                        from waitress import serve
                        print(f"Waitress serving {host}:{port}")
                        serve(_app, host=host, port=port)
                        
                    if server == 'paste':
                        # in case you want to use paste
                        from paste import httpserver
                        from paste.translogger import TransLogger
                        handler = TransLogger(_app.wsgi_app, setup_console_handler=(True))
                        print("Starting Paste Server")
                        httpserver.serve(handler, host=host, port=port)
                        
                    if server == 'gevent':
                        """Gevent server, high speed, but no threading. Supports SSL (if keyfile and certfile are set)"""
                        from gevent import pywsgi
                        address = (host, port)
                        print("Gevent serving on {}:{}".format(host, port))
                        if keyfile or certfile:
                            httpd = pywsgi.WSGIServer(address, self.app, keyfile=keyfile, certfile=certfile, ssl_context='adhoc')
                        else:
                            httpd = pywsgi.WSGIServer(address, self.app)
                        httpd.serve_forever()
                            
                    if server == 'twisted':
                        """Twisted server - a bit more complicated server.
                        High performance for prodcution.  Supports SSL (if keyfile and certfile are set)
                        """
                        from twisted.web.server import Site
                        from twisted.web.wsgi import WSGIResource
                        from twisted.internet import reactor
                        if not quiet:
                            from twisted.python.log import startLogging
                            import sys
                            startLogging(sys.stdout)
                        resource = WSGIResource(reactor, reactor.getThreadPool(), self.app)
                        site = Site(resource)
                        if certfile:
                            from twisted.internet import ssl
                            sslContext = ssl.DefaultOpenSSLContextFactory(keyfile, certfile)
                            reactor.listenSSL(port, site, sslContext)
                        else:
                            reactor.listenTCP(port, site)
                        reactor.run()
                        
                    # default to wsgiref
                    _app.run(host=host, port=port)
                    
                except Exception as e:
                    errors.append("Server error: " + str(e))

        print(', '.join(errors))
        usage = """
Run usage:

    python app.py --runserver [--port {5000}] [--host {127.0.0.1}] [--server {wsgiref}]
            
    
Other operations:

    python app.py [--createuser | --deleteuser | --listuser | --updateuser ]
    
    createuser - creates a new user
    deleteuser - deletes an existing user
    listusers - list all users
    updateuser - update an existing user
"""
        print(usage)
        return False


def _merge_dicts(dict1, dict2):
    """ 
    _merge_dicts(dict1, dict2) - merge two dictionaries, return the union.
    Using yield increases efficiency.
    From
    """
    for k in set(dict1.keys()).union(dict2.keys()):
        if k in dict1 and k in dict2:
            if isinstance(dict1[k], dict) and isinstance(dict2[k], dict):
                # unfortunately, a recursive call
                yield (k, dict(_merge_dicts(dict1[k], dict2[k])))
            else:
                # If one of the values is not a dict, you can't continue merging it.
                # Value from second dict overrides one in first and we move on.
                yield (k, dict2[k])
                # Alternatively, replace this with exception raiser to alert you of value conflicts
        elif k in dict1:
            yield (k, dict1[k])
        else:
            yield (k, dict2[k])


def expand_fields(fields):
    """
    expand_fields(fields) - expand flattened fields to nested fields
    : params data - a flattened record
    returns expanded fields
    """
    data = {}
    for name, value in fields.items():
        data = dict(_merge_dicts(data, _nest_value(name, value)))
    return data


def _nest_value(name, value):
    """
    _nest_value(name, value) - put the fields from a 
    "flattened" dotted name into nested structure and return
    
    :param name - the flattened dotted name
    :param value - the actual value
    
    return nested_value
    
    How can I do this cleaner with a dict structure?
    """
    data = {}
    parts = name.strip().split('.')
    if len(parts) == 1:
        data.update({parts[0]: value})
    elif len(parts) == 2:
        data.update({parts[0]: {parts[1]: value}})
    elif len(parts) == 3:
        data.update({parts[0]: {parts[1]: {parts[2]: value}}})
    else:
        raise ValueError("Schmema depth exceeds maximum limit of 3")
    return data


def _get_nested_value(name, data):
    """
    _get_nested_value(name, data) - get the fields from a "flattened" dotted name
    :param name - the flattened dotted name
    :param data - data dictionary of document
    return value
    """
    parts = name.strip().split('.')
    value = data
    for part in parts:
        value = value.get(part, '')
        if not isinstance(value, dict):
            return value
    return None


def _schema_transform(data, schema):
    """_schema_transform(data, schema) - create fields from data document and schema. These
    fields are used to create a form for editing the document. The fields are ordered.

    :param data - the document data
    :param schema - the document schema
    
    return
        fields
    
    A schema for each field is defined on one line as shown below.
    
    dataName : controlToUse :Label of the collection : type : defaultValue
    
    implemented:
    A caret (^) is used to indicate that the field is shown in a list-view.
    
    not implemented in this version:
    A asterisk (*) is used to indicate a required field.
    A pipe (|) is used to indicate a list of values.
    
    
    for example:
    ^name : textbox : Name
    
    
    type (simple types only)
    
    """
    # grab the schema buffer
    schema_lines = schema.get('schema').split('\n')
    fields = []
    for line in schema_lines:
        if line:
            field = {}

            # if there is an '_id' field, then this is an existing document
            if '_id' in data:
                field.update({'_id': data['_id']})

            # break it on ':'
            parts = line.split(':')

            # name part

            # is it a list-view field?
            field['list-view'] = '^' in parts[0]
            parts[0] = parts[0].replace('^', '')

            # is it a required field?
            field['required'] = '*' in parts[0]
            parts[0] = parts[0].replace('*', '')

            field['name'] = parts[0].strip()  # the name part

            field['control'] = parts[1].strip()  # get the type

            if len(parts) > 2:
                field['label'] = parts[2].strip()  # the label
            else:
                field['label'] = field['name'].title()

            if len(parts) > 3:
                field['type'] = parts[3].strip()

            # value for field(data) is none, get it from schema
            if data == {}:
                if len(parts) > 4:
                    field['value'] = parts[4].strip()
                else:
                    # if value is missing, make it an empty string
                    field['value'] = ''
            else:
                # transform multiple depths
                value = _get_nested_value(field['name'], data)
                field['value'] = value

            fields.append(field)
    return fields


def _unflatten(dictionary, separator='.'):
    """
    _unflatten(dictionary, separator='.') - unflatten a dictionary
    :param dictionary - the dictionary to unflatten
    :param separator - the separator to use
    return unflattened dictionary
    """
    resultDict = dict()
    for key, value in dictionary.items():
        parts = key.split(separator)
        d = resultDict
        for part in parts[:-1]:
            if part not in d:
                d[part] = dict()
            d = d[part]
        d[parts[-1]] = value
    return resultDict


def _flatten_dict(d, parent_key='', sep='.'):
    """
    _flatten_dict(d, parent_key = '', sep='.') - flatten a nested dictionary
    :param d - the dictionary to flatten
    :param parent_key - the parent key
    :param sep - the separator
    return flattened dictionary
    """
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, dict):
            items.extend(_flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def _fields_transform(fields):
    """transform fields to be used in form"""
    # flatten dictionary if needed
    f_fields = _flatten_dict(fields)
    nfields = []
    for key, value in f_fields.items():
        nf = {}
        nf['name'] = key
        nf['value'] = str(value)
        nf['label'] = key.capitalize()
        if '\n' in nf['value']:
            nf['type'] = 'textarea'
        else:
            nf['type'] = 'text'
        nfields.append(nf)
    return nfields


def cook_data(raw_data):
    """cook data to be used in form"""
    data = {}
    lines = raw_data.split('\n')
    for line in lines:
        if ':' in line:
            key, value = line.split(':')
            key = key.strip()
            data[key] = value.strip()
    return data

def get_file(filename, *args, **kwargs):
    """get_file(filename, *args, **kwargs) - get text file or return None,
    searches the likely paths to find the file. If not found, return None
    Args:
        filename (str): a filename to search
        *args (str): multiple directory candidates for file location first one to match wins
        **kwargs (keyword arguments): default ftype='text' also would use ftype='binary'
    Example:
        get_file('index.html', 'templates', ftype='text')
        get_file('mylogo.gif', 'static/images', ftype='binary')
    """
    real_filename = search_file(filename, *args)
    file_contents = None
    path = pathlib.Path(real_filename)
    if path.is_file():
        if real_filename:
            if 'bin' in kwargs.get('ftype',''):
                # binary file types
                with open(real_filename, 'rb') as fp:
                    file_contents = fp.read()
            else:
                with open(real_filename) as fp:
                    file_contents = fp.read()

    return file_contents

def get_text_file(filename, *args):
    """call get_file for a text file - looks for the file in multiple directorys
    Args:
        filename (str) - a filename
        *args (str) - 0 or more directories to return a file from
    Returns:
        str: the contents of the file or None
    see "get_file"
    """
    return get_file(filename, *args)

def search_file(filename, *args):
    """search_file(filename, *args) - look for a filename in several locations,
    return the actual filename that is found first or None
    Args:
        filename (str): the file to search for existence
        *args (str): 0 or more directories to examine
    Returns:
        str: the full path of the exisiting file or None
    """
    fname = filename
    if filename.startswith('/'):
        fname = filename[1:]
    # possible paths ACTUAL PATH, relative path to app, or template_dirs
    # might want to make this more specific to avoid name conflict

    paths = [filename, fname]
    for arg in args:
        if isinstance(arg, list):
            for sub in arg:
                paths.append(os.path.join(sub, fname))
        else:
            paths.append(os.path.join(arg, fname))

    for fn in paths:
        #if os.path.exists(fn):
        # *** better way ***
        path = pathlib.Path(fn)
        if path.is_file():        
            return fn
    return None

def render_template(filename, **kwargs):
    """render_template(filename, **kwargs
    provides flexible jinja2 rendering of filename and kwargs
    
    Args:
        filename - filename of template file, looks in candidate directories
        (by default, looking into ./templates but can be overridden with kwargs)
    """
    template_dirs = ''
    #static_dir =''
    if 'template_dirs' in kwargs:
        template_dirs = kwargs.get('template_dirs')

    # Grab file content, flexible location
    file_content = get_text_file(filename, _template_dirs, template_dirs)
    template_dirs = _template_dirs

    if file_content:
        # create a Jinja2 environment variable
        environment = Environment(loader=FileSystemLoader(template_dirs, followlinks=True))
            
        # make url_for() function available at the template level
        kwargs['url_for'] = url_for
                
        template = environment.from_string(file_content)
        
        return template.render(**kwargs)
    return "ERROR: render_template - Failed to find {}".format(filename)

if __name__ == '__main__':
    print("... Flask_Simple_Admin is not intended for direct execution. ...")
    print("done")
