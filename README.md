# flask_simple_admin

The purpose of this repository is to provide a simple adminstration and user authentication for Flask.  This repository was adapted from `minimus_admin` and ported to `bottle_admin` and now Flask.  Probably at some point, Django.

Supports MongoDB and MontyDB as a flat file alternative to Mongo.

## requirements

* flask (https://github.com/pallets/flask)
* pymongo (https://github.com/mongodb/mongo-python-driver)
* montydb (https://github.com/davidlatwe/montydb) - an excellent alternative to PyMongo

### optional

* waitress (preferred server for proxy)
* paste (old reliable!)
* gevent (fast server can handle certificates)
* twisted (preferred server for simple non-proxy deployment)

# Installation

```
$ mkdir sample-proj
$ cd sample-proj
$ git clone https://github.com/jefmud/flask_simple_admin
```

# Usage

Here's a simple program that uses `flask_simple_admin`

```
from flask import Flask, render_template
from flask_simple_admin import Admin
import sys

app = Flask(__name__)
app.secret_key = 'secret!' # set your key to something no one has seen
admin = Admin(app)

@app.route('/')
def index():
    return """
    <html>
    <body>Admin interface - <a href="/admin">click here</a></body>
    </html>
    """

if __name__ == '__main__':
    admin.user_services_cli(sys.argv)
```

# getting ready

We will have to create a user or two before running the program.

```
$ python app.py --createuser
Username (required): admin
Real Name: Admin User
Email: admin@example.com
Password (required):password
Created user
```

# Running our program

```
$ python app.py --runserver

 * Serving Flask app 'app.py'
 * Debug mode: off
Listening on http://127.0.0.1:5000/
Hit Ctrl-C to quit.

serving on http://127.0.0.1:5000
```

# Finally
Have fun!

