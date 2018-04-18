NO LONGER IN SERVICE
====================

This repository houses the deposed codebase that powered pypi.python.org
for nearly 15 years.

`warehouse <https://github.com/pypa/warehouse>`_ now powers pypi.org, the
next-generation PyPI!

Required packages
-----------------

To run the PyPI software, you need Python 2.7+ and PostgreSQL


Quick development setup
-----------------------

It is recommended to read
http://wiki.python.org/moin/CheeseShopDev#DevelopmentEnvironmentHints though
this document is quite out of date, but contain some useful informations.

Make sure you have a working PostgreSQL Database Available, by getting a local
development install of _Warehouse_. See the Database Setup Below.

Make sure your config.ini is up-to-date, initially copying from
config.ini.template. Change CONFIG_FILE at the beginning of ``pypi.wsgi``,
so it looks like this::

    CONFIG_FILE = 'config.ini'

Then, you can create a development environment like this, if you have
virtualenv installed::

    $ virtualenv --no-site-packages .
    $ pip install -r requirements.txt

Then you can launch the server using the pypi.wsgi script::

    $ python pypi.wsgi
    Serving on port 8000...

PyPI will be available in your browser at http://localhost:8000

Database Setup
--------------


Postgres
~~~~~~~~

.. note::

    These instruction are in progress.


Connect Legacy-PYPI to warehouse
````````````````````````````````

It is highly recommended, and simpler to connect legacy-pypi to an already
working `warehouse <https://github.com/pypa/warehouse>`_ setup.

Once you have a working warehouse setup, it should expose the PostgreSQL
database on port 5433, you can check that in the ``docker-compose.yml`` file
which should contain a ``ports`` section like so::

  db:
    image: postgres:9.5
    ports:
        - "5433:5433"


Modify the pypi-legacy ``config.ini`` ``[database]`` section to connect to this
database, You can find the required information as follows. In the
``docker-compose.yml`` file find the line the set the DATABASE_URL::

    DATABASE_URL: postgresql://postgres@db/warehouse

It is structure in the following way: ``DATABASE_URL: postgresql://<user_name>@<host>/<database_name>``

Use the ``docker-machine env`` to find the Docker IP, for example::


    $ docker-machine env
    export DOCKER_TLS_VERIFY="1"
    export DOCKER_HOST="tcp://192.168.99.100:2376"
    export DOCKER_CERT_PATH="$HOME/.docker/machine/machines/default"
    export DOCKER_MACHINE_NAME="default"

Here the docker-ip is ``192.168.99.100``.

The final ``config.ini`` will be like::

    [database]

    ;Postgres Database using
    ;warehouse's docker-compose
    host = 192.168.99.100
    port = 5433
    name = warehouse
    user = postgres

Start warehouse as usual before starting PyPI-legacy, then start pypi-legacy
that should now connect to the local warehouse database.


Run a local Postgres Database
`````````````````````````````

It is recommended not to use a local PostgreSQL database as all the Database
migration and maintenance tasks are performed by warehouse.

To fill a database, run ``pkgbase_schema.sql`` on an empty Postgres database.
Then run ``tools/demodata`` to populate the database with dummy data.

To initialize an empty Postgres Database, after making sure Postgres is
installed on your machine, change to a directory of your convenience, like the
root of this repository, and issue the following::

  $ mkdir tmp
  $ chmod 700 tmp
  $ initdb -D tmp

The ``initdb`` step will likely tell you how to start a database server; likely
something along the line of::

  $ pg_ctl -D tmp -l logfile start

You want to start that in a separate terminal, in the folder where you
created the previous ``tmp`` directory, and run the above command.


Back to our initial terminal use the following to list all available Postgres
databases::

  $ psql -l
     Name    | Owner    | Encoding |   Collate   |    Ctype    |  Access privileges
  -----------+----------+----------+-------------+-------------+---------------------
   postgres  | guido_vr | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
   template0 | guido_vr | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/guido_vr     +
             |          |          |             |             | guido_vr=CTc/guido_vr
   template1 | guido_vr | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/guido_vr     +
             |          |          |             |             | guido_vr=CTc/guido_vr

Your exact input will differ. Note the _name_ of the database. In our case
above, ``postgres``, and the _user_ name. In our case ``guido_vr``, they will
be of use to configure the database in the ``config.ini`` file later.

We now need to populate the database with an example data. For example,
`example.sql <https://github.com/pypa/warehouse/tree/master/dev>`_ that can
be found on the warehouse repository. After having it downloaded and unpacked,
use the following::

  $ pgsql -d postgres -f /path/to/example/file.sql

Where ``postgres`` is the _name_ of the database noted above.


Set up the ``config.ini`` file ``[database]`` section, to connect to the Postgres
instance we just started::

  [database]

  ;Postgres Database
  host = localhost
  port = 5433
  name = postgres
  user = guido_vr


The default _host_ is likely ``localhost``, and the _port_ number ``5433`` as well.
adapt ``name`` and ``user`` with the value noted before.


Sqlite
~~~~~~

.. note::

    Usage of the SqLite local database is not recommended; And might not be
    functional.


For testing purposes, run the following to create a ``packages.db`` file at the
root of the repository::

    python2 tools/mksqlite.py

Set ``[database]driver`` to ``sqlite3`` in ``config.ini``, and
``[database]name`` to ``packages.db``::

    [database]

    driver = sqlite3
    name = package.db



Then run ``tools/demodata``    to populate the database.

PyPI Requires the ``citext`` extension to be installed.

TestPyPI Database Setup
-----------------------

testpypi runs under postgres; because I don't care to fill my head with such
trivialities, the setup commands are::

   createdb -O testpypi testpypi
   psql -U testpypi testpypi <pkgbase_schema.sql


Restarting PyPI
---------------

PyPI has 2 different pieces that need started, web server and the task runner.

::

    # Restart the web server
    $ /etc/init.d/pypi restart
    # Restart the task runner
    $ initctl restart pypi-worker

Clearing a stuck cache
----------------------

Users reporting stale data being displayed? Try::

  curl -X PURGE https://pypi.python.org/pypi/setuptools

(where the URL is the relevant one to the issue, I presume)

To see what fastly thinks it knows about a page (or how it's getting to you) try::

  curl -I -H 'Fastly-Debug: 1'  https://pypi.python.org/pypi/setuptools
