#!/usr/bin/env python
import sys
import os
import json
import pickle

from pkg_resources import safe_name

# Workaround current bug in docutils:
# http://permalink.gmane.org/gmane.text.docutils.devel/6324
import docutils.utils

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path = [root] + sys.path

import config
import store

config = config.Config("config.ini")
store = store.Store(config)


# Load the JSON up
fname = os.path.join(os.path.dirname(__file__), "hosting_mode_migration.json")
with open(fname) as fp:
    data = json.load(fp)

processed = {
    "pypi-explicit": set(),
    "pypi-scrape": set(),
    "pypi-scrape-crawl": set(),
}

accepted_modes = {
    "pypi-scrape-crawl": ["pypi-scrape-crawl", "pypi-scrape", "pypi-explicit"],
    "pypi-scrape": ["pypi-scrape", "pypi-explicit"],
    "pypi-explicit": ["pypi-explicit"],
}


store.open()
for desired_mode, names in data.iteritems():
    if desired_mode == "pypi-scrape-crawl":
        continue  # We don't need to do any processing for pypi-scrape-crawl

    for name in names:
        packages = store.find_package(name)
        if not packages:
            continue  # This doesn't exist

        assert safe_name(name).lower() == safe_name(packages[0]).lower()
        name = packages[0]

        current_mode = store.get_package_hosting_mode(name)

        if current_mode not in accepted_modes[desired_mode]:
            store.set_package_hosting_mode(name, desired_mode)
            processed[desired_mode].add(name)
store.commit()

with open("migrated.pkl", "wb") as pkl:
    pickle.dump(processed, pkl)
