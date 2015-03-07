#!/usr/bin/env python
# -*- coding: utf-8 -*- #
from __future__ import unicode_literals

AUTHOR = u'Nildram'
SITENAME = u'Nildram'
SITEURL = ''

PATH = 'content'

TIMEZONE = 'Europe/Paris'

DEFAULT_LANG = u'en'

# Feed generation is usually not desired when developing
FEED_ALL_ATOM = None
CATEGORY_FEED_ATOM = None
TRANSLATION_FEED_ATOM = None
AUTHOR_FEED_ATOM = None
AUTHOR_FEED_RSS = None
AUTHOR_EMAIL = 'nildram@nildram.io'

# Blogroll
LINKS = (('Pelican', 'http://getpelican.com/'),
         ('Python.org', 'http://python.org/'),
         ('Jinja2', 'http://jinja.pocoo.org/'),
         ('You can modify those links in your config file', '#'),)

# Social widget
SOCIAL = (('github', 'https://github.com/nildram'),
         ('twitter-square', 'https://twitter.com/niIdram'),)

DEFAULT_PAGINATION = 10

# Uncomment following line if you want document-relative URLs when developing
#RELATIVE_URLS = True
THEME = 'pure'
COVER_IMG_URL = '/images/background.png'
TAGLINE = 'Software Exploitation and Development'
GOOGLE_ANALYTICS = 'UA-60488639-1'

PLUGIN_PATHS = ['plugins']
PLUGINS = ['gravatar']

STATIC_PATHS = ['images', 'extra']
EXTRA_PATH_METADATA = {
        'extra/CNAME': {'path': 'CNAME'},
        }
