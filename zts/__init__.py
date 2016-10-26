#!/usr/bin/env python
# coding: utf-8

from flask import Flask, redirect, current_app, request, session, \
     render_template, flash, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, \
     login_required, current_user
from flask_admin import Admin
from flask_wtf import Form
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired
from flask_principal import Principal, Identity, AnonymousIdentity, \
     identity_changed
from datetime import datetime, timedelta
import logging, logging.handlers
import math
import os, sys
import config

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = config.ZTS_SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = config.ZTS_SECRET_KEY
app.debug = True
db = SQLAlchemy(app)

principal = Principal(app)

login_manager = LoginManager(app)
login_manager.init_app(app)

admin = Admin(app, name='ZTS Admin', template_mode='bootstrap3')

FORMAT = '%(asctime)-15s %(levelname)s %(message)s'
logger = logging.getLogger(config.ZTS_LOGGER_NAME)
logger_handler = logging.handlers.RotatingFileHandler(config.ZTS_LOG_FILE, mode='a', maxBytes=2**20, backupCount=10)
logger_formatter = logging.Formatter(FORMAT)
logger_handler.setFormatter(logger_formatter)
logger.addHandler(logger_handler)
logger.setLevel(logging.DEBUG)

def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

sys.excepthook = handle_exception

def generate_random_data():
    from models import Area, User, Ticket, Note, TicketCloseReason
    import random
    import loremipsum

    db.drop_all()
    db.create_all()

    areas = [
        Area(name=u'CTO'),
        Area(name=u'Network'),
        Area(name=u'Infrastructure'),
        Area(name=u'Devops'),
        Area(name=u'Helpdesk'),
    ]
    db.session.add_all(areas)
    db.session.commit()

    users = [
        User(user='bonagurabsb', name=u'Bruno Bonagura', areas=areas, access_admin=True, access_reports=False),
    ]
    users[0].set_password('ax886dds')
    db.session.add_all(users)
    
    reasons = [
        TicketCloseReason(reason=u'Solved'),
        TicketCloseReason(reason=u'False Alarm'),
        TicketCloseReason(reason=u'Network failure'),
        TicketCloseReason(reason=u'Misconfiguration'),
        TicketCloseReason(reason=u'Remission')
    ]
    db.session.add_all(reasons)
    db.session.commit()

    random.seed('oi')
    for i in range(1, 100):
        t = Ticket(
            title = unicode(loremipsum.get_sentence()),
            text = unicode(loremipsum.get_paragraph()),
            current_area = random.choice(areas),
            created_at = datetime.now() - timedelta(random.randint(1,100)),
            created_by = random.choice(users),
        )
        t.add_note(random.choice(users), unicode(loremipsum.get_sentence()))
        db.session.add(t)
    db.session.commit()

if __name__ == '__main__':
    generate_random_data()

import zts.views