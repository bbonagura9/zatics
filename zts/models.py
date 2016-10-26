#!/usr/bin/python
# coding: utf-8

from flask import Flask, redirect, current_app, request, session, \
     render_template, flash, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, \
     login_required, current_user
from flask_wtf import Form
from werkzeug.security import generate_password_hash, \
     check_password_hash
from wtforms import StringField, PasswordField, TextAreaField, SelectField
from wtforms.validators import DataRequired
from flask_principal import Principal, Identity, AnonymousIdentity, \
     identity_changed, Permission, RoleNeed, identity_loaded
from flask_admin.contrib.sqla import ModelView
from datetime import datetime, timedelta
import math
from zts import db, app, principal
import re
import logging
import config
from pyzabbix import ZabbixAPI

logger = logging.getLogger(config.ZTS_LOGGER_NAME)

user_area_assoc_table = db.Table('user_area', db.Model.metadata,
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('area_id', db.Integer, db.ForeignKey('area.id'))
)

ticket_close_permission = Permission(RoleNeed('ticket_close'))
admin_permission = Permission(RoleNeed('admin'))
report_permission = Permission(RoleNeed('report'))

class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(32), nullable=False)
    name = db.Column(db.Unicode(32))
    pwhash = db.Column(db.String(128))
    access_admin = db.Column(db.Boolean(), default=False, nullable=False)
    access_reports = db.Column(db.Boolean(), default=False, nullable=False)
    access_close = db.Column(db.Boolean(), default=False, nullable=False)
    active = db.Column(db.Boolean(), default=True, nullable=False)
    areas = db.relationship(
        "Area",
        secondary=user_area_assoc_table,
        back_populates="users")
    auth = False

    def is_authenticated(self):
        return self.auth

    def is_active(self):
        return self.active

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    def can_close(self):
        return self.access_close

    def is_admin(self):
        return self.access_admin

    def can_read_report(self):
        return self.access_reports

    def set_password(self, password):
        self.pwhash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.pwhash, password)

    def __str__(self):
        return 'User (%s)' % self.name

class Area(db.Model):
    __tablename__ = 'area'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode(32), nullable=False)
    users = db.relationship(
        "User",
        secondary=user_area_assoc_table,
        back_populates="areas")

    def __str__(self):
        return 'Area (%s)' % self.name

class Note(db.Model):
    __tablename__ = 'note'

    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text(2048), nullable=False)
    at = db.Column(db.DateTime, nullable=False)
    by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    by = db.relationship('User')
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'))
    ticket = db.relationship('Ticket')

class Ticket(db.Model):
    __tablename__ = 'ticket'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Unicode(255), nullable=False)
    text = db.Column(db.UnicodeText(2048))
    current_area_id = db.Column(db.Integer, db.ForeignKey('area.id'), nullable=False)
    current_area = db.relationship('Area')
    created_at = db.Column(db.DateTime, nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    owned_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    owned_by = db.relationship('User', foreign_keys=[owned_by_id])
    is_closed = db.Column(db.Boolean, default=False)
    zabbix_trigger_id = db.Column(db.Integer, default=0)
    last_change = db.Column(db.DateTime, nullable=False)
    events = db.relationship('TicketEvent', back_populates='ticket')

    def touch(self):
        self.last_change = datetime.now()

    def add_note(self, by, text):
        self.touch()
        note = Note(
            text = text,
            at = datetime.now(),
            by = by,
            ticket = self
        )
        db.session.add(note)

        note_event = TicketNoteAddedEvent(
            note = note,
            ticket = self,
            user = by,
            at = datetime.now(),
        )
        db.session.add(note_event)
        db.session.commit()

        logger.info(u'%s added note to ticket #%d' % (by.user, self.id))
        return note

    def take(self, by):
        self.touch()

        self.owned_by = by
        event = TicketTakeEvent(user=by, ticket=self, at=datetime.now())
        db.session.add(event)
        db.session.commit()

        logger.info(u'%s took ticket #%d' % (by.user, self.id))

    def transfer_to(self, by, to_area):
        self.touch()

        event = TicketAreaTransferEvent(
            user=by, 
            ticket=self, 
            to_area=to_area, 
            from_area=self.current_area,
            at=datetime.now())
        db.session.add(event)

        self.current_area = to_area
        self.owned_by = None

        db.session.commit()
        logger.info(u'%s transfered ticket #%d to %s' % (by.user, self.id, to_area.name))

    def close(self, by, reason):
        self.touch()

        self.is_closed = True
        
        event = TicketCloseEvent(user=by, ticket=self, at=datetime.now(), reason=reason)
        db.session.add(event)
        db.session.commit()

        logger.info(u'%s closed ticket #%d (%s)' % (by.user, self.id, reason.reason))

class TicketCloseReason(db.Model):
    __tablename__ = 'ticket_close_reason'
    id = db.Column(db.Integer, primary_key=True)
    reason = db.Column(db.UnicodeText(32), nullable=False)
    description = db.Column(db.UnicodeText(2048))

class Event(db.Model):
    __tablename__ = 'event'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User')
    at = db.Column(db.DateTime, nullable=False, default=datetime.now())
    type = db.Column(db.String(50))

    __mapper_args__ = {
        'polymorphic_identity':'event',
        'polymorphic_on':type
    }

    def __repr__(self):
        return 'Event'

class TicketEvent(Event):
    __tablename__ = 'event_ticket'
    id = db.Column(db.Integer, db.ForeignKey('event.id'), primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'))
    ticket = db.relationship('Ticket', back_populates='events')
    __mapper_args__ = {
        'polymorphic_identity':'event_ticket',
    }
    def __repr__(self):
        return 'TicketEvent'

class TicketNoteAddedEvent(TicketEvent):
    __tablename__ = 'event_ticket_note_added'
    id = db.Column(db.Integer, db.ForeignKey('event_ticket.id'), primary_key=True)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    note = db.relationship('Note')
    __mapper_args__ = {
        'polymorphic_identity':'event_ticket_note_added',
    }
    def __repr__(self):
        return 'TicketNoteAddedEvent'

class TicketAreaTransferEvent(TicketEvent):
    __tablename__ = 'event_ticket_area_transfer'
    id = db.Column(db.Integer, db.ForeignKey('event_ticket.id'), primary_key=True)
    from_area_id = db.Column(db.Integer, db.ForeignKey('area.id'))
    from_area = db.relationship('Area', foreign_keys=[from_area_id])
    to_area_id = db.Column(db.Integer, db.ForeignKey('area.id'), nullable=False)
    to_area = db.relationship('Area', foreign_keys=[to_area_id])
    __mapper_args__ = {
        'polymorphic_identity':'event_ticket_area_transfer',
    }
    def __repr__(self):
        return 'TicketAreaTransferEvent'

class TicketTakeEvent(TicketEvent):
    __tablename__ = 'event_ticket_take'
    id = db.Column(db.Integer, db.ForeignKey('event_ticket.id'), primary_key=True)
    __mapper_args__ = {
        'polymorphic_identity':'event_ticket_take',
    }
    def __repr__(self):
        return 'TicketTakeEvent'

class TicketCloseEvent(TicketEvent):
    __tablename__ = 'event_ticket_close'
    id = db.Column(db.Integer, db.ForeignKey('event_ticket.id'), primary_key=True)
    reason_id = db.Column(db.Integer, db.ForeignKey('ticket_close_reason.id'))
    reason = db.relationship('TicketCloseReason')
    __mapper_args__ = {
        'polymorphic_identity':'event_ticket_close',
    }
    def __repr__(self):
        return 'TicketCloseEvent'

class TicketReopenEvent(TicketEvent):
    __tablename__ = 'event_ticket_reopen'
    id = db.Column(db.Integer, db.ForeignKey('event_ticket.id'), primary_key=True)
    __mapper_args__ = {
        'polymorphic_identity':'event_ticket_reopen',
    }
    def __repr__(self):
        return 'TicketReopenEvent'

class LoginForm(Form):
    user = StringField('user', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])

class NoteForm(Form):
    text = TextAreaField('text', validators=[DataRequired()])

class TicketTransferForm(Form):
    area_id = SelectField(u'Area', coerce=int)

class TicketOpenForm(Form):
    title = StringField('title', validators=[DataRequired()])
    text = TextAreaField('text', validators=[DataRequired()])
    current_area_id = SelectField(u'Area', coerce=int, validators=[DataRequired()])

class ZtsModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin()

    def inaccessible_callback(self, name, **kwargs):
        # redirect to login page if user doesn't have access
        return redirect(url_for('index'))

class ZtsUserModelView(ZtsModelView):
    column_exclude_list = list = ('pwhash',)
    form_excluded_columns = ('pwhash',)
    form_extra_fields = {
        'password': PasswordField('Password')
    }
    def on_model_change(self, form, model, is_created):
        if len(model.password):
            model.set_password(model.password)
