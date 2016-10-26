#!/usr/bin/python
# coding: utf-8

from flask import Flask, redirect, current_app, request, session, render_template, flash, url_for, request, escape
from flask_sqlalchemy import SQLAlchemy
import flask_sqlalchemy
from flask_login import LoginManager, login_user, logout_user, \
     login_required, current_user
from flask_wtf import Form
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired
from flask_principal import Principal, Identity, AnonymousIdentity, \
     identity_changed, identity_loaded, RoleNeed
from sqlalchemy import func, distinct, desc
from jinja2 import evalcontextfilter, Markup, escape
from sqlalchemy.sql.expression import func, or_, and_
from datetime import datetime, timedelta, date
import math
import logging
import ldap
import re
import subprocess
from itertools import dropwhile
from zts import app, login_manager, db, admin
from zts.models import User, Ticket, Note, Area, LoginForm, NoteForm, \
    TicketAreaTransferEvent, Event, TicketTakeEvent, TicketCloseEvent, \
    TicketTransferForm, ticket_close_permission, report_permission, admin_permission, \
    TicketOpenForm, TicketReopenEvent, TicketNoteAddedEvent, TicketCloseReason, \
    ZtsModelView, ZtsUserModelView
import config
from pyzabbix import ZabbixAPI
from pprint import pformat,pprint

logger = logging.getLogger(config.ZTS_LOGGER_NAME)

admin.add_view(ZtsUserModelView(User, db.session))
admin.add_view(ZtsModelView(Area, db.session))
admin.add_view(ZtsModelView(TicketCloseReason, db.session))

def timedelta_str(td):
    values = [
        ('y', str(td.days / 365)),
        ('m', str((td.days % 365) / 31)),
        ('d', str(td.days % 31)),
        ('h', str(td.seconds / 3600)),
        ('min', str((td.seconds % 3600) / 60)),
        ('s', str(td.seconds % 60))
    ]

    v = [ x[1]+x[0] for x in filter(lambda v: v[1] != '0', values) ]

    if len(v) >= 2:
        return v[0] + ' ' + v[1]
    elif len(v) == 1:
        return v[0]
    else:
        return '<1s'

@app.template_filter()
@evalcontextfilter
def day_short(eval_ctx, dt):
    dt_date = date(dt.year, dt.month, dt.day)
    if dt_date == date.today():
        return 'Today'

    if dt_date == date.today() - timedelta(1):
        return 'Yesterday'

    return dt.strftime('%d/%m/%y')


@app.template_filter()
@evalcontextfilter
def nl2br(eval_ctx, value):
    result = value.replace('\n', '<br>')
    if eval_ctx.autoescape:
        result = Markup(result)
    return result

@app.context_processor
def geral_context():
    orphans_count = 0
    if current_user.is_authenticated:
        orphans_count = db.session.query(Ticket). \
                        filter(
                            Ticket.owned_by == None, 
                            Ticket.is_closed == False, 
                            Ticket.current_area_id.in_([ a.id for a in current_user.areas ])) \
                        .count()

    return dict(orphans_count=orphans_count, loginForm=LoginForm())

@login_manager.user_loader
def load_user(userid):
    # Return an instance of the User model
    return db.session.query(User).get(userid)

@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    # Set the identity user object
    if hasattr(identity, 'user'):
        identity.user = current_user

    # Add the UserNeed to the identity
    if hasattr(current_user, 'access_admin') and current_user.is_admin():
        identity.provides.add(RoleNeed('admin'))
    if hasattr(current_user, 'can_read_report') and current_user.can_read_report():
        identity.provides.add(RoleNeed('report'))
    if hasattr(current_user, 'can_close') and current_user.can_close():
        identity.provides.add(RoleNeed('ticket_close'))


@app.route('/')
def index():
    zapi = ZabbixAPI(config.ZTS_ZABBIX_API_ADDRESS)
    zapi.login(*config.ZTS_ZABBIX_API_CREDENTIALS) 

    overview = []

    return render_template('overview.html', overview=overview)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        try:
            user = db.session.query(User).filter(User.user == form.user.data).one()
            if not user.check_password(form.password.data):
                raise flask_sqlalchemy.orm.exc.NoResultFound()

            # Keep the user info in the session using Flask-Login
            login_user(user)
            user.auth = True

            # Tell Flask-Principal the identity changed
            identity_changed.send(current_app._get_current_object(),
                                  identity=Identity(user.id))

            logger.info(u'%s logged in' % user.user)
            flash(u'Login success! Welcome.', 'success')
        except flask_sqlalchemy.orm.exc.NoResultFound:
            logger.warning(u'User %s not found on DB for login attempt' % form.user.data)
            flash(u'Invalid user or password', 'danger')
    return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    u = current_user.user

    # Remove the user information from the session
    logout_user()

    # Remove session keys set by Flask-Principal
    for key in ('identity.name', 'identity.auth_type'):
        session.pop(key, None)

    # Tell Flask-Principal the user is anonymous
    identity_changed.send(current_app._get_current_object(),
                          identity=AnonymousIdentity())

    logger.info(u'%s logged out' % u)
    flash(u'Logged out', 'success')
    return redirect(url_for('index'))

def render_ticket_list(query, title, query_zabbix=True):
    TICKETS_PER_PAGE = config.ZTS_TICKETS_PER_PAGE
    page = int(request.args.get('page', 1))

    my_areas_id = [ a.id for a in current_user.areas ]
    query = query.filter(Ticket.current_area_id.in_(my_areas_id))

    total_pages = int(math.ceil(float(query.count()) / TICKETS_PER_PAGE))
    tickets = query.order_by(Ticket.last_change.desc())\
                   .offset((page-1)*TICKETS_PER_PAGE)\
                   .limit(TICKETS_PER_PAGE)\
                   .all()

    pagination_range = range(max(1, page-5), min(total_pages, page+5)+1)

    trigger_values = dict()
    if query_zabbix:
        zapi = ZabbixAPI(config.ZTS_ZABBIX_API_ADDRESS)
        zapi.login(*config.ZTS_ZABBIX_API_CREDENTIALS) 

        triggerids = filter(lambda n: n is not None and n > 0, [ ticket.zabbix_trigger_id for ticket in tickets ])
        triggers = zapi.trigger.get(triggerids=triggerids, output=['value'])
        trigger_values = dict([ (int(trigger['triggerid']), int(trigger['value'])) for trigger in triggers ])

    return render_template('ticket_list.html', 
                            tickets=tickets, 
                            pagination={ 'page': page, 'total': total_pages }, 
                            pagination_range=pagination_range,
                            ticket_list_title=title,
                            trigger_values=trigger_values)

@app.route('/ticket/list/orphans')
@login_required
def ticket_list_orphans():
    q = db.session.query(Ticket).filter(Ticket.owned_by == None, Ticket.is_closed == False)
    return render_ticket_list(q, u'Orphan tickets')

@app.route('/ticket/list/mine')
@login_required
def ticket_list_mine():
    q = db.session.query(Ticket).filter(Ticket.owned_by == current_user, Ticket.is_closed == False)
    return render_ticket_list(q, u'My tickets')

@app.route('/ticket/list/area/<int:area_id>')
@login_required
def ticket_list_area(area_id):
    area = db.session.query(Area).filter(Area.id == area_id).one()
    ticket_list_title = u'Tickets (%s)' % area.name
    if area not in current_user.areas:
        flash(u'You cannot list tickets from an area you don\'t belong.', 'danger')
        return redirect(url_for('index'))
    q = db.session.query(Ticket).filter(Ticket.current_area == area, Ticket.is_closed == False)
    return render_ticket_list(q, ticket_list_title)

@app.route('/ticket/list/closed')
@login_required
def ticket_list_closed():
    q = db.session.query(Ticket).filter(Ticket.is_closed == True)
    return render_ticket_list(q, u'Closed tickets', False)

@app.route('/ticket/show/<int:ticket_id>')
@login_required
def ticket_show(ticket_id):
    ticket = db.session.query(Ticket).filter(Ticket.id == ticket_id).one_or_none()

    if ticket is None:
        flash(u'Invalid ticket', 'danger')
        return redirect(url_for('index'))
    
    transfer_form = TicketTransferForm()
    transfer_form.area_id.choices = [(a.id, a.name) for a in db.session.query(Area).all()]
    transfer_form.area_id.default = ticket.current_area.id
    transfer_form.process()

    areas = db.session.query(Area).all()

    trigger_value = None
    host_triggers = []
    if ticket.zabbix_trigger_id is not None and ticket.zabbix_trigger_id > 0:
        zapi = ZabbixAPI(config.ZTS_ZABBIX_API_ADDRESS)
        zapi.login(*config.ZTS_ZABBIX_API_CREDENTIALS)
        triggers = zapi.trigger.get(
            triggerids=ticket.zabbix_trigger_id, 
            selectHosts=['hostid'],
            output=['value'])

        if len(triggers):
            trigger_value = int(triggers[0]['value'])
        
            host_triggers = zapi.trigger.get(
                hostids=triggers[0]['hosts'][0]['hostid'], 
                only_true=True,
                expandDescription=True,
                output=['description', 'value', 'priority', 'lastchange'])

            host_triggers = filter(lambda t: int(t['triggerid']) != ticket.zabbix_trigger_id, host_triggers)
            for host_trigger in host_triggers:
                t = db.session.query(Ticket.id) \
                    .filter(
                        Ticket.zabbix_trigger_id == int(host_trigger['triggerid']), 
                        Ticket.is_closed == False) \
                    .one_or_none()
                host_trigger['ticket_id'] = t.id if t is not None else None

            for trigger in host_triggers:
                trigger['age'] = timedelta_str(datetime.now() - datetime.fromtimestamp(int(trigger['lastchange'])))

    my_area = ticket.current_area_id in [ a.id for a in current_user.areas ]
    close_reasons = db.session.query(TicketCloseReason).all()

    logger.info(u'%s viewed ticket #%d' % (current_user.user, ticket.id))
    return render_template('ticket_show.html', 
                ticket=ticket, 
                areas=areas, 
                noteform=NoteForm(), 
                transfer_form=transfer_form, 
                show_close=current_user.can_close(),
                close_reasons=close_reasons,
                trigger_value=trigger_value,
                my_area=my_area,
                host_triggers=host_triggers)

@app.route('/ticket/newnote/<int:ticket_id>',  methods=['POST'])
@login_required
def ticket_newnote(ticket_id):
    form = NoteForm()

    if form.validate_on_submit():
        ticket = db.session.query(Ticket).filter(Ticket.id == ticket_id).one_or_none()
        ticket.add_note(current_user, escape(form.text.data))
        flash(u'Note added successfully.', 'success')
    
    return redirect(url_for('ticket_show', ticket_id=ticket_id))

@app.route('/ticket/take/<int:ticket_id>')
@login_required
def ticket_take(ticket_id):
    ticket = db.session.query(Ticket).filter(Ticket.id == ticket_id).one()

    if ticket.current_area not in current_user.areas:
        flash(u'You cannot take a ticket that is not in an area you belong.', 'danger')
        return redirect(url_for('ticket_show', ticket_id=ticket_id))

    ticket.take(current_user)
    flash(u'The ticket was taken.', 'success')
    
    return redirect(url_for('ticket_show', ticket_id=ticket_id))

@app.route('/ticket/transfer/<int:ticket_id>')
@login_required
def ticket_transfer(ticket_id):
    ticket = db.session.query(Ticket).get(ticket_id)
    area_id = request.args.get('area_id', '1')
    area = db.session.query(Area).get(area_id)
    
    ticket.transfer_to(current_user, area)
    flash(u'Ticket transfered to %s.' % area.name, 'success')
    
    return redirect(url_for('ticket_show', ticket_id=ticket_id))

@app.route('/ticket/close/<int:ticket_id>/<int:reason_id>')
@login_required
@ticket_close_permission.require()
def ticket_close(ticket_id, reason_id):
    ticket = db.session.query(Ticket).get(ticket_id)
    reason = db.session.query(TicketCloseReason).get(reason_id)
    ticket.close(current_user, reason)
    flash(u'Ticket closed.', 'success')

    return redirect(url_for('ticket_show', ticket_id=ticket_id))

@app.route('/ticket/open', methods=['GET', 'POST'])
@login_required
def ticket_open():
    form = TicketOpenForm()
    form.current_area_id.choices = [(a.id, a.name) for a in current_user.areas]

    if form.validate_on_submit():
        newticket = Ticket(
            title = escape(form.title.data),
            text = escape(form.text.data),
            current_area_id = form.current_area_id.data,
            created_at = datetime.now(),
            created_by = current_user,
            owned_by = current_user,
            last_change = datetime.now(),
        )
        db.session.add(newticket)
        db.session.commit()
        logger.info('%s opened ticket #%d' % (current_user.user, newticket.id))

        return redirect(url_for('ticket_show', ticket_id=newticket.id))

    return render_template('ticket_open.html', form=form)

@app.route('/report/tickets_per_area')
@login_required
@report_permission.require()
def report_tickets_per_area():
    tickets_per_area = []
    count_func = func.count(distinct(TicketAreaTransferEvent.ticket_id))
    res = db.session.query(TicketAreaTransferEvent, count_func) \
                    .group_by(TicketAreaTransferEvent.to_area_id).order_by(count_func).all()
    for event, count in res:
        tickets_per_area.append((event.to_area.name, count))
    return render_template('report_ticket_per_area.html', tickets_per_area=tickets_per_area)

@app.route('/report/tickets_totals')
@login_required
@report_permission.require()
def report_tickets_totals():
    qtickets = db.session.query(Ticket)
    total_tickets = qtickets.count()
    closed_tickets = qtickets.filter(Ticket.is_closed == True).count()
    return render_template('report_tickets_totals.html', 
                            total_tickets=total_tickets,
                            closed_tickets=closed_tickets)

@app.route('/report/tickets_per_weekday')
@login_required
@report_permission.require()
def report_tickets_per_weekday():
    tr_weekday = [ u'Sunday', u'Monday', u'Tuesday', u'Wednesday', u'Thursday', u'Friday', u'Saturday' ]
    tickets_per_weekday = zip(tr_weekday, [0]*7)
    res = db.session.query(func.dayofweek(Ticket.created_at), func.count(Ticket.id)) \
                    .group_by(func.dayofweek(Ticket.created_at)) \
                    .order_by(func.dayofweek(Ticket.created_at))

    total_tickets = 0
    for dayofweek, tcount in res:
        tickets_per_weekday[dayofweek-1] = (tr_weekday[dayofweek-1], tcount)
        total_tickets = total_tickets + tcount

    return render_template('report_tickets_per_weekday.html', 
                            tickets_per_weekday=tickets_per_weekday,
                            total_tickets=total_tickets)

@app.route('/report/tickets_close_reason')
@login_required
@report_permission.require()
def report_tickets_close_reason():
    tickets_close_reason = []
    closed_tickets = db.session.query(TicketCloseEvent).count()
    res = db.session.query(TicketCloseEvent, func.count(TicketCloseEvent.id)) \
                    .group_by(TicketCloseEvent.reason_id) \
                    .all()
    for event, count in sorted(res, key=lambda r: r[1], reverse=True):
        tickets_close_reason.append(
            (event.reason.reason, count, 100*float(count)/closed_tickets)
        )

    return render_template('report_tickets_close_reason.html', 
                            tickets_close_reason=tickets_close_reason)

@app.route('/report/recent_log')
@login_required
@report_permission.require()
def report_recent_log():
    def parse_log_item(item_text):
        tr_severity_class = {
            'CRITICAL': 'danger',
            'ERROR': 'danger',
            'WARNING': 'warning',
            'INFO': 'info',
            'DEBUG': 'success',
        }

        text_arr = item_text.split()
        log_datetime = text_arr[0]  + ' ' + text_arr[1].split(',')[0]
        log_severity = text_arr[2]
        log_text = ' '.join(text_arr[3:])

        return {
            'at': datetime.strptime(log_datetime, '%Y-%m-%d %H:%M:%S'),
            'class': tr_severity_class.get(log_severity, ''),
            'severity': log_severity,
            'text': log_text.decode('utf-8'),
        }

    log_items = subprocess.check_output(['tail','-n100',config.ZTS_LOG_FILE]).strip().split('\n')
    log_items = filter(lambda s: re.match(r'^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}', s), log_items)
    log_items.reverse()

    return render_template('report_recent_log.html', log_items=map(parse_log_item, log_items))

@app.route('/report/log_overview')
@login_required
@report_permission.require()
def report_log_overview():
    def parse_entry_per_day_result(result):
        res_arr = result.strip().split()
        return (datetime.strptime(res_arr[1], '%Y-%m-%d'), int(res_arr[0]))

    entries_per_day_arr = subprocess.check_output('''
       cat {log_path} {log_path}.* | grep -E '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}' | grep -v Zabbix | cut -d' ' -f1 | sort | uniq -c
    '''.format(log_path=config.ZTS_LOG_FILE), shell=True).strip().split('\n')
    entries_per_day = sorted(
        filter(
            lambda e: (datetime.now() - e[0]).days <= 60,
            map(parse_entry_per_day_result , entries_per_day_arr)
        ),
        key=lambda e: e[0]
    )

    user_list = dict(db.session.query(User.user, User.name).all())
    entries_per_user_arr = subprocess.check_output('''
        cat {log_path} {log_path}.* | grep -E "^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}" | cut -d' ' -f4 | sort | uniq -c
    '''.format(log_path=config.ZTS_LOG_FILE), shell=True).strip().split('\n')
    entries_per_user = sorted(
        filter(
            lambda e: e[0] != 'Zabbix' and e[0] != 'Invalid',
            map(lambda e: (user_list.get(e.strip().split()[1], 'Invalid'), int(e.strip().split()[0])), entries_per_user_arr)
        ),
        key=lambda e: e[1],
        reverse=True
    )

    return render_template(
        'report_log_overview.html', 
        entries_per_user=entries_per_user,
        entries_per_day=entries_per_day   
    )

@app.route('/report/daily')
@login_required
@report_permission.require()
def report_daily():
    def filter_notes(note):
        if not note.at > mindate:
            return False
        if not note.by.name != 'Zabbix':
            return False
        filtered_prefixes = [
            'Transferido para',
            'Assumi ticket',
            'Ticket aberto',
        ]
        if reduce(lambda a,b: a or note.text.startswith(b), filtered_prefixes, False):
            return False
        return True

    result = []
    now = datetime.now()
    mindate = datetime(now.year, now.month, now.day)
    tickets = db.session.query(Ticket).filter(Ticket.last_change > mindate).all()
    for ticket in tickets:
        actions = [ (n.at, n.by.name, n.text) for n in filter(filter_notes, ticket.notes)]
        if ticket.created_at > mindate:
            actions.append((ticket.created_at, ticket.created_by.name, 'Ticket aberto'))
        
        # actions.extend([ 
        #     (e.at, e.user.name, 'Ticket fechado') 
        #     for e in db.session.query(TicketCloseEvent).filter(TicketCloseEvent.ticket_id == ticket.id, TicketCloseEvent.at > mindate)
        # ])
        actions.extend([
            (e.at, e.user.name, 'Ticket reaberto') 
            for e in db.session.query(TicketReopenEvent).filter(TicketReopenEvent.ticket_id == ticket.id, TicketReopenEvent.at > mindate)
        ])

        actions.sort(key=lambda a: a[0])
        
        if len(actions) > 0:
            result.append({
                'id': ticket.id,
                'title': ticket.title,
                'actions': actions
            })

    return render_template('report_daily.html', report=result)

@app.route('/report/stats')
@login_required
@report_permission.require()
def report_stats():
    query = db.session.query(Ticket, func.count(Ticket.id)).filter(Ticket.is_closed == False).group_by(Ticket.current_area_id)
    area_ticket_count = [ (r[0].current_area.name, r[1]) for r in query ]

    tickets_opened_today = 0
    n = db.session.query(func.count(distinct(TicketReopenEvent.id))) \
        .filter(func.to_days(TicketReopenEvent.at) == func.to_days(func.now())) \
        .group_by(func.to_days(TicketReopenEvent.at)).scalar() or 0
    tickets_opened_today = tickets_opened_today + n

    n = db.session.query(func.count(Ticket.id)) \
        .filter(func.to_days(Ticket.created_at) == func.to_days(func.now())) \
        .group_by(func.to_days(Ticket.created_at)).scalar() or 0
    tickets_opened_today = tickets_opened_today + n

    n = db.session.query(func.count(TicketCloseEvent.id)) \
        .filter(func.to_days(TicketCloseEvent.at) == func.to_days(func.now())) \
        .group_by(func.to_days(TicketCloseEvent.at)).scalar() or 0
    tickets_closed_today = n

    return render_template('report_stats.html', 
                            area_ticket_count=area_ticket_count, 
                            tickets_opened_today=tickets_opened_today, 
                            tickets_closed_today=tickets_closed_today,
                            now=datetime.now())