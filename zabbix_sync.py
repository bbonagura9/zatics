#!/usr/bin/python
# coding: utf-8

from pyzabbix import ZabbixAPI, ZabbixAPIException
from zts import app, login_manager, db
from zts.config import *
from zts.models import User, Ticket, Note, Area, LoginForm, NoteForm, \
	TicketAreaTransferEvent, Event, TicketTakeEvent, TicketCloseEvent, \
	TicketTransferForm, ticket_close_permission, TicketOpenForm, TicketReopenEvent
from datetime import datetime, timedelta
from flask import escape
from requests.adapters import ConnectionError
import logging, logging.handlers
import textwrap
import time
import sys
from pprint import pprint

priorities = [ u'Not classified', u'Info', u'Warning', u'Average', u'High', u'Disaster' ]

logger = logging.getLogger(ZTS_SYNC_LOGGER_NAME)
logger_handler = logging.handlers.RotatingFileHandler(ZTS_SYNC_LOGGER_FILE, mode='a', maxBytes=2**20, backupCount=5)
logger_formatter = logging.Formatter(ZTS_SYNC_LOG_FORMAT)
logger_handler.setFormatter(logger_formatter)
logger.addHandler(logger_handler)
logger.setLevel(logging.INFO)

zts_logger = logging.getLogger(ZTS_LOGGER_NAME)

try:
	current_user = db.session.query(User).filter(User.user == ZTS_SYNC_USER_NAME).one()
	ticket_open_area = db.session.query(Area).filter(Area.name == ZTS_SYNC_TICKET_OPEN_AREA_NAME).one()
except Exception as e:
	logger.error('Error while fetching sync user name and ticket open area.')
	logger.debug('Error details: %s' % str(e).replace('\n', ' '))

zapi = ZabbixAPI(ZTS_ZABBIX_API_ADDRESS)
zapi.login(*ZTS_ZABBIX_API_CREDENTIALS)

def handle_exception(exc_type, exc_value, exc_traceback):
	if issubclass(exc_type, KeyboardInterrupt):
		sys.__excepthook__(exc_type, exc_value, exc_traceback)
		exit(0)
	exc_info=(exc_type, exc_value, exc_traceback)
	logger.error("Uncaught exception: %s" % str(exc_info).replace('\n', ' '))

def get_triggers():
	""" Retorna os triggers relevantes à criação e existência de tickets 
		- Referente a hosts monitorados e não em manutenção
		- Descarta triggers dependentes
		- Com severidade mínima MIN_SEVERITY

		Para triggers de MCI e MOSU
		- Com última modificação no máximo até MINS_TO_OPEN_MMZ_TICKET minutos atrás

		Para triggers os demais
		- Com última modificação no máximo até MINS_TO_OPEN_TICKET minutos atrás
	"""
	common_params = dict(
		monitored=True, 
		min_severity=ZTS_SYNC_MIN_SEVERITY,
		expandData=True,
		only_true=True,
		expandDescription=True,
		expandComment=True,
		maintenance=ZTS_SYNC_MAINTENANCE,
		skipDependent=ZTS_SYNC_SKIP_DEPENDENT,
		output=['triggerid', 'description', 'comments', 'priority', 'lastchange', 'value'])

	triggers = filter(lambda t: int(t['value']) == 1, zapi.trigger.get(
		lastChangeTill=int(((datetime.utcnow() - timedelta(0, ZTS_SYNC_MINS_TO_OPEN_TICKET*60)) - datetime(1970,1,1)).total_seconds()),
		**common_params))

	logger.info('Fetching %d triggers.' % (len(triggers)))
	return triggers

def ticket_text(trigger):
	""" Retorna texto do ticket referente ao trigger """

	return escape(textwrap.dedent(u'''
		Comentários do trigger: {comments}
		Última modificação: {lastchange}
	''').strip().format(
		comments=unicode(trigger['comments']), 
		lastchange=datetime.fromtimestamp(int(trigger['lastchange'])).strftime('%d/%m/%Y %H:%M')
	))

def ticket_reopen(ticket):
	""" Faz a reabertura de um ticket fechado recentemente """
	ticket.reopen(current_user)

def ticket_update(ticket, trigger):
	""" Atualiza o título e texto de um ticket relativo ao trigger """
	ticket.title = unicode(priorities[int(trigger['priority'])] + ': ' + trigger['description'])
	ticket.text = ticket_text(trigger)
	logger.debug('Ticket #{ticket.id} found for this trigger and it is open (updated).'.format(**locals()))

def ticket_open(trigger):
	""" Abre um novo ticket referente ao trigger """
	newticket = Ticket(
		title = unicode(priorities[int(trigger['priority'])] + ': ' + trigger['description']),
		text = ticket_text(trigger),
		current_area = ticket_open_area,
		created_at = datetime.now(),
		created_by = current_user,
		last_change = datetime.now(),
		zabbix_trigger_id = int(trigger['triggerid']),
	)
	db.session.add(newticket)
	db.session.commit()
	zts_logger.info('Zabbix opened ticket #%d' % (newticket.id))

	logger.info('Opened ticket #{newticket.id} for trigger {trigger[triggerid]}'.format(**locals()))

def get_ticket_for_trigger(trigger):
	""" Retorna o ticket mais recente relativo a trigger, se existir """
	return 	db.session.query(Ticket) \
			.filter(Ticket.zabbix_trigger_id == int(trigger['triggerid'])) \
			.order_by(Ticket.last_change.desc()) \
			.first()

def check_supression():
	if ZTS_SYNC_SUPRESSION_IT_SERVICE_ID is None or ZTS_SYNC_SUPRESSION_IT_SERVICE_ID == '':
		return False

	s = zapi.service.get(serviceids=ZTS_SYNC_SUPRESSION_IT_SERVICE_ID, output=['status'])
	if len(s) == 0:
		logger.warning('Could not get IT service to check supression')
		return False

	if int(s[0]['status']) != 0:
		logger.warning('IT service seems down. Synchronization will be supressed.')
		return True

	return False

def main():
	sys.excepthook = handle_exception

	while True:
		try:
			logger.info('Running...')

			if not check_supression():
				for trigger in get_triggers():
					logger.debug('Verifying trigger {triggerdesc} (id={triggerid})'.format(
						triggerid=trigger['triggerid'], 
						triggerdesc=trigger['description'].encode('utf-8')
					))
					
					ticket = get_ticket_for_trigger(trigger)
					
					if ticket is not None:
						if ticket.is_closed:
							if (datetime.now() - ticket.last_change).days < ZTS_SYNC_DAYS_TO_REOPEN_TICKET:
								logger.info('Recent closed ticket #{ticket.id} found, reopening.'.format(**locals()))
								ticket_reopen(ticket)
							else:
								ticket_open(trigger)
						else:
							ticket_update(ticket, trigger)
					else:
						ticket_open(trigger)
				
				db.session.commit()
			else:
				logger.warning('Syncing supressed.')

			logger.debug('Sleeping for {} seconds'.format(ZTS_SYNC_EXECUTION_PERIOD))

			t = ZTS_SYNC_EXECUTION_PERIOD
			while t > 0:
				time.sleep(1)
				t = t - 1

		except ZabbixAPIException as e:
			logger.warning('Zabbix API exception: %s' % e.message)

		except ConnectionError:
			logger.warning('Connection Error, reconnecting...')

		except KeyboardInterrupt:
			logger.warning('Closing by user request.')

if __name__ == '__main__':
	main()
