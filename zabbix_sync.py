#!/usr/bin/python
# coding: utf-8

from pyzabbix import ZabbixAPI, ZabbixAPIException
from pst2 import app, login_manager, db
from pst2.models import User, Ticket, Note, Area, LoginForm, NoteForm, \
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

priorities = [ u'Não classificada', u'Informação', u'Atenção', u'Média', u'Alta', u'Desastre' ]

MIN_SEVERITY = 3 #médio
MINS_TO_OPEN_TICKET = 30
MINS_TO_OPEN_MMZ_TICKET = 5
MINS_TO_CLOSE_TICKET = 30
DAYS_TO_REOPEN_TICKET = 7
EXECUTION_PERIOD = 200 #seconds
ZBX_API_ADDRESS = 'http://10.52.152.115/zabbix'
ZBX_API_CREDENTIALS = ('apiuser', 'bolachachavecelularmonitorcoca')
CLOSE_REASON_VALUE = u'6'
LOG_FORMAT = '%(asctime)-15s %(levelname)s %(message)s'

logger = logging.getLogger('zabbix_sync_logger')
logger_handler = logging.handlers.RotatingFileHandler('/home/zabbix/pst2/zabbix_sync.log', mode='a', maxBytes=2**20, backupCount=5)
logger_formatter = logging.Formatter(LOG_FORMAT)
logger_handler.setFormatter(logger_formatter)
logger.addHandler(logger_handler)
logger.setLevel(logging.INFO)

pst_logger = logging.getLogger('pst_logger')

current_user = db.session.query(User).filter(User.user == u'Zabbix').one()
helpdesk_area = db.session.query(Area).filter(Area.name == u'Helpdesk').one()
controle_area = db.session.query(Area).filter(Area.name == u'Controle').one()

zapi = ZabbixAPI(ZBX_API_ADDRESS)
zapi.login(*ZBX_API_CREDENTIALS)

def is_controle_area(trigger):
	""" Descobre se um trigger é relativo a um ticket que deve ser aberto na área controle """
	return False
	#return trigger['description'].startswith('MCI')

def handle_exception(exc_type, exc_value, exc_traceback):
	if issubclass(exc_type, KeyboardInterrupt):
		sys.__excepthook__(exc_type, exc_value, exc_traceback)
		return
	logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

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
		min_severity=MIN_SEVERITY,
		expandData=True,
		only_true=True,
		expandDescription=True,
		expandComment=True,
		maintenance=False,
		skipDependent=True,
		output=['triggerid', 'description', 'comments', 'priority', 'lastchange', 'value'])

	triggers = filter(lambda t: int(t['value']) == 1, zapi.trigger.get(
		lastChangeTill=int(((datetime.utcnow() - timedelta(0, MINS_TO_OPEN_TICKET*60)) - datetime(1970,1,1)).total_seconds()),
		**common_params))

	recent_triggers_ids = set([ t['triggerid'] for t in triggers ])
	mosu_triggers = filter(lambda t: int(t['value']) == 1, zapi.trigger.get(
		lastChangeTill=int(((datetime.utcnow() - timedelta(0, MINS_TO_OPEN_MMZ_TICKET*60)) - datetime(1970,1,1)).total_seconds()),
		search={'description': 'MOSU'},
		**common_params))
	mci_triggers = filter(lambda t: int(t['value']) == 1, zapi.trigger.get(
		lastChangeTill=int(((datetime.utcnow() - timedelta(0, MINS_TO_OPEN_MMZ_TICKET*60)) - datetime(1970,1,1)).total_seconds()),
		search={'description': 'MCI'},
		**common_params))

	triggers.extend(filter(lambda t: t['triggerid'] not in recent_triggers_ids, mosu_triggers))
	triggers.extend(filter(lambda t: t['triggerid'] not in recent_triggers_ids, mci_triggers))

	logger.info('Fetching %d triggers (%d mosu, %d mci).' % (len(triggers), len(mosu_triggers), len(mci_triggers)))
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

	ticket.is_closed = False
	ticket.last_change = datetime.now()
	ticket.owned_by = None
	ticket.current_area_id = helpdesk_area.id

	ticket.notes.append(Note(
		text = u'Ticket reaberto por retorno do alerta',
		at = datetime.now(),
		by = current_user,
		ticket = ticket,
	))

	event = TicketReopenEvent(user=current_user,ticket=ticket,at=datetime.now())
	db.session.add(event)

	pst_logger.info('Zabbix reopened ticket #%d' % (ticket.id))

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
		current_area = controle_area if is_controle_area(trigger) else helpdesk_area,
		created_at = datetime.now(),
		created_by = current_user,
		last_change = datetime.now(),
		zabbix_trigger_id = int(trigger['triggerid']),
	)
	db.session.add(newticket)
	db.session.commit()
	pst_logger.info('Zabbix opened ticket #%d' % (newticket.id))

	event = TicketAreaTransferEvent(user=current_user, ticket=newticket, to_area=newticket.current_area)
	db.session.add(event)
	logger.info('Opened ticket #{newticket.id} for trigger {trigger[triggerid]}'.format(**locals()))

def ticket_close(ticket):
	""" Fecha um ticket """
	#ticket.is_closed = True
	#ticket.close_reason = CLOSE_REASON_VALUE
	ticket.last_change = datetime.now()

	#event = TicketCloseEvent(user=current_user, ticket=ticket, at=datetime.now())
	#db.session.add(event)

	ticket.notes.append(Note(
		text = u'Ticket fechado por restabelecimento do status correto.',
		at = datetime.now(),
		by = current_user,
		ticket = ticket,
	))

	pst_logger.info('Zabbix closed ticket #%d' % (ticket.id))

def get_ticket_for_trigger(trigger):
	""" Retorna o ticket mais recente relativo a trigger, se existir """
	return 	db.session.query(Ticket) \
			.filter(Ticket.zabbix_trigger_id == int(trigger['triggerid'])) \
			.order_by(Ticket.last_change.desc()) \
			.first()

def check_supression():
	s = zapi.service.get(serviceids='37', output=['status'])
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
							if (datetime.now() - ticket.last_change).days < DAYS_TO_REOPEN_TICKET:
								logger.info('Recent closed ticket #{ticket.id} found, reopening.'.format(**locals()))
								ticket_reopen(ticket)
							else:
								ticket_open(trigger)
						else:
							ticket_update(ticket, trigger)
					else:
						ticket_open(trigger)
				
				db.session.commit()

				# tickets = db.session.query(Ticket).filter(
				# 	Ticket.is_closed == False, 
				# 	Ticket.owned_by == None, 
				# 	Ticket.zabbix_trigger_id != None).all()
				# logger.info('Verifying %d tickets.' % (len(tickets)))
				# for ticket in tickets:
				# 	logger.debug('Verifying ticket #{ticket.id} for trigger {ticket.zabbix_trigger_id}'.format(**locals()))
					
				# 	trigger = zapi.trigger.get(
				# 		triggerids=ticket.zabbix_trigger_id,
				# 		lastChangeTill=int(((datetime.utcnow() - timedelta(0, MINS_TO_CLOSE_TICKET*60)) - datetime(1970,1,1)).total_seconds()),
				# 		filter={'value': '0'},
				# 		output=['triggerid', 'value', 'lastchange'])

				# 	if len(trigger) != 0:
				# 		logger.info('Trigger has been in OK state longer than %d minutes (since %s), closing ticket #%d.' % (MINS_TO_CLOSE_TICKET, datetime.fromtimestamp(int(trigger[0]['lastchange'])).strftime('%Y-%m-%d %H:%M:%S'), ticket.id))
				# 		ticket_close(ticket)

				# db.session.commit()

			logger.debug('Sleeping for {} seconds'.format(EXECUTION_PERIOD))

			t = EXECUTION_PERIOD
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
