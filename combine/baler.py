#!/usr/bin/env python
# -*- coding: utf-8 -*-
import ConfigParser
import datetime as dt
import gzip
import json
import os
import threading
import time
from logging import getLogger
from Queue import Queue

import requests
import unicodecsv
#import sqlalchemy
#from sqlalchemy.sql import table, column, select, update, insert
from sqlalchemy import *
from sqlalchemy.orm import create_session

logger = getLogger('baler')


def tiq_output(reg_file, enr_file):
    config = ConfigParser.SafeConfigParser()
    cfg_success = config.read('combine.cfg')
    if not cfg_success:
        logger.error('tiq_output: Could not read combine.cfg.')
        logger.error('HINT: edit combine-example.cfg and save as combine.cfg.')
        return

    tiq_dir = os.path.join(config.get('Baler', 'tiq_directory'), 'data')
    today = dt.datetime.today().strftime('%Y%m%d')

    with open(reg_file, 'rb') as f:
        reg_data = json.load(f)

    with open(enr_file, 'rb') as f:
        enr_data = json.load(f)
    logger.info('Preparing tiq directory structure under %s' % tiq_dir)
    if not os.path.isdir(tiq_dir):
        os.makedirs(os.path.join(tiq_dir, 'raw', 'public_inbound'))
        os.makedirs(os.path.join(tiq_dir, 'raw', 'public_outbound'))
        os.makedirs(os.path.join(tiq_dir, 'enriched', 'public_inbound'))
        os.makedirs(os.path.join(tiq_dir, 'enriched', 'public_outbound'))

    inbound_data = [row for row in reg_data if row['indicator_direction'] == 'inbound']
    outbound_data = [row for row in reg_data if row['indicator_direction'] == 'outbound']

    try:
        bale_reg_csvgz(inbound_data, os.path.join(tiq_dir, 'raw', 'public_inbound', today + '.csv.gz'))
        bale_reg_csvgz(outbound_data, os.path.join(tiq_dir, 'raw', 'public_outbound', today + '.csv.gz'))
    except:
        pass

    inbound_data = [row for row in enr_data if (row['indicator_direction'] == 'inbound' and row['indicator_type'] == 'IPv4')]
    outbound_data = [row for row in enr_data if (row['indicator_direction'] == 'outbound' and row['indicator_type'] == 'IPv4')]

    try:
        bale_enr_csvgz(inbound_data, os.path.join(tiq_dir, 'enriched', 'public_inbound', today + '.csv.gz'))
        bale_enr_csvgz(outbound_data, os.path.join(tiq_dir, 'enriched', 'public_outbound', today + '.csv.gz'))
    except:
        pass


# oh my god this is such a hack

def bale_reg_csvgz(harvest, output_file):
    """ bale the data as a gziped csv file"""
    logger.info('Output regular data as GZip CSV to %s' % output_file)
    with gzip.open(output_file, 'wb') as csv_file:
        bale_writer = unicodecsv.writer(csv_file, quoting=unicodecsv.QUOTE_ALL)

        # header row
        bale_writer.writerow(('entity', 'type', 'direction', 'source', 'notes', 'date'))
        for row in harvest:
            r = []
            for key in ['indicator', 'indicator_type', 'indicator_direction', 'source_name', 'note', 'date']:
                if key in row:
                    r.append(row[key])
                else:
                    r.append('')
            bale_writer.writerow(r)


def bale_reg_csv(harvest, output_file):
    """ bale the data as a csv file"""
    logger.info('Output regular data as CSV to %s' % output_file)
    with open(output_file, 'wb') as csv_file:
        bale_writer = unicodecsv.writer(csv_file, quoting=unicodecsv.QUOTE_ALL)

        # header row
        bale_writer.writerow(('entity', 'type', 'direction', 'source', 'notes', 'date'))
        for row in harvest:
            r = []
            for key in ['indicator', 'indicator_type', 'indicator_direction', 'source_name', 'note', 'date']:
                if key in row:
                    r.append(row[key])
                else:
                    r.append('')
            bale_writer.writerow(r)


def bale_enr_csv(harvest, output_file):
    """ output the data as an enriched csv file"""
    logger.info('Output enriched data as CSV to %s' % output_file)
    with open(output_file, 'wb') as csv_file:
        bale_writer = unicodecsv.writer(csv_file, quoting=unicodecsv.QUOTE_ALL)

        # header row
        bale_writer.writerow(('entity', 'type', 'direction', 'source', 'notes', 'date', 'url', 'domain', 'ip', 'asnumber', 'asname', 'country', 'hostname', 'ips', 'mx'))
        for row in harvest:
            r = []
            for key in ['indicator', 'indicator_type', 'indicator_direction', 'source_name', 'note', 'date', 'domain', 'ip', 'url']:
                if key in row:
                    r.append(row[key])
                else:
                    r.append('')
            try:
                for key in ['as_num', 'as_name', 'country', 'hostname', 'A', 'MX']:
                    if key in row['enriched']:
                        if key == 'A' or key == 'MX':
                            r.append("|".join(row['enriched'][key]))
                        else:
                            r.append(row['enriched'][key])
                    else:
                        r.append('')
            except:
            #if not row['enriched']:
                r += ['', '', '', '', '', '']
            bale_writer.writerow(r)


def bale_enr_csvgz(harvest, output_file):
    """ output the data as an enriched gziped csv file"""
    logger.info('Output enriched data as GZip CSV to %s' % output_file)
    with gzip.open(output_file, 'wb') as csv_file:
        bale_writer = unicodecsv.writer(csv_file, quoting=unicodecsv.QUOTE_ALL)

        # header row
        bale_writer.writerow(('entity', 'type', 'direction', 'source', 'notes', 'date', 'url', 'domain', 'ip', 'asnumber', 'asname', 'country', 'hostname', 'ips', 'mx'))
        for row in harvest:
            r = []
            for key in ['indicator', 'indicator_type', 'indicator_direction', 'source_name', 'note', 'date', 'domain', 'ip', 'url']:
                if key in row:
                    r.append(row[key])
                else:
                    r.append('')
            if not row['enriched']:
                r += ['', '', '', '', '', '']
            else:
                for key in ['as_num', 'as_name', 'country', 'hostname', 'A', 'MX']:
                    if key in row['enriched']:
                        if key == 'A' or key == 'MX':
                            r.append("|".join(row['enriched'][key]))
                        else:
                            r.append(row['enriched'][key])
                    else:
                        r.append('')
            bale_writer.writerow(r)


def bale_reg_cef(harvest, output_file):
    """ bale the data as a cef file"""
    logger.info('Output regular data as CEF to %s' % output_file)
    with open(output_file, 'wb') as cef_file:
        try:
            for row in harvest:
                r = []
                for key in ['indicator', 'indicator_type', 'indicator_direction', 'source_name', 'notes', 'date', 'domain', 'ip', 'url']:
                    if key in row:
                        r.append(row[key])
                    else:
                        r.append('')
                try:
                    for key in ['as_num', 'as_name', 'country', 'hostname', 'A', 'MX']:
                        if key in row['enriched']:
                            if key == 'A' or key == 'MX':
                                r.append("|".join(row['enriched'][key]))
                            else:
                                r.append(row['enriched'][key])
                        else:
                            r.append('')
                except:
                    r += ['', '', '', '', '', '']
                if r[1] == 'IPv4' or r[1] == 'IPv6':
                    cef_str = 'CEF:0|Combine|API|1.0|100|Known Malicious Host|1|src='+r[0]+' direction='+r[2]+' msg='+r[3]+' asnumber='+r[9]+' asname='+r[10]+' country='+r[11]+"\n"
                elif r[1] == 'FQDN':
                    cef_str = 'CEF:0|Combine|API|1.0|100|Known Malicious Domain|1|shost='+r[0]+' direction='+r[2]+' msg='+r[3]+"\n"
                elif r[1] == 'Subnet':
                    cef_str = 'CEF:0|Combine|API|1.0|100|Known Malicious Subnet|1|shost='+r[0]+' direction='+r[2]+' msg='+r[3]+"\n"
                else:
                    logger.debug("WARNING! unknow type: " + str(r))
		    continue
		cef_file.write(cef_str)

		import logging
		from logging.handlers import SysLogHandler
		import socket
		class ContextFilter(logging.Filter):
		  hostname = socket.gethostname()

		  def filter(self, record):
		        record.hostname = ContextFilter.hostname
			return True
		loggersyslog = logging.getLogger()
		loggersyslog.setLevel(logging.INFO)
		syslog = SysLogHandler(address='/dev/log')
		#syslog = logging.handlers.SysLogHandler(address = ('IP', PORT))
		#formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
		formatter = logging.Formatter('combine: %(message)s')
		syslog.setFormatter(formatter)
		loggersyslog.addHandler(syslog)
		loggersyslog.info(cef_str)
		## testing = do once to not flood syslog
                #break
        except Exception, e:
            logger.error("Error " + str(e) + " with r " + str(r))

def bale_enr_cef(harvest, output_file):
    """ output the data as an enriched CEF file"""
    logger.info('Output enriched data as CEF to %s' % output_file)
    bale_reg_cef(harvest, output_file)

def bale_CRITs_indicator(base_url, data, indicator_que):
    """ One thread of adding indicators to CRITs"""
    while not indicator_que.empty():
        indicator = indicator_que.get()
        if indicator['indicator_type'] == 'IPv4':
            # using the IP API
            url = base_url + 'ips/'
            data['add_indicator'] = "true"
            data['ip'] = indicator['indicator']
            data['ip_type'] = 'Address - ipv4-addr'
            # source = the actual URL and source_name = name in the plugin
            data['reference'] = indicator['source']
            if 'source_name' in indicator:
                data['source'] = indicator['source_name']
            res = requests.post(url, data=data, verify=False)
            if res.status_code not in [201, 200, 400]:
                logger.info("Issues with adding: %s" % data['ip'])
        elif indicator['indicator_type'] == "FQDN":
            # using the Domain API
            url = base_url + 'domains/'
            data['add_indicator'] = "true"
            data['domain'] = indicator['indicator']
            data['reference'] = indicator['source']
            if 'source_name' in indicator:
                data['source'] = indicator['source_name']
            res = requests.post(url, data=data, verify=False)
            if res.status_code not in [201, 200, 400]:
                logger.info("Issues with adding: %s" % data['domain'])
        else:
            logger.info("don't yet know what to do with: %s[%s]" % (indicator['indicator_type'], indicator['indicator']))


def bale_CRITs(harvest, filename):
    """ taking the output from combine and pushing it to the CRITs web API"""
    # checking the minimum requirements for parameters
    # it would be nice to have some metadata on the feeds that can be imported in the intel library:
    #   -> confidence
    #   -> type of feed (bot vs spam vs ddos, you get the picture)
    data = {'confidence': 'medium'}
    start_time = time.time()
    config = ConfigParser.SafeConfigParser()
    cfg_success = config.read('combine.cfg')
    if not cfg_success:
        logger.error('tiq_output: Could not read combine.cfg.\n')
        logger.error('HINT: edit combine-example.cfg and save as combine.cfg.\n')
        return
    if config.has_option('Baler', 'crits_username'):
        data['username'] = config.get('Baler', 'crits_username')
    else:
        raise 'Please check the combine.cnf file for the crits_username field in the [Baler] section'
    if config.has_option('Baler', 'crits_api_key'):
        data['api_key'] = config.get('Baler', 'crits_api_key')
    else:
        raise 'Please check the combine.cnf file for the crits_api_key field in the [Baler] section'
    if config.has_option('Baler', 'crits_campaign'):
        data['campaign'] = config.get('Baler', 'crits_campaign')
    else:
        logger.info('Lacking a campaign name, we will default to "combine." Errors might ensue if it does not exist in CRITs')
        data['campaign'] = 'combine'
    if config.has_option('Baler', 'crits_url'):
        base_url = config.get('Baler', 'crits_url')
    else:
        raise 'Please check the combine.cnf file for the crits_url field in the [Baler] section'
    if config.has_option('Baler', 'crits_maxThreads'):
        maxThreads = int(config.get('Baler', 'crits_maxThreads'))
    else:
        logger.info('No number of maximum Threads has been given, defaulting to 10')
        maxThreads = 10

    data['source'] = 'Combine'
    data['method'] = 'trawl'

    # initializing the Queue to the list of indicators in the harvest
    ioc_queue = Queue()
    for indicator in harvest:
        ioc_queue.put(indicator)
    total_iocs = ioc_queue.qsize()

    for x in range(maxThreads):
        th = threading.Thread(target=bale_CRITs_indicator, args=(base_url, data, ioc_queue))
        th.start()

    for x in threading.enumerate():
        if x.name == "MainThread":
            continue
        x.join()

    logger.info('Output %d indicators to CRITs using %d threads. Operation tool %d seconds\n' %
                (total_iocs, maxThreads, time.time() - start_time))

def bale_reg_sql0(harvest, output_file):
    """ bale the data as a sql file"""
    logger.info('Output regular data as SQL to %s' % output_file)
    engine = create_engine(output_file)
    metadata = MetaData(bind=engine)
    table = 'harvest'
    fields = ['indicator', 'indicator_type', 'indicator_direction', 'source_name', 'notes', 'date']

    ## create table if not existing
    t = Table(table, metadata,
        Column('indicator', String(100), primary_key=True),
        Column('indicator_type', String(10), primary_key=True),
        Column('indicator_direction', String(10)),
        Column('source_name', String(30)),
#        Column('notes', String(100)),
        Column('date', String(20), primary_key=True),
        )
    t.create(checkfirst=True)
    mytable = Table(table, metadata, autoload=True)

    session = create_session(bind=engine)
    for row in harvest:
        #values = [ row['indicator'], row['indicator_type'], row['indicator_direction'], row['source_name'], row['notes'], row['date'] ]
        values = [ row['indicator'], row['indicator_type'], row['indicator_direction'], row['source_name'], row['date'] ]
        i = insert(table)
	print table
	print values
        i = i.values(values)
        print row
        print str(i)
        session.execute(i)
        #print "INSERT INTO %s (%s) VALUES (%s);" % (table, [ row['indicator'], row['indicator_type'], row['indicator_direction'], row['source_name'], row['note'], row['date'] ], values)

def bale_reg_sql(harvest, output_file):
    """ bale the data as a sql file"""
    logger.info('Output regular data as SQL to %s' % output_file)
    engine = create_engine(output_file)
    res1 = engine.execute("create table if not exists harvest(indicator varchar(128), indicator_type varchar(32), indicator_direction varchar(8), source_name varchar(32), notes varchar(128), date timestamp, PRIMARY KEY (indicator,source_name,date) )")
    table = 'harvest'
    fields = ['indicator', 'indicator_type', 'indicator_direction', 'source_name', 'notes', 'date']

    for row in harvest:
        #values = [ row['indicator'], row['indicator_type'], row['indicator_direction'], row['source_name'], row['notes'], row['date'] ]
        values = [ row['indicator'], row['indicator_type'], row['indicator_direction'], row['source_name'], '', row['date'] ]
        try:
            ## IMPROVE? fail gracefully on primary key. http://www.postgresql.org/message-id/CAD8_UcYgTcg7ZTjuOzt8hbFGLjFgrbHpCAW6aU=CprC7sUD6fw@mail.gmail.com
            res2 = engine.execute("insert into harvest values('%s', '%s', '%s', '%s', '%s', '%s')" % (row['indicator'], row['indicator_type'], row['indicator_direction'], row['source_name'], '', row['date']))
            #res2 = engine.execute("insert into harvest values('%s', '%s', '%s', '%s', '%s', '%s')" % (row['indicator'], row['indicator_type'], row['indicator_direction'], row['source_name'], row['notes'], row['date']))
        except Exception, e:
            print "Exception: " + str(e)
            import os, sys, traceback
            print '-'*60
            traceback.print_exc(file=sys.stdout)
            print '-'*60

def bale_enr_sql(harvest, output_file):
    """ output the data as an enriched sql file"""
    logger.info('Output enriched data as SQL to %s' % output_file)
    engine = create_engine(output_file)
    res1 = engine.execute("create table if not exists harvest_enr(indicator varchar(128), indicator_type varchar(32), indicator_direction varchar(8), source_name varchar(32), notes varchar(128), date timestamp, url varchar(256), domain varchar(256), ip varchar(15), asnumber varchar(10), asname varchar(128), country varchar(8), hostname varchar(256), ips varchar(256), mx varchar(256), PRIMARY KEY (indicator,source_name,date) )")

    for row in harvest:
            r = []
            for key in ['indicator', 'indicator_type', 'indicator_direction', 'source_name', 'note', 'date', 'domain', 'ip', 'url']:
                if key in row:
                    r.append(row[key])
                else:
                    r.append('')
            try:
                for key in ['as_num', 'as_name', 'country', 'hostname', 'A', 'MX']:
                    if key in row['enriched']:
                        if key == 'A' or key == 'MX':
                            r.append("|".join(row['enriched'][key]))
                        else:
                            r.append(row['enriched'][key])
                    else:
                        r.append('')
            except:
                r += ['', '', '', '', '', '']
            try:
                ## IMPROVE? fail gracefully on primary key. http://www.postgresql.org/message-id/CAD8_UcYgTcg7ZTjuOzt8hbFGLjFgrbHpCAW6aU=CprC7sUD6fw@mail.gmail.com
                #res2 = engine.execute("insert into harvest_enr values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::integer, %s, %s, %s, %s, %s)", r)
                res2 = engine.execute("insert into harvest_enr values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", r)
            except Exception, e:
                print "Exception on " + row['indicator'] + ": " + str(e)
#                import os, sys, traceback
#                print '-'*60
#                traceback.print_exc(file=sys.stdout)
#                print '-'*60
#                break


def bale(input_file, output_file, output_format, is_regular):
    config = ConfigParser.SafeConfigParser()
    cfg_success = config.read('combine.cfg')
    if not cfg_success:
        logger.error('Baler: Could not read combine.cfg.')
        logger.error('HINT: edit combine-example.cfg and save as combine.cfg.')
        return

    logger.info('Reading processed data from %s' % input_file)
    with open(input_file, 'rb') as f:
        harvest = json.load(f, encoding='utf8')

    # TODO: also need plugins here (cf. #23)
    if is_regular:
        format_funcs = {'csv': bale_reg_csv, 'crits': bale_CRITs, 'cef' : bale_reg_cef, 'sql' : bale_reg_sql }
    else:
        format_funcs = {'csv': bale_enr_csv, 'crits': bale_CRITs, 'cef' : bale_enr_cef, 'sql' : bale_enr_sql }
    logger.info('Output %s to %s, format %s' % (input_file, output_file, output_format))
    format_funcs[output_format](harvest, output_file)


def main():
    #bale('crop.json', 'harvest.csv', 'csv', True)
    bale('enriched.json', 'harvest.csv', 'csv', False)
    #bale('enriched.json', 'harvest.cef', 'cef', False)
    #bale('crop.json', 'sqlite:///harvest.sqlite', 'sql', True)
    #bale('crop.json', 'postgresql://combine:combine@localhost:5432/harvest', 'sql', True)
    bale('enriched.json', 'postgresql://combine:combine@localhost:5432/harvest', 'sql', False)

