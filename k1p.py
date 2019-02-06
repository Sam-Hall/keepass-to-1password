#!/usr/bin/env python

import os
import logging

import ConfigParser
import argparse
from jinja2 import Environment, PackageLoader
from bs4 import BeautifulSoup
from datetime import datetime

# Helper
def normalize(s):
  return '"%s"' % s.replace('"', '""')

# Setup logging
script_name = os.path.splitext(os.path.basename(__file__))[0]
logging.basicConfig()
logger = logging.getLogger(script_name)
logger.setLevel(logging.DEBUG)

# Parse command line options
parser = argparse.ArgumentParser(
    description='Converts KeePass XML file to 1Password CSV')
parser.add_argument('--version', action='version', version='%(prog)s 0.1.0')
args = parser.parse_args()

# Read config file
config = ConfigParser.SafeConfigParser()
config.read(os.path.join('etc', script_name + '.conf'))

passwords_xml = BeautifulSoup(open(config.get('General', 'input')),'lxml')
logger.info('KeePass XML file is opened')
timestamp = datetime.today().isoformat()
thisYear = int(timestamp[:4])
lastKPC = int(timestamp[:4])
lastKPM = int(timestamp[:4])
lastKPA = int(timestamp[:4])

passwords = []

for entry in passwords_xml.find_all('entry'):
  password = {}

  parentNode = entry.parent
  password['folder'] = ''
  password['path'] = ''

  # If this entry is in a <Group> node get the full path (ignoring the root folder)
  if parentNode.name == 'group':
    parentGroup = ''
    # Traverse back to <Root> node to get the full path for the entry...
    while parentNode.parent.name != 'root':
      parentName = parentNode.find_all('name', recursive=False)
      if parentName and not parentName[0].string:
        parentGroup = 'null' # Keypass allows nameless folders
      elif parentName:
        parentGroup = parentName[0].string
      else:
        parentGroup = ''
      if parentGroup != '':
        password['path'] = parentGroup + '\\' + password['path']
        parentNode = parentNode.parent
        if password['folder'] == '':
          password['folder'] = parentGroup
      else:
        break

  # Ignore password history entries...
  if parentNode.name != 'history':
    migrationNote = 'Keepass migration: '+timestamp
    if entry.times:
      # Extract some audit meta-data
      audit = entry.times
      ctime = audit.creationtime.string
      mtime = audit.lastmodificationtime.string
      atime = audit.lastaccesstime.string
      migrationNote += '\nCreation: '+ctime
      migrationNote += '\nModification: '+mtime
      migrationNote += '\nLast access: '+atime
      migrationNote += '\n#KPC'+ctime[:4]+' #KPM'+mtime[:4]+' #KPA'+atime[:4]
      if int(ctime[:4]) < lastKPC:
        lastKPC = int(ctime[:4])
      if int(mtime[:4]) < lastKPM:
        lastKPM = int(mtime[:4])
      if int(atime[:4]) < lastKPA:
        lastKPA = int(atime[:4])

    # Grab all the key/value pairs...
    for kvp in entry.find_all('string', recursive=False):
      if kvp.value.string:
        password[kvp.key.string.lower()]=kvp.value.string
      else:
        password[kvp.key.string.lower()]=''

    # Append migration note
    if password['notes']:
      password['notes'] += '\n\n' + migrationNote
    else:
      password['notes'] = migrationNote

    # Set the entry title to the username if title was omitted in Keepass...
    if not password['title']:
      password['title'] = password['username']

    # Append the folder name to the entry title...
    if password['folder'] != '':
      password['title'] = password['folder'] + ' - ' + password['title']

    # Double quote the strings ready for CSV output...
    for k in password.keys():
      password[k] = normalize(password[k])

    passwords.append(password)

# Prepare output file
env = Environment(loader=PackageLoader('__main__', 'templates'))
template = env.get_template('passwords.tmpl')
output = open(config.get('General', 'output'), 'w')
output.write(template.render(passwords = passwords).encode('utf-8'))
output.close()

logger.info('1Password CSV file is written')
if lastKPC < thisYear:
  logger.info('Oldest passwords created in '+str(lastKPC))
if lastKPM < thisYear:
  logger.info('Oldest passwords modified in '+str(lastKPM))
if lastKPA < thisYear:
  logger.info('Some passwords that haven''t been accessed since '+str(lastKPA))