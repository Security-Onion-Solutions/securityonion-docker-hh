# Base config
import configparser

parser = configparser.ConfigParser()
parser.read('SOCtopus.conf')

filename = parser.get('log', 'logfile')
es_index = parser.get('es', 'es_index_pattern', fallback='so-*')

