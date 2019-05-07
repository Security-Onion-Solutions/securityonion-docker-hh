# Base config
import configparser

parser = configparser.ConfigParser()
parser.read('SOCtopus.conf')

filename = parser.get('log', 'logfile')


