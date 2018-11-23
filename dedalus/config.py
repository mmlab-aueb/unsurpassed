# GENERAL CONFIGURATION
CLIENT_PROTO = b'MNPC01'  #: Client protocol identifier
WORKER_PROTO = b'MNPW01'  #: Worker protocol identifier
CONSUMER_PROTO = b'MNPK01'  #: Kafka consumer protocol identifier
M_BROKER = 'broker'
M_WORKER = 'worker'
M_CLIENT = 'client'
S_BROKER = b'Broker'
S_WORKER = b'Worker'
S_CLIENT = b'Client'
S_CONSUMER = b'Consumer'
S_KAFKAINTERFACE = b'KafkaInterface'

S_SUDO = 'raspberry\n'

THROUGHPUT_BUFSIZE = 1024

HB_INTERVAL = 5000  #: Heartbeat interval in milliseconds
HB_RETRIES = 5      #: Heartbeat retries before quiting

DEFAULT_INTEFACE = 'wboard'     # 'wboard'  # The interface used by the underlying ad hoc network
CONTROL_INTERFACE = 'wdongle'    # 'wdongle' The interface used by the control network

# MSG TYPES
MSG_READY = b'\x01'
MSG_QUERY = b'\x02'
MSG_REPLY = b'\x03'
MSG_HEARTBEAT = b'\x04'
MSG_DISCONNECT = b'\x05'

# BROKER COMMANDS
MSG_WINFO = b'br01'
MSG_PCHANGE = b'br02'
MSG_PAVAILABLE = b'br03'

# WORKER COMMANDS
MSG_WDUMP = b'wr01'

# HW SCANNER COMMANDS
MSG_ECHO = b'hs01'
MSG_CPUPERCENT = b'hs02'
MSG_CPUTIMES = b'hs03'
MSG_CPUTIMESPERCENT = b'hs04'
MSG_CPUCOUNT = b'hs05'
MSG_CPUSTATS = b'hs06'
MSG_NETIOCOUNTERS = b'hs07'
MSG_NETCONNECTIONS = b'hs08'
MSG_NETIFADDRS = b'hs09'
MSG_NETIFSTATS = b'hs10'
MSG_BOOTTIME = b'hs11'
MSG_MEMORYINFO = b'hs12'
MSG_MEMORYPERCENT = b'hs13'
MSG_CONNECTIONS = b'hs14'
MSG_DUMP = b'hs15'
MSG_REBOOT_HOST = b'hs16'

# TG COMMANDS
MSG_SENDTRAFFIC = b'tg01'
MSG_STOPSENDINGTRAFFIC = b'tg02'
MSG_MEASUREBANDWIDTH = b'tg03'
MSG_TXPOWER = b'tg04'
MSG_DTNFILE = b'tg05'
MSG_PINGTEST = b'tg06'
MSG_ICNFILE = b'tg07'

# NET MANAGEMENT COMMANDS
MSG_SETPROTO = b'nm01'
MSG_NETRESTART = b'nm02'
MSG_ROUTINGINFO = b'nm03'
MSG_NETSTART = b'nm04'
MSG_NETSTOP = b'nm05'
MSG_DTNSTART = b'nm06'
MSG_DTNRESTART = b'nm07'
MSG_DTNSTOP = b'nm08'
MSG_CURRENTRPROTO = b'nm09'
MSG_CURRENTDPROTO = b'nm10'
MSG_SETDTNPROTO = b'nm11'
MSG_ICNSTART= b'nm12'
MSG_ICNRESTART= b'nm13'
MSG_ICNSTOP= b'nm14'

# TODO: review these
# BABEL SCANNER COMMANDS
MSG_FLUSH = b'pb01'
MSG_DUMP_B = b'pb02'
MSG_MONITOR = b'pb03'
MSG_UNMONITOR = b'pb04'

# WORKER TYPES
WK_TYPE_BROKER = b'00'
WK_TYPE_PC = b'01'
WK_TYPE_UMV = b'02'
WK_TYPE_UAV = b'03'
WK_TYPE_FOREIGN = b'04'

# WORKER STATUS
WORKER_OFFLINE_STATUS = b'lost'
WORKER_ONLINE_STATUS = b'online'
WORKER_BUSY_STATUS = b'busy'
WORKER_INACTIVE_STATUS = b'inactive'
WORKER_FOREIGN_STATUS = b'foreign'

# ROUTING PROTOCOLS
# TODO: review these
ROUTING_BABEL = b'rp01'                 # commands
ROUTING_BATMAN = b'rp02'
ROUTING_BMX = b'rp03'
ROUTING_IBR = b'dp01'
N_BABEL = 'babeld'                      # names
N_BATMAN = 'batman'
N_BMX = 'bmx7'
N_IBR = 'dtnd'
N_CCN = 'ccn'
PROTOCOL_MODULES = {                    # modules
    N_BABEL: 'scanner_babel',
    N_BATMAN: 'scanner_batman',
    N_BMX: 'scanner_bmx',
    N_IBR: 'scanner_ibr',
    N_CCN: 'scanner_ccn'
}
ALL_PROTOCOLS = [N_BABEL, N_BATMAN, N_BMX]
DEFAULT_ROUTING_PROTOCOL = N_BABEL

# SERVICES
SERVICE_ECHO = b'echo'
SERVICE_BROKER = b'broker'

# KAFKA
BROKER_TOPIC = 'dedalus_broker'
MULTICAST_TOPIC = 'unsurpassed'
K_GROUP = 'unsurpassed'
