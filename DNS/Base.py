# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

import socket, string, types, time, select
from . import Type,Class,Opcode

# This random generator is used for transaction ids and port selection.  This
# is important to prevent spurious results from lost packets, and malicious
# cache poisoning.  This doesn't matter if you are behind a caching nameserver
# or your app is a primary DNS server only. To install your own generator,
# replace DNS.Base.random.  SystemRandom uses /dev/urandom or similar source.  

try:
  from random import SystemRandom
  random = SystemRandom()
except:
  import random

class DNSError(Exception): pass
class ArgumentError(DNSError): pass
class SocketError(DNSError): pass
class TimeoutError(DNSError): pass

class ServerError(DNSError):
    def __init__(self, message, rcode):
        DNSError.__init__(self, message, rcode)
        self.message = message
        self.rcode = rcode

class IncompleteReplyError(DNSError): pass

# Lib uses some of the above exception classes, so import after defining.
from . import Lib

defaults= { 'protocol':'udp', 'port':53, 'opcode':Opcode.QUERY,
            'qtype':Type.A, 'rd':1, 'timing':1, 'timeout': 30, 'server_rotate': 0,
            'server': [] }

def ParseResolvConf(resolv_path="/etc/resolv.conf"):
    "parses the /etc/resolv.conf file and sets defaults for name servers"
    global defaults
    lines=open(resolv_path).readlines()
    for line in lines:
        line = line.strip()
        if not line or line[0]==';' or line[0]=='#':
            continue
        fields=line.split()
        if len(fields) < 2: 
            continue
        if fields[0]=='domain' and len(fields) > 1:
            defaults['domain']=fields[1]
        if fields[0]=='search':
            pass
        if fields[0]=='options':
            pass
        if fields[0]=='sortlist':
            pass
        if fields[0]=='nameserver':
            defaults['server'].append(fields[1])

class DnsRequest:
    """ high level Request object """
    def __init__(self,*name,**args):
        self.donefunc=None
        self.defaults = {}
        self.argparse(name,args)
        self.defaults = self.args
        self.tid = 0

    def argparse(self,name,args):
        if not name and 'name' in self.defaults:
            args['name'] = self.defaults['name']
        if type(name) is bytes or type(name) is str:
            args['name']=name
        else:
            if len(name) == 1:
                if name[0]:
                    args['name']=name[0]
        if defaults['server_rotate'] and \
                type(defaults['server']) == types.ListType:
            defaults['server'] = defaults['server'][1:]+defaults['server'][:1]
        for i in list(defaults.keys()):
            if i not in args:
                if i in self.defaults:
                    args[i]=self.defaults[i]
                else:
                    args[i]=defaults[i]
        if type(args['server']) == bytes or type(args['server']) == str:
            args['server'] = [args['server']]
        self.args=args

    def socketInit(self,a,b):
        self.s = socket.socket(a,b)

    def processUDPReply(self):
        if self.timeout > 0:
            r,w,e = select.select([self.s],[],[],self.timeout)
            if not len(r):
                raise TimeoutError('Timeout')
        (self.reply, self.from_address) = self.s.recvfrom(65535)
        self.time_finish=time.time()
        self.args['server']=self.ns
        return self.processReply()

    def _readall(self,f,count):
      res = f.read(count)
      while len(res) < count:
        if self.timeout > 0:
            # should we restart timeout everytime we get a dribble of data?
            rem = self.time_start + self.timeout - time.time()
            if rem <= 0: raise DNSError('Timeout')
            self.s.settimeout(rem)
        buf = f.read(count - len(res))
        if not buf:
          raise DNSError('incomplete reply - %d of %d read' % (len(res),count))
        res += buf
      return res

    def processTCPReply(self):
        if self.timeout > 0:
            self.s.settimeout(self.timeout)
        else:
            self.s.settimeout(None)
        f = self.s.makefile('rb')
        try:
            header = self._readall(f,2)
            count = Lib.unpack16bit(header)
            self.reply = self._readall(f,count)
        finally:
            f.close()
        self.time_finish=time.time()
        self.args['server']=self.ns
        return self.processReply()

    def processReply(self):
        self.args['elapsed']=(self.time_finish-self.time_start)*1000
        u = Lib.Munpacker(self.reply)
        r=Lib.DnsResult(u,self.args)
        r.args=self.args
        return r

    def getSource(self):
        "Pick random source port to avoid DNS cache poisoning attack."
        while True:
            try:
                source_port = random.randint(1024,65535)
                self.s.bind(('', source_port))
                break
            except socket.error as msg: 
                # Error 98, 'Address already in use'
                if msg[0] != 98: raise

    def conn(self):
        self.getSource()
        self.s.connect((self.ns,self.port))

    def req(self,*name,**args):
        " needs a refactoring "
        self.argparse(name,args)
        protocol = self.args['protocol']
        self.port = self.args['port']
        self.tid = random.randint(0,65535)
        self.timeout = self.args['timeout'];
        opcode = self.args['opcode']
        rd = self.args['rd']
        server=self.args['server']
        if type(self.args['qtype']) == bytes or type(self.args['qtype']) == str:
            try:
                qtype = getattr(Type, str(self.args['qtype'].upper()))
            except AttributeError:
                raise ArgumentError('unknown query type')
        else:
            qtype = self.args['qtype']
        if 'name' not in self.args:
            print((self.args))
            raise ArgumentError('nothing to lookup')
        qname = self.args['name']
        if qtype == Type.AXFR and protocol != 'tcp':
            print('Query type AXFR, protocol forced to TCP')
            protocol = 'tcp'
        m = Lib.Mpacker()
        m.addHeader(self.tid,
              0, opcode, 0, 0, rd, 0, 0, 0,
              1, 0, 0, 0)
        m.addQuestion(qname, qtype, Class.IN)
        self.request = m.getbuf()
        try:
            if protocol == 'udp':
                self.sendUDPRequest(server)
            else:
                self.sendTCPRequest(server)
        except socket.error as reason:
            raise SocketError(reason)
        return self.response

    def sendUDPRequest(self, server):
        "refactor me"
        first_socket_error = None
        self.response=None
        for self.ns in server:
            try:
                if self.ns.count(':'):
                    if hasattr(socket,'has_ipv6') and socket.has_ipv6:
                        self.socketInit(socket.AF_INET6, socket.SOCK_DGRAM)
                    else: continue
                else:
                    self.socketInit(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    self.time_start=time.time()
                    self.conn()
                    self.s.send(self.request)
                    r=self.processUDPReply()
                    while r.header['id'] != self.tid        \
                            or self.from_address[1] != self.port:
                        r=self.processUDPReply()
                    self.response = r
                finally:
                    self.s.close()
            except socket.error as e:
                first_socket_error = first_socket_error or e
                continue
        if not self.response and first_socket_error:
            raise first_socket_error

    def sendTCPRequest(self, server):
        " do the work of sending a TCP request "
        first_socket_error = None
        self.response=None
        for self.ns in server:
            try:
                if self.ns.count(':'):
                    if hasattr(socket,'has_ipv6') and socket.has_ipv6:
                        self.socketInit(socket.AF_INET6, socket.SOCK_STREAM)
                    else: continue
                else:
                    self.socketInit(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    self.time_start=time.time()
                    self.conn()
                    buf = Lib.pack16bit(len(self.request))+self.request
                    self.s.setblocking(0)
                    self.s.sendall(buf)
                    r=self.processTCPReply()
                    if r.header['id'] == self.tid:
                        self.response = r
                        break
                finally:
                    self.s.close()
            except socket.error as e:
                first_socket_error = first_socket_error or e
                continue
        if not self.response and first_socket_error:
            raise first_socket_error
