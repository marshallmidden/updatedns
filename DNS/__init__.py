# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

__version__ = '3.0.1'

from . import Type
from . import Opcode
from . import Status
from . import Class
from .Base import DnsRequest
from .Base import DNSError
from .Lib import DnsResult
from .Base import *
from .Lib import *
Error = DNSError
Request = DnsRequest
Result = DnsResult

#-- Base._DiscoverNameServers()
