#!/usr/bin/python3
#-----------------------------------------------------------------------------
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
#-----------------------------------------------------------------------------
# Not Done Yet -- 2020-09-28 -- not really needed for normal Parsec Labs usage.
    #-- change     - change from one IP address to another.
    #-- mx         - set MX record.
    #-- cname      - set CNAME record to another name.
    #-- txt        - set TXT record for name.

# The argparse routine prints following triple quote as part of help message.
'''
Add or remove entries from the dynamic DNS @ 172.22.1.2.

Note: Commands may be abbreviated to uniqueness. Example: "r" for "remove".

Synopsis: (May be abbreviated to uniqueness...)
    add        - Add to DNS name and IP pair(s). Remove old one(s) and add these.
    remove     - Remove from DNS name and/or IP (multiple allowed).
    delete     - alias for remove.
    show       - show all IP and A for arguments.
    exit       - exit interactive mode.
    quit       - alias for exit.

Examples:
    updateDNS.py add hello 172.22.14.200    # parsec.lab:hello A 172.22.14.200
                                              14.22.172.in-addr.arpa:200 PTR hello.parsec.lab.
    updateDNS.py delete hello
    updateDNS.py remove 172.22.14.200
    updateDNS.py add *.hello 172.22.14.200  # parsec.lab:hello A 172.22.14.200
                                                         $ORIGIN m4-14-22.parsec.lab.
                                                         *     A 172.22.14.200
                                              14.22.172.in-addr.arpa:200 PTR hello.parsec.lab.
    updateDNS.py show *.hello 172.22.14.200  # parsec.lab:hello A 172.22.14.200
'''
#-----------------------------------------------------------------------------
# Modules to include for program.
import argparse                             # Process arguments.
import os                                   # O/S routines - directory paths ...
import re                                   # Regular expression matching.
import readline                             # Command line history and editing.
import rlcompleter                          # Completion function for readline.
import shlex                                # Simple lexical analysis.
import subprocess                           # Run commands in a subprocess.
import sys                                  # O/S values, routines, etc.
import termios                              # POSIX style tty control - single character, etc.
# Use the tab key for completion.
if sys.platform == 'darwin':
    readline.parse_and_bind ("bind ^I rl_complete")
else:
    readline.parse_and_bind("tab: complete")
# fi
#-----------------------------------------------------------------------------
global SERVER, RECURSIVE, TIMEOUT
# Nameserver to use by default.
SERVER = '172.22.1.2'
#-- SERVER = '172.22.1.4'
# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
# If cached, okay - else RECURSION == 1 means ask next nameserver outwards.
RECURSIVE = 0
#-- RECURSIVE = 1
# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
# Seconds to wait for timeout. Quick is good. :)
TIMEOUT = 3
FULLDOMAIN = "parsec.lab"
NSUPDATE= ("/usr/bin/nsupdate", "-k", "rndc.key", "-v")

HIST_FILE = os.path.join(os.path.expanduser("~"), ".updateDNS_history")
#-----------------------------------------------------------------------------
class dnsCompleter:
    def __init__(self, options):
        self.options = options
        self.current_candidates = []
        return

    def complete(self, text, state):
        if state == 0:
            # This is the first time for this text -- build possible match list.
            origline = readline.get_line_buffer().rstrip()
            line = origline.lstrip()
            delta = len(origline) - len(line)
            begin = readline.get_begidx() - delta
            end = readline.get_endidx() - delta
            being_completed = line[begin:end]
            words = line.split()

            if not words:                   # If no starting word, all are possible.
                self.current_candidates = sorted(self.options)
            else:
                try:
                    if begin != 0:          # If first character of first word.
                        # later word        # No autofill for other arguments.
                        return None
                    # fi
                    # first word
                    candidates = self.options
                    if being_completed:
                        # Match with portion of input already typed.
                        self.current_candidates = [ w for w in candidates if w.startswith(being_completed) ]
                    else:
                        # Matching empty string, use all possible input.
                        self.current_candidates = candidates
                    # fi
                except (KeyError, IndexError) as err:
                    self.current_candidates = []
                # yrt
            # fi
        # fi
        try:
            response = self.current_candidates[state]
        except IndexError:
            response = None
        # yrt
        return response
#-----------------------------------------------------------------------------
def run_command(cmd, inp=''):
    result = None
    try:
        # capture_output in result.stdout.
        # capture_stderr in result.stderr.
        # check for non-zero exit code -- try/except.
        # input = string of bytes

        #-- result = subprocess.run(                # python > 3.5
        #--                         cmd,
        #--                         capture_output=True, text=True,
        #--                         input=inp,
        #-- )
        result = subprocess.check_output(
                                   cmd,
                                   universal_newlines=True,
                                   input=inp,
                                   stderr=subprocess.STDOUT,
                               )
    except:
        print("Error running executable {} - {}".format(cmd, sys.exc_info()[0]))
    # ytr
    #-- if not result:              # python > 3.5
    if result and result.stdout:
        print("stdout:\n{}".format(result.stdout))
    # fi
    if result and result.stderr:
        print("stderr:\n{}".format(result.stderr))
    # fi
# End of run_command

#=============================================================================
import DNS
#=============================================================================
#-- def print_r(s, r):
#--     def print_type(s, r, what):
#--         t = r.__dict__[what]
#--         print('{0:5} type(r.{1:11}={2}'.format(s, what + ')', type(t)))
#--         print('           r.{0:11}={1}'.format(what, t))
#--     # End of print_type
#-- 
#--     r.show()
#--     print_type(s, r, 'header')
#--     print_type('', r, 'questions')
#--     print_type('', r, 'answers')
#--     print_type('', r, 'authority')
#--     print_type('', r, 'additional')
#--     # print_type('', r, 'args')
#-- # End of print_r

#=============================================================================
def send_dns_request(n, q='A', s=[SERVER], t=TIMEOUT, r=RECURSIVE, err=None):
    # . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
    def bitfield(q, w, p):
        vs = None
        done = False
        maxlen = len(w)
        while not done:
            length = w[p]
            if ((length & 0xc0) >> 6) == 3:
                # Pointer -- we do not wish to handle pointers.
                done = True
                continue
            # fi
            if length == 0:
                # zero length, ignore.
                done = True
                continue
            # fi

            p = p + 1
            if (p+length) > maxlen:
               length = maxlen - p;
            # fi
            s = str(w[p:p+length], "utf-8")
            if not vs:
                vs = s
            else:
                vs = vs + '.' + s
            # fi
            p = p + length
            if p >= maxlen:
                done = True
            # fi
        # elihw
        return vs
    # End of bitfield
    # . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
    # Process send_dns_request follows.
    try:
        r = DNS.DnsRequest(name=n, qtype=q, server=s, timeout=t, rd=r).req()
    except DNS.Base.TimeoutError:
        print("Timeout sending DNS request to nameserver {}".format(s))
        print("   {} of type {}".format(n, q))
        print(" ... exiting immediately ...")
        sys.exit(1)
    except:
        if err:
            print("Error {} occurred during processing {} of {} from nameserver {}".format(sys.exc_info()[0], q, n, s))
            sys.exit(1)
        # fi
    # yrt
    if r.header['status'] != 'NOERROR':
        if err:
            print("Error getting {} of {} from nameserver {}".format(q, n, nameserver))
        # fi
        return None
    # fi
    vstr = []
    for x in r.answers:
        if x['type'] == DNS.Type.A:           # 1     a host address
            v = int.from_bytes(x['data'], byteorder='big', signed=False)
            vs = str(v>>24 & 0xFF) +'.'+ str(v>>16 & 0xFF) +'.'+ str(v>>8 & 0xFF) +'.'+ str(v & 0xFF)
            vstr.append(vs)
        elif x['type'] == DNS.Type.NS:        # 2     an authoritative name server
            vs = x['data']
            vstr.append(vs)
        elif x['type'] == DNS.Type.MD:        # 3     MD (obsolete)
            print("Not handled type MD:", x['type'])
        elif x['type'] == DNS.Type.MF:        # 4     MF (obsolete)
            print("Not handled type MF:", x['type'])
        elif x['type'] == DNS.Type.CNAME:     # 5     Canonical name - alias
            # -- Ignore CNAME types during A/MX/TXT processing.
            if q == 'A' or q == 'MX' or q == 'TXT' or q == 'NS' or q == 'MD' or q == 'MF':
                continue
            # fi
            if q == 'SOA' or q == 'MB' or q == 'MG' or q == 'MR' or q == 'NULL' or q == 'WKS':
                continue
            # fi
            if q == 'HINFO' or q == 'MINFO' or q == 'AAAA' or q == 'SRV' or q == 'SPF' or q == 'UNAME':
                continue
            # fi
            w = x['data']
            vs = bitfield(q, w, 0)
            if vs:
                vstr.append(vs)
            # fi
        elif x['type'] == DNS.Type.SOA:       # 6     marks the start of a zone of authrity
            vs = x['data']
            vstr.append(vs)
        elif x['type'] == DNS.Type.MB:        # 7     experimental
            print("Not handled type MB:", x['type'])
        elif x['type'] == DNS.Type.MG:        # 8     experimental
            print("Not handled type MG:", x['type'])
        elif x['type'] == DNS.Type.MR:        # 9     experimental
            print("Not handled type MR:", x['type'])
        elif x['type'] == DNS.Type.NULL:      # 10    experimental
            print("Not handled type NULL:", x['type'])
        elif x['type'] == DNS.Type.WKS:       # 11    Well Known Service description
            print("Not handled type WKS:", x['type'])
        elif x['type'] == DNS.Type.PTR:       # 12    A domain name pointer
            vs = x['data']
            vstr.append(vs)
        elif x['type'] == DNS.Type.HINFO:   # 13    Host information
            print("Not handled type HINFO:", x['type'])
        elif x['type'] == DNS.Type.MINFO:   # 14    Mailbox of mail list information
            print("Not handled type MINFO:", x['type'])
        elif x['type'] == DNS.Type.MX:      # 15    mail exchange
            w = x['data']
            vs = bitfield(q, w, 2)
            if vs:
                vstr.append(vs)
            # fi
        elif x['type'] == DNS.Type.TXT:     # 16    Text strings
            w = x['data']
            vs = bitfield(q, w, 0)
            if vs:
                vstr.append(vs)
            # fi
        # ... nothing in between ...
        elif x['type'] == DNS.Type.AAAA:    # 28    Text strings
            print("Not handled type AAAA (IPV6 mapping):", x['type'])
        # ... nothing in between ...
        elif x['type'] == DNS.Type.SRV:     # 33    DNS RR for specifying service location (rfc 2782)
            print("Not handled type SRV:", x['type'])
        # ... nothing in between ...
        elif x['type'] == DNS.Type.SPF:     # 99    TXT RR for Send Policy Framework
            print("Not handled type SPF:", x['type'])
        # ... nothing in between ...
        elif x['type'] == DNS.Type.UNAME:   # 110
            print("Not handled type UNAME:", x['type'])
        # ... nothing in between ...
        elif x['type'] == DNS.Type.MP:      # 240
            print("Not handled type MP:", x['type'])
        else:
            print("Not handled type:", x['type'])
        # fi
    # rof

    if not vstr:
        if err:
            print("Nothing found {} of {} from nameserver {}".format(q, n, nameserver))
        # fi
        return None
    # fi
    return vstr
# End of send_dns_request

#=============================================================================

# Getting PTR is special. Provide IP in normal format. Reverse it, etc.
def PTR(nameserver, ip, err=None):
    if not ip[0].isdigit():
        return None
    # fi
    a = ip.split('.')
    for A in a:
        if not A.isdigit():
            return None
        # fi
    # rof
    a.reverse()
    revip = '.'.join(a) + '.in-addr.arpa'
    names = send_dns_request(revip, 'PTR', nameserver)
    return names
# End of PTR

#=============================================================================
# This routine debugs above routines - probably want normal RECURSIVE nameserver.
def debug_routines():
    ip_list = ( "10.99.23.13", "127.0.0.1", "192.35.59.45", "192.189.54.17", 
                "8.8.8.8", "49.156.18.125", "204.79.197.212", "216.92.156.164", 
                "202.29.151.3", "208.43.65.50", "210.8.232.1", "172.22.14.10", 
                "172.22.1.140", )

    a_list =  ( "han.{}".format(FULLDOMAIN),
                "m4-14-10.{}".format(FULLDOMAIN),
                "jenkins.{}".format(FULLDOMAIN),
                "cdns01.comcast.net", "cdns02.comcast.net", "cloudflare.com.",
                "connect.com.au", "www.example.org.", "google.com", "www.google.com.",
                "he.net.", "www.he.net.", "hotmail.com", "iana.org.", "www.iana.org.",
                "ianawww.vip.icann.org.", "kitterman.com", "mailout03.controlledmail.com",
                "munnari.oz.au", "proxy.connect.com.au", )

    T_list = ( "A", "CNAME", "MX", "TXT", )

    for x in ip_list + a_list:
        names = PTR(SERVER, x)
        if names:
            print("PTR", x, "->", names)
        # fi

        for T in T_list:
            names = send_dns_request(x, T, SERVER)
            if names:
                print(T, x, "->", names)
            # fi
        # rof
    # rof
# End of debug_routines

#=============================================================================
def main(values):
    leave  = ('e', 'ex', 'exi', 'exit',
              'q', 'qu', 'qui', 'quit', )
    help   = ('h', 'he', 'hel', 'help', )
    add    = ('a', 'ad', 'add', )
    remove = ('r', 're', 'rem', 'remo', 'remov', 'remove',
              'd', 'de', 'del', 'dele', 'delet', 'delete', )
    #-- change = ('c', 'ch', 'cha', 'chan', 'chang', 'change', )
    show   = ('s', 'sh', 'sho', 'show', )

    tab_words = ['exit', 'quit', 'help', 'add ', 'remove ', 'delete ', 'show ']

    #-----------------------------------------------------------------------------
    def parse_args(values):
        parser = argparse.ArgumentParser(
            description=__doc__,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog= 'Change dynamic DNS for {}\n'.format(FULLDOMAIN))
        parser.add_argument('-q', '--quiet', action='store_true',
                            help = 'Do not print nsupdate commands to execute.')
        parser.add_argument('rest', nargs='*',
                            metavar='[add|delete|remove/show] [name|ip] ...',
                            help='Add/remove/show items in dynamic DNS.')
        args = parser.parse_args(values)
        return (args)
    # End of parse_args

    #-----------------------------------------------------------------------------
    def check_name_reasonable(name, twonotokay):
        if len(name) > 255:
            return "Name ({}) cannot be longer than 255 characters!".format(name)
        # fi

        allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        newer = all(allowed.match(x) for x in name.split("."))
        if not newer:
            return "Name ({}) is not a valid DNS name!".format(name)
        # fi

        a = name.split('.')
        for A in a:
            if A.isdigit():
                return "Name ({}) cannot be a number ({})!".format(name, A)
            # fi
        # rof

        pat = '\.' + FULLDOMAIN.replace('.', '\.')
        m = re.search(pat, name)
        if m:
            return "Name ({}) must not have {} in it, assumed!".format(name, FULLDOMAIN)
        # fi

        if twonotokay:
            if len(a) > 1:
                return "Name ({}) must not have any dots (.) in it!".format(name)
        else:
            if len(a) > 2:
                return "Name ({}) must not have more than 1 dot (.) in it!".format(name)
            # fi
        # fi

        return None
    # End of check_name_reasonable

    #-----------------------------------------------------------------------------
    def check_ip_reasonable(ip):
        a = ip.split('.')
        if len(a) != 4:
            return "IP address expected to have four (not {}) parts to it ({})!".format(len(a), ip)
        # fi
        for A in a:
            if not A.isdigit():
                return "IP ({}) must have components as digits (not {})!".format(ip, A)
            # fi
            if int(A) < 0 or int(A) > 255:
                return "IP ({}) must have components between 0 and 255 (not {})!".format(ip, A)
            # fi
        # rof
        return None
    # End of check_ip_reasonable

    #-----------------------------------------------------------------------------
    def getch():
        #-----------------------------------------------------------------------------
        def getsinglecharacterinteractive():
            try:
                ch = sys.stdin.read(1)
            except KeyboardInterrupt:
                # For some reason, cannot do both changes at the same time -- to revert.
                new[3] = new[3] | termios.ECHO          # Input echoing
                termios.tcsetattr(fd, termios.TCSADRAIN, new)
                new[3] = new[3] | termios.ICANON        # Full line input processing
                termios.tcsetattr(fd, termios.TCSADRAIN, new)
                print("\nexiting...")
                sys.exit(1)
            except SystemExit:
                sys.exit(1)
            except:
                print("\nexiting...")
                sys.exit(1)
            #yrt
            return ch
        # End of getsinglecharacterinteractive

        #-----------------------------------------------------------------------------
        # Start getch processing.
        """Read single character from standard input without echo."""
        fd = sys.stdin.fileno()
        # termios.tcgetattr fails if not terminal input. Assume 'y' for that case.
        try:
            old_settings = termios.tcgetattr(fd)
            new = old_settings
            new[3] = new[3] & ~termios.ECHO             # No input echoing
            termios.tcsetattr(fd, termios.TCSADRAIN, new)
            new[3] = new[3] & ~termios.ICANON           # Single character processing
            termios.tcsetattr(fd, termios.TCSADRAIN, new)
            ch = getsinglecharacterinteractive()
            # For some reason, cannot do both changes at the same time -- to revert.
            new[3] = new[3] | termios.ECHO          # Input echoing
            termios.tcsetattr(fd, termios.TCSADRAIN, new)
            new[3] = new[3] | termios.ICANON        # Full line input processing
            termios.tcsetattr(fd, termios.TCSADRAIN, new)
        except SystemExit:
            sys.exit(1)
        except:
            ch = 'y'
            pass
        # yrt
        return ch
    # End of getch

    #-----------------------------------------------------------------------------
    def Ask_Continue_Delete(str):
        print(str)
        c = ""
        while c not in ("y", "n", "d"):
            print("Continue (yes, no, delete)? [y/n/d] > ", end='', flush=True)
            c = getch().lower()
            print(c, flush = True)
        # elihw
        return c
    # End of Ask_Continue_Delete

    #-----------------------------------------------------------------------------
    def Ask_Delete(str):
        print(str)
        c = ""
        while c not in ("y", "n", "d"):
            print("Yes or no? [y/n] > ", end='', flush=True)
            c = getch().lower()
            print(c, flush = True)
        # elihw
        return c
    # End of Ask_Delete

    #-----------------------------------------------------------------------------
    def Ask_Do_It():
        print("Execute nsupdate to do it?")
        c = ""
        while c not in ("y", "n"):
            print("Yes or No? [y/n] > ", end='', flush=True)
            c = getch().lower()
            print(c, flush = True)
        # elihw
        return c
    # End of Ask_Do_It

    #-----------------------------------------------------------------------------
    def do_nsupdate_command(req):
        if not quiet:
            print("Request to nsupdate will be:")
            print("------------------------------------------------------------------------------")
            print(req, end='')
            print("------------------------------------------------------------------------------")
            c = Ask_Do_It()
            if c != 'y':
                return "Not doing it, as instructed."
            # fi
        #fi

        run_command(NSUPDATE, req)

        return "Done..."
    # End of do_nsupdate_command

    #-----------------------------------------------------------------------------
    def process_add(a):
        global SERVER

        req = "server {}\n".format(SERVER)

        if not a or len(a) < 2 or not a[0] or not a[1]:
            print("Add command requires at least two arguments - NAME and IP(s)!")
            return None
        # fi

        # Check name reasonable.
        newname = a[0]
        newips = a[1:]
        if newname[-1] == ".":
            newname = newname[:-1]                # Strip exactly one dot from the right.
        # fi
        # Strip possible parsec.lab from end.
        if newname.endswith(FULLDOMAIN):
            newname = newname[:-len(FULLDOMAIN)]
            if newname[-1] == ".":
                newname = newname[:-1]            # Strip exactly one dot from the right.
            # fi
        # fi
        # Check for leading "*." -- allowable.
        ifleadingstar = re.match('\*\.', newname)
        str2 = ''
        if ifleadingstar:
            tmp = newname[2:]
            na = newips
            na.insert(0, tmp)
            str2 = process_add(na)
            if str2 and not str2.endswith('\n'):
                str2 = str2 + '\n'
            # fi
            str = None
        else:
            str = check_name_reasonable(newname, True)
        # fi
        if str:
            return str2 + str
        # fi
        newips = a[1:]

        # Check IP address reasonable.
        for ip in newips:
            str = check_ip_reasonable(ip)
            if str:
                return str
            # fi
        # rof

        # Henceforth we want fullname.
        fullname = newname + '.' + FULLDOMAIN

        # Check CNAME already exists for fullname. If so, error - must delete CNAME first.
        cnames = send_dns_request(fullname, "CNAME", SERVER)
        if cnames:
            c = Ask_Continue_Delete('Name {} already has a CNAME record ({})'.format(fullname, cnames))
            # NOTE: a 'y' should get an error when attempting to execute nsupdate command.
            if c == 'n':
                return "CNAME already exists - stopping! {} -> {}".format(fullname, cnames)
            # fi
            if c == 'd':
                for n in cnames:
                    req += "update delete {} CNAME {}\n".format(fullname, n)
                    req += "send\n"       # Send because of multiple zone problems.
                # rof
            # fi
        # fi
        
        # Check TXT already exists for fullname. If so, WARN, ask if continue.
        txts = send_dns_request(fullname, "TXT", SERVER)
        if txts:
            c = Ask_Continue_Delete('Name {} already has a TXT record ({})'.format(fullname, txts))
            if c == 'n':
                return "TXT already exists - stopping! {} -> {}".format(fullname, txts)
            # fi
            if c == 'd':
                for n in txts:
                    req += "update delete {} TXT {}\n".format(fullname, n)
                    req += "send\n"       # Send because of multiple zone problems.
                # rof
            # fi
        # fi
        
        # Check MX already exists for fullname. If so, WARN, ask if continue.
        mxs = send_dns_request(fullname, "MX", SERVER)
        if mxs:
            c = Ask_Continue_Delete('Name {} already has a MX record ({})'.format(fullname, mxs))
            if c == 'n':
                return "MX already exists - stopping! {} -> {}".format(fullname, mxs)
            # fi
            if c == 'd':
                for n in mxs:
                    req += "update delete {} MX {}\n".format(fullname, n)
                    req += "send\n"       # Send because of multiple zone problems.
                # rof
            # fi
        # fi
        
        # Check A name already exists for fullname (and different IPs). If so, WARN, ask if continue.
        ips = send_dns_request(fullname, "A", SERVER)
        # We need to knows if A belongs to CNAME above.
        t = newips
        u = []
        if ips and len(ips) >= 1:
            if cnames and len(cnames) >= 1:
                specialflag = 0
                for n in cnames:
                    crs = send_dns_request(n + '.' + FULLDOMAIN, "A", SERVER)
                    if crs:
                        for c in crs:
                            if c in ips:
                                specialflag = specialflag + 1
                                if c in t:
                                    t.remove(c)    # Do not re-add anything from a CNAME
                                # fi
                            # fi
                        # rof
                    # fi
                # rof
                if specialflag != len(ips):
                    return "A records ({}) exist that are not only part of the CNAME ({})!".format(ips,cnames)
                # fi
            # fi
            for ip in ips:
                if ip in t:
                    t.remove(ip)
                else:
                    u.append(ip)
                # fi
            # rof
        # fi

        # If some new ips to do.

        if not t:
            return "No IP's to add - {}".format(ips)
        # fi

        for ip in t:
            s = ip.split('.')
            s.reverse()
            rip = '.'.join(s) + '.in-addr.arpa'
            req += "update delete {} IN A {}\n".format(fullname, ip)
            req += "update add {} 3600 IN A {}\n".format(fullname, ip)
            req += "send\n"       # Send because of multiple zone problems.
        # rof

        # If PTR already exists for a different name - ERROR? - must delete? WARN, ask if want to delete?
        if not ifleadingstar:
            flagerror = False
            for ip in t:
                s = ip.split('.')
                s.reverse()
                rip = '.'.join(s) + '.in-addr.arpa'
                ptrs = send_dns_request(rip, "PTR", SERVER)
                if ptrs:
                    for p in ptrs:
                        if p == fullname:
                            # already exists - no problem
                            pass
                        else:
                            flagerror = True
                            print("IP ({}) PTR record ({}) already exists for something else ({})".format(ip,rip,p))
                        # fi
                    # rof 
                # fi
            # rof
            if flagerror:
                return "See above errors - non-recoverable by this script!"
            # fi

            for ip in t:
                s = ip.split('.')
                s.reverse()
                rip = '.'.join(s) + '.in-addr.arpa'
                req += "update delete {} IN PTR {}\n".format(rip, fullname)
                req += "update add {} 3600 IN PTR {}\n".format(rip, fullname)
                req += "send\n"       # Send because of multiple zone problems.
            # rof
        # fi

        # Finish up the request to nsupdate.
        ret = do_nsupdate_command(req)
        return ret
    # End of process_add

    #-----------------------------------------------------------------------------
    def process_remove(a):
        #-----------------------------------------------------------------------------
        def process_remove_name(arg):
            # Check name reasonable.
            req = ''
            thename = arg
            if thename[-1] == ".":
                thename = thename[:-1]                # Strip exactly one dot from the right.
            # fi
            # Strip possible parsec.lab from end.
            if thename.endswith(FULLDOMAIN):
                thename = thename[:-len(FULLDOMAIN)]
                if thename[-1] == ".":
                    thename = thename[:-1]            # Strip exactly one dot from the right.
                # fi
            # fi
            # Check for leading "*." -- allowable.
            ifleadingstart = re.match('\*\.', thename)
            str2 = ''
            if ifleadingstart:
                tmp = thename[2:]
                (str2, req) = process_remove_name(tmp)
                if str2 and not str2.endswith('\n'):
                    str2 = str2 + '\n'
                # fi
                str = None
            else:
                str = check_name_reasonable(thename, True)
            # fi

            if str:
                return str2 + str, req
            # fi
            str = ''

            # Henceforth we want fullname.
            fullname = thename + '.' + FULLDOMAIN

            # Check CNAME already exists for fullname. If so delete CNAME it.
            cnames = send_dns_request(fullname, "CNAME", SERVER)
            if cnames:
                for n in cnames:
                    req += "update delete {} CNAME {}\n".format(fullname, n)
                    req += "send\n"       # Send because of multiple zone problems.
                # rof
            # fi
            
            # Check TXT already exists for fullname. If so, WARN, ask if continue.
            txts = send_dns_request(fullname, "TXT", SERVER)
            if txts:
                c = Ask_Delete('Name {} has a TXT record ({}), delete it?'.format(fullname, txts))
                if c == 'd' or c == 'y':
                    for n in txts:
                        req += "update delete {} TXT {}\n".format(fullname, n)
                        req += "send\n"       # Send because of multiple zone problems.
                    # rof
                # fi
            # fi
            
            # Check MX already exists for fullname. If so, WARN, ask if continue.
            mxs = send_dns_request(fullname, "MX", SERVER)
            if mxs:
                c = Ask_Delete('Name {} has a MX record ({}), delete it?'.format(fullname, mxs))
                if c == 'd' or c == 'y':
                    for n in mxs:
                        req += "update delete {} MX {}\n".format(fullname, n)
                        req += "send\n"       # Send because of multiple zone problems.
                    # rof
                # fi
            # fi
            
            # Check if A name already exists for fullname (and different IPs). If so, WARN, ask if continue.
            ips = send_dns_request(fullname, "A", SERVER)

            # Try not to delete A for CNAME ... stupid DNS.
            t = ips
            if ips and len(ips) >= 1:
                if cnames and len(cnames) >= 1:
                    specialflag = 0
                    for n in cnames:
                        crs = send_dns_request(n + '.' + FULLDOMAIN, "A", SERVER)
                        if crs:
                            for c in crs:
                                if c in t:
                                    t.remove(c)    # Do not re-delete anything A from a CNAME
                                # fi
                            # rof
                        # fi
                    # rof
                # fi
            # fi

            if t:
                for n in t:
                    req += "update delete {} IN A {}\n".format(fullname, n)
                    req += "send\n"       # Send because of multiple zone problems.
                    # Note: failures are okay.
                    s = n.split('.')
                    s.reverse()
                    rip = '.'.join(s) + '.in-addr.arpa'
                    req += "update delete {} IN PTR {}\n".format(rip, fullname)
                    req += "send\n"       # Send because of multiple zone problems.
                # orf
            # fi
            if req == '':
                return str2 + 'Nothing found to delete for name {}!'.format(fullname), ''
            # fi
            return str2 + '', req
        # End of process_remove_name

        #-----------------------------------------------------------------------------
        def process_remove_ip(arg):
            # Check IP address reasonable.
            req = ''
            s = arg.split('.')
            s.reverse()
            rip = '.'.join(s) + '.in-addr.arpa'
            ptrs = send_dns_request(rip, "PTR", SERVER)
            if ptrs:
                for n in ptrs:
                    req += "update delete {} IN PTR {}\n".format(rip, n)
                    req += "send\n"       # Send because of multiple zone problems.
                    # Get A for name "n".
                    ars = send_dns_request(n, "A", SERVER)
                    if ars:
                        for a in ars:
                            if a == arg:
                                # Check TXT already exists for n. If so, WARN, ask if continue.
                                txts = send_dns_request(n, "TXT", SERVER)
                                if txts:
                                    c = Ask_Delete('Name {} has a TXT record ({}), delete it?'.format(n, txts))
                                    if c == 'd' or c == 'y':
                                        for t in txts:
                                            req += "update delete {} TXT {}\n".format(n, t)
                                            req += "send\n"       # Send because of multiple zone problems.
                                        # rof
                                    # fi
                                # fi
                                # Check MX already exists for n. If so, WARN, ask if continue.
                                mxs = send_dns_request(n, "MX", SERVER)
                                if mxs:
                                    c = Ask_Delete('Name {} has a MX record ({}), delete it?'.format(n, mxs))
                                    if c == 'd' or c == 'y':
                                        for m in mxs:
                                            req += "update delete {} MX {}\n".format(n, m)
                                            req += "send\n"       # Send because of multiple zone problems.
                                        # rof
                                    # fi
                                # fi
            
                                # Delete the A after possible TXT and MX.
                                req += "update delete {} IN A {}\n".format(n, a)
                                req += "send\n"       # Send because of multiple zone problems.
                            # fi
                        # rof
                    # fi
                # rof 
            # fi

            if not req or req == '':
                return 'Nothing found to delete for ip {}!'.format(arg), ''
            # fi
            return '', req
        # End of process_remove_ip

        #-----------------------------------------------------------------------------
        # Process process_remove follows.

        req = ''
        if not a or len(a) < 1 or not a[0]:
            print("Add command requires at lease one argument - NAME or IP!")
            return None
        # fi

        for arg in a:
            str = check_ip_reasonable(arg)
            if str:                             # Might be a name.
                (str, r) = process_remove_name(arg)
            else:
                (str, r) = process_remove_ip(arg)
            # fi
            # If error with name or ip processing, leave with message.
            if str and str != '':
                return str
            # fi
            req += r
        # rof

        if not req or req == '':
            return "Nothing found to delete!"
        # fi

        # Set server before request.
        req = "server {}\n".format(SERVER) + req

        # Finish up the request to nsupdate.
        ret = do_nsupdate_command(req)
        return ret
    # End of process_remove

    #-----------------------------------------------------------------------------
    def process_show(a):
        #-----------------------------------------------------------------------------
        def process_show_name(a):
            # Check name reasonable.
            thename = a
            if thename[-1] == ".":
                thename = thename[:-1]                # Strip exactly one dot from the right.
            # fi
            # Strip possible parsec.lab from end.
            if thename.endswith(FULLDOMAIN):
                thename = thename[:-len(FULLDOMAIN)]
                if thename[-1] == ".":
                    thename = thename[:-1]            # Strip exactly one dot from the right.
                # fi
            # fi
            # Check for leading "*." -- allowable.
            ifleadingstar = re.match('\*\.', thename)
            str2 = ''
            if ifleadingstar:
                tmp = thename[2:]
                str2 = process_show_name(tmp)
                if str2 and not str2.endswith('\n'):
                    str2 = str2 + '\n'
                # fi
                str = None
            else:
                str = check_name_reasonable(thename, False)
            # fi

            if str:
                return str2 + str
            # fi
            str = ''

            # Henceforth we want fullname.
            fullname = thename + '.' + FULLDOMAIN

            # Check CNAME already exists for fullname.
            cnames = send_dns_request(fullname, "CNAME", SERVER)
            if cnames:
                for n in cnames:
                    str += "WARNING: {} CNAME {}\n".format(fullname, n)
                # rof
            # fi
            
            # Check TXT already exists for fullname.
            txts = send_dns_request(fullname, "TXT", SERVER)
            if txts:
                for n in txts:
                    str += "{} TXT {}\n".format(fullname, n)
                # rof
            # fi
            
            # Check MX already exists for fullname.
            mxs = send_dns_request(fullname, "MX", SERVER)
            if mxs:
                for n in mxs:
                    str += "{} MX {}\n".format(fullname, n)
                # rof
            # fi
            
            # Check if A name already exists for fullname.
            ips = send_dns_request(fullname, "A", SERVER)
            if ips:
                for n in ips:
                    str += "{} IN A {}\n".format(fullname, n)

                    s = n.split('.')
                    s.reverse()
                    rip = '.'.join(s) + '.in-addr.arpa'
                    ptrs = send_dns_request(rip, "PTR", SERVER)
                    if ptrs:
                        for p in ptrs:
                            str += "{} IN PTR {}.\n".format(rip, p)
                        # orf
                    # if
                # orf
            # fi
            if str == '':
                return str2 + "Nothing found in DNS - {}.\n".format(a)
            # fi
            return str2 + str
        # End of process_show_name

        #-----------------------------------------------------------------------------
        def process_show_ip(a):
            # Check IP address reasonable.
            str = ''
            s = a.split('.')
            s.reverse()
            rip = '.'.join(s) + '.in-addr.arpa'
            ptrs = send_dns_request(rip, "PTR", SERVER)
            if ptrs:
                for n in ptrs:
                    str += "{} IN PTR {}\n".format(rip, n)
                    # Get A for name "n".
                    ars = send_dns_request(n, "A", SERVER)
                    if ars:
                        for ar in ars:
                            if ar == a:
                                # Check TXT already exists for n. If so, WARN, ask if continue.
                                txts = send_dns_request(n, "TXT", SERVER)
                                if txts:
                                    for t in txts:
                                        str += "{} TXT {}\n".format(n, t)
                                    # rof
                                # fi
                                # Check MX already exists for n. If so, WARN, ask if continue.
                                mxs = send_dns_request(n, "MX", SERVER)
                                if mxs:
                                    for m in mxs:
                                        str += "{} MX {}\n".format(n, m)
                                    # rof
                                # fi
                                # Print the A after possible TXT and MX.
                                str += "{} IN A {}\n".format(n, a)
                            # fi
                        # rof
                    # fi
                # rof 
            # fi
            if str == '':
                return "Nothing found in DNS - {}.\n".format(a)
            # fi
            return str
        # End of process_show_ip

        #-----------------------------------------------------------------------------
        # Start process_show
        global SERVER

        if not a or len(a) < 1 or not a[0]:
            print("Show command requires at least one arguments - NAME or IP Address!")
            return None
        # fi

        for arg in a:
            str = check_ip_reasonable(arg)
            if str:                             # Might be a name.
                str = process_show_name(arg)
            else:
                str = process_show_ip(arg)
            # fi
            if str and str != '':
                if str.endswith('\n'):
                    print(str, end = '')
                else:
                    print(str)
                # fi
            # fi
        # rof
        return str

    # End of process_show

    #-----------------------------------------------------------------------------
    def usage(str):
        if str:
            print(str)
        # fi
        print(__doc__)
        return
    # End of usage

    #-----------------------------------------------------------------------------
    def process_line(rest):
        what = rest[0].lower()
        rest = rest[1:]
        newrest = []
        if rest:
            for r in rest:
                newrest.append(r.lower)
            # rof
        # fi

        # Exit or quit the program.
        if what in leave:
            print("exiting...")
            sys.exit(0)
        # fi

        # Print help message.
        if what in help:
            usage('')
            return
        # fi

        # Show NAME(s)/IP(s)
        if what in show:
            process_show(rest)
            return
        # fi

        # ADD NAME to IP(s).
        if what in add:
            str = process_add(rest)
            if str is not None:
                print(str)
            else:
                usage(None)
            # fi
            return
        # fi

        # Remove IP or NAME.
        if what in remove:
            str = process_remove(rest)
            if str is not None:
                print(str)
            else:
                usage()
            # fi
            return
        # fi

        print('-' * 78, file=sys.stderr)
        print("ERROR - unrecognized argument '{}'".format(what), file=sys.stderr)
        
        return
    # End of process_line

    #-----------------------------------------------------------------------------
    # main processing.
    args = parse_args(values)

    quiet = args.quiet

    if args.rest and args.rest[0]:
        process_line(args.rest)
        return
    # fi

    # Command line history.
    if os.path.exists(HIST_FILE):
        readline.read_history_file(HIST_FILE)
    # fi
    readline.set_history_length(10000)

    completer = dnsCompleter( tab_words )

    readline.set_completer(completer.complete)

    while True:
        try:
            if sys.stdin.isatty():
                if sys.platform == 'darwin':
                    input('ready> ')
                    line = readline.get_line_buffer()
                else:
                    line = input('ready> ')
                # fi
            else:
                line = sys.stdin.readline()
            if line:
                line = line.strip()
                if not sys.stdin.isatty():
                    print('READ>', line)
                # fi

                # Parse and process line.
                try:
                    t = shlex.split(line)
                except ValueError as ex:
                    print("Parsing error in line '%s'" % line)
                    print("    ", str(ex))
                    continue
                except SystemExit:
                    sys.exit(1)
                except:
                    print("Parsing error in line '%s'" % line)
                    print("    ", sys.exc_info()[0])
                    continue
                # yrt

                if t and t[0]:
                    process_line(t)
                # fi
            # fi
        except (EOFError, SystemExit, KeyboardInterrupt):
            # History writing here.
            readline.write_history_file(HIST_FILE)
            sys.exit(1)
        # yrt
    # elihw
    return
# End of main

#-----------------------------------------------------------------------------
# Execute the main routine.
if __name__ == '__main__':
    main(sys.argv[1:])
    sys.exit(0)
# fi
#-----------------------------------------------------------------------------
# End of file updateDNS.py
