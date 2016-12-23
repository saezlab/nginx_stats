#!/usr/bin/python

#
# Processes logfiles of nginx and extracts basic statistics.
#
# (c) Dénes Türei, turei.denes@gmail.com
#

import ipwhois
import os
import dateutil.parser
import itertools
import sys
import collections
import pycountry
from future.utils import iteritems

WHOIS_CACHE = {}

def output_toplist(fname, cntr):
    """
    Outputs a toplist from a Counter.
    """
    with open(fname, 'w') as f:
        f.write(
            '\n'.join(
                map(
                    lambda i:
                        '%s\t%u' % i,
                    reversed(
                        sorted(
                            iteritems(
                                cntr
                            ),
                            key = lambda i:
                                i[1]
                        )
                    )
                )
            )
        )

def processline(l):
    """
    Processes one line of the log.
    """
    
    return {
        'ip': l[0],
        'req_url': l[1],
        'time': dateutil.parser.parse('%s %s' % (l[3][1:], l[4][:-1]), fuzzy = True),
        'http_code': int(l[6]) if l[6].isdigit() else None,
        'page': l[5],
        'from_url': l[8],
        'useragent': l[9]
    }

def whoislookup(l):
    """
    Extends one data point with whois data.
    """
    
    if '_whois_done' in l and l['_whois_done']:
        return None
    
    this_whois = {'country': None,
                  'names': [(None, None, None, None)],
                  '_whois_done': False}
    
    if l['ip'] in WHOIS_CACHE:
        this_whois = WHOIS_CACHE[l['ip']]
    
    else:
        sys.stdout.write('\t[WHOIS] %s' % l['ip'])
        
        try:
            ipw = ipwhois.IPWhois(l['ip'])
            res = ipw.lookup_whois(retry_count = 5)
            this_whois['country'] = res['asn_country_code']
            this_whois['names'] = list(map(lambda e:
                (e['name'], e['description'], e['city'], e['country']), res['nets']))
            sys.stdout.write('\n')
            this_whois['_whois_done'] = True
            WHOIS_CACHE[l['ip']] = this_whois
        except (ipwhois.exceptions.HTTPLookupError, ipwhois.exceptions.HTTPRateLimitError):
            sys.stdout.write(' [FAILED]\n')
    
    l.update(this_whois)

def countries(data):
    """
    Return counts for each country.
    Maps country 2 letter codes to full names.
    """
    
    allcountr = set(map(lambda c: c.alpha_2, list(pycountry.countries)))
    
    return \
        collections.Counter(
            map(
                lambda d:
                    pycountry.countries.lookup(d[0]).name,
                set(
                    map(
                        lambda d:
                            (
                                d['country'],
                                d['ip']
                            ),
                        filter(
                            lambda d:
                                'country' in d and d['country'] in allcountr,
                            data
                        )
                    )
                )
            )
        )

def names(data, unique = False):
    """
    Returns counts per organization/network name.
    E.g. one name is `GoogleBot`, another is `Cambridge University`, etc.
    
    :param bool unique: Count only once repeated IPs.
    """
    
    lst = \
        map(
            lambda d:
                (
                    (', '.join(
                        map(str, d['names'][0])
                    )).replace('\n', ', '),
                    d['ip']
                ),
            filter(
                lambda d:
                    'names' in d and len(d['names']),
                data
            )
        )
    
    if unique: lst = set(lst)
    
    return \
        collections.Counter(
            map(
                lambda d:
                    d[0],
                lst
            )
        )

def readfile(fname):
    """
    Reads file, returns list of lines.
    """
    
    with open(fname, 'r') as f:
        out = []
        in_q = False
        line = []
        field = []
        for c in f.read():
            if c == '"':
                in_q = not in_q
            elif c == '\n':
                if not in_q:
                    line.append(''.join(field))
                    field = []
                    out.append(line)
                    line = []
            elif c == ' ' and not in_q:
                line.append(''.join(field))
                field = []
            else:
                field.append(c)
    if len(line):
        line.append(''.join(field))
        out.append(line)
    return out

#
# Here comes the interactive part.
# Or uncomment the line below and run from the shell.
# if __name__ == '__main__':
#

logs = filter(lambda fn: 'access.log' in fn, os.listdir('./'))

data = \
    list(
        itertools.chain(
            *map(
                lambda logf:
                    map(
                        processline,
                        readfile(logf)
                    ),
                logs
            )
        )
    )

_ = list(map(whoislookup, data))

visitors_countries = countries(data)
visitors_names = names(data)
visitors_names_unique = names(data, unique = True)

output_toplist('visitors_by_name', visitors_names)
output_toplist('visitors_by_name_unique', visitors_names_unique)
output_toplist('visitors_by_country', visitors_countries)
