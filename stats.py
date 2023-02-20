#!/usr/bin/env python

#
# (c) 2016-2023 Dénes Türei, turei.denes@gmail.com
# License: MIT (Expat) License
#

"""
Process nginx logfiles and extract basic statistics.
"""

import ipwhois
import os
import dateutil.parser
import itertools
import sys
import imp
import collections
import pycountry
import pickle
from future.utils import iteritems


class WebStats(object):

    whois_cachefile = 'whois.pickle'
    WHOIS_CACHE  = {}
    WHOIS_FAILED = set()
    last_failed  = None

    def __init__(
        self,
        logdir,
        domain_filter = lambda x: x,
        logfiles_domain = None,
        bot_keywords = {
            'Microsoft',
            'Facebook',
            'Yahoo',
            'Google',
            'Baidu',
            'Bot',
        },
        ac_keywords = {
            'Uni',
            'Lab',
            'Instit',
            'Bio',
            'Sci',
            'Geno',
        },
        only_ac = False,
    ):
        """
        Process nginx logfiles and extract basic statistics.

        Args:
            logdir:
                Look up Nginx logfiles from this directory.
            domain_filter:
                A function with value corresponding to False or True for
                domains to be excluded or included, respectively.
            logfiles_domain:
                From ``logdir`` use only the log files that belong to this
                domain.
            bot_keywords:
                Keywords to identify crawlers and other bots. Log entries
                from bots will be removed.
            ac_keywords:
                Keywords to identify academic institutions.
            only_ac:
                Create statistics only from log entries that belong to
                academic institutions, as identified based on ``ac_keywords``.
        """

        self.logdir = logdir
        self.domain_filter = domain_filter
        self.logfiles_domain = logfiles_domain
        self.bot_keywords = bot_keywords
        self.ac_keywords  = ac_keywords
        self.only_ac = only_ac


    def reload(self):

        modname = self.__class__.__module__
        mod = __import__(modname, fromlist = [modname.split('.')[0]])
        imp.reload(mod)
        new = getattr(mod, self.__class__.__name__)
        setattr(self, '__class__', new)


    def main(self):

        self.read_whois_cache()
        self.logfiles_lookup()
        self.read_logfiles()
        self.collect_whois()
        self.select_ac()
        self.remove_bots()
        self.stats()
        self.export()


    def read_whois_cache(self):

        if os.path.exists(self.whois_cachefile):

            self.WHOIS_CACHE, self.WHOIS_FAILED = pickle.load(
                open(self.whois_cachefile, 'rb')
            )


    def output_toplist(self, fname, cntr):
        """
        Outputs a toplist from a Counter.
        """

        rev_sorted = reversed(
            sorted(
                iteritems(cntr),
                key = lambda i: i[1]
            )
        )

        with open(fname, 'w') as f:

            _ = f.write(
                '\n'.join(
                    '%s\t%u' % i,
                    for i in rev_sorted
                )
            )


    def processline(self, l):
        """
        Processes one line of the log.
        """

        return {
            'ip': l[0],
            'req_url': l[1],
            'time': dateutil.parser.parse(
                '%s %s' % (l[3][1:], l[4][:-1]),
                fuzzy = True
            ),
            'http_code': int(l[6]) if l[6].isdigit() else None,
            'page': l[5],
            'from_url': l[8],
            'useragent': l[9]
        }


    def whoislookup(self, l):
        """
        Extends one data point with whois data.
        """

        if '_whois_done' in l and l['_whois_done']:
            return None

        this_whois = {'country': None,
                    'names': [(None, None, None, None)],
                    '_whois_done': False}

        if l['ip'] in self.WHOIS_CACHE:
            this_whois = self.WHOIS_CACHE[l['ip']]
        elif l['ip'] in self.WHOIS_FAILED:
            return

        else:
            sys.stdout.write('\t[WHOIS] %s' % l['ip'])

            try:
                ipw = ipwhois.IPWhois(l['ip'])
                res = ipw.lookup_whois(retry_count = 5)
                this_whois['country'] = res['asn_country_code']
                this_whois['names'] = [
                    (e['name'], e['description'], e['city'], e['country'])
                    for e in res['nets']
                ]
                sys.stdout.write('\n')
                this_whois['_whois_done'] = True
                self.WHOIS_CACHE[l['ip']] = this_whois
            except (ipwhois.exceptions.HTTPLookupError,
                    ipwhois.exceptions.HTTPRateLimitError,
                    ipwhois.exceptions.WhoisLookupError):
                sys.stdout.write(' [FAILED]\n')
                self.WHOIS_FAILED.add(l['ip'])
                self.last_failed = l['ip']

        l.update(this_whois)


    def countries(self, data):
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


    def names(self, data, unique = False):
        """
        Counts per organization/network name.

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


    def readfile(self, fname):
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

    def logfiles_lookup(self):

        self.logs = [
            os.path.join(self.logdir, fn)
            for fn in
            os.listdir(self.logdir)
            if ('access.log' in fn or 'cache.log' in fn) and (
                self.logfiles_domain is None or
                self.logfiles_domain in fn
            )
        ]


    def read_logfiles(self):

        self.data = \
            list(
                filter(
                    self.domain_filter,
                    itertools.chain(
                        *map(
                            lambda logf:
                                map(
                                    self.processline,
                                    self.readfile(logf)
                                ),
                            self.logs
                        )
                    )
                )
            )


    @staticmethod
    def inspect_name(n, kws):

        for n0 in n:

            if not n0:
                continue

            for n1 in n0:

                if not n1:
                    continue

                if any(b in n1 for b in kws):

                    return True

        return False


    def remove_bots(self):

        def is_bot(n):

            return self.inspect_name(n, self.bot_keywords)

        self.data = [d for d in self.data if not is_bot(d['names'])]


    def select_ac(self):

        if self.only_ac:

            def is_ac(n):

                return self.inspect_name(n, self.ac_keywords)

            self.data = [d for d in self.data if is_ac(d['names'])]


    def collect_whois(self):

        try:

            _ = list(map(self.whoislookup, self.data))

        except:

            self.WHOIS_FAILED.discard(self.last_failed)

            with open(self.whois_cachefile, 'wb') as fp:

                pickle.dump((self.WHOIS_CACHE, self.WHOIS_FAILED), fp)


    def stats(self):

        self.visitors_countries = self.countries(self.data)
        self.visitors_names = self.names(self.data)
        self.visitors_names_unique = self.names(self.data, unique = True)


    def export(self):

        self.output_toplist('visitors_by_name', self.visitors_names)
        self.output_toplist('visitors_by_name_unique', self.visitors_names_unique)
        self.output_toplist('visitors_by_country', self.visitors_countries)

        with open(self.whois_cachefile, 'wb') as fp:

            pickle.dump((self.WHOIS_CACHE, self.WHOIS_FAILED), fp)
