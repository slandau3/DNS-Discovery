import time
import pprint
import argparse

from berserker_resolver import Resolver
from multiprocessing.pool import ThreadPool as Pool
from concurrent.futures import ThreadPoolExecutor

from typing import List
from dataclasses import dataclass
from datetime import datetime


parser = argparse.ArgumentParser(description='Scan IP\'s for DNS Resolvers')
parser.add_argument('ADDRESS_FILE', type=argparse.FileType('r'), help='File containg IP addresses to scan')
parser.add_argument('--domain', default='google.com', help='Domain usedin DNS A record query (default = google.com)')
parser.add_argument('--outfile', default='nameservers.csv', help='CSV output file')

@dataclass
class DNSResolver:
    """
    Dataclass representing a DNS Resolver.
    Stores identifying information as well as
    the ip of a nameserver.
    """
    ip: str
    rcode: str
    response_timestamp: float
    region: str

    request_domain: str
    record: str
    
    
class NS_Checker:
    """
    Provides funcitonality for checking that a
    nameserver exists at the given ip.
    """
    def __init__(self, domain: str):
        self.domain = domain

    def ns_exists(self, ns_candidate: str) -> DNSResolver:
        """
        Queries the ns_candidate to determine if it's
        a nameserver. An A record with whatever domain
        was specified is sent is sent to the ns_candidate.

        :param ns_candidate:    IP of a possible nameserver

        :returns:   DNSResolver object if a nameserver exists
                    at the given ip. None otherwise
        """
        resolver = Resolver()
        try:
            answer = resolver.query(self.domain, ns_candidate)
            return DNSResolver(ip=ns_candidate, rcode=answer.response.rcode(), 
                    response_timestamp=datetime.timestamp(datetime.now()), region=None,
                    request_domain=self.domain, record='A')
        except:
            return None


def get_nameservers(f: str) -> List[str]:
    """
    Read all nameservers from the given file into a list of IP's

    :param f: Name of the file to read
    :returns:   List of IP addresses as strings
    """
    with open(f) as nss:
        return [ns.strip() for ns in nss.readlines()]


def scan_nameservers_parallel(nameservers: List[str], threads: int=1000, domain: str='google.com') -> List[DNSResolver]:
    checker = NS_Checker(domain)

    with ThreadPoolExecutor(1000) as executor:
        jobs = []
        for ns in nameservers:
            jobs.append(executor.submit(checker.ns_exists, ns))

        print('ip, rcode, response_timestamp, region, request_domain, record')
        for job in jobs:
            res = job.result()
            if res is not None:
                print(res.ip, res.rcode, res.response_timestamp, res.region, res.request_domain, res.record)
        #  results = [job.result() for job in jobs]

        # Return a list of DNSResolver objects.
        # Filter the None's out of the list from
        # IP's that did not host nameservers
        #  return list(filter(lambda res: res is not None, results))


def main():
    args = parser.parse_args()
    
    nameservers = get_nameservers(args.ADDRESS_FILE.name)

    a = scan_nameservers_parallel(nameservers, domain=args.domain)
    #  pprint.pprint(a)


if __name__ == '__main__':
    main()
