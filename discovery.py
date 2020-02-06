import time

from berserker_resolver import Resolver
from multiprocessing.pool import ThreadPool as Pool
from concurrent.futures import ThreadPoolExecutor

from typing import List


def get_nameservers(f: str):
    with open(f) as nss:
        return [ns.strip() for ns in nss.readlines()]

class NS_Checker:
    def __init__(self, domain: str):
        self.domain = domain


    def ns_exists(self, nameserver: str) -> bool:
        resolver = Resolver()
        try:
            answer = resolver.query(self.domain, nameserver)
            #  print(vars(answer), nameserver)
            return nameserver
        except:
            return False

def scan_nameservers_parallel(nameservers: List[str], threads=1000):
    checker = NS_Checker('google.com')

    with ThreadPoolExecutor(1000) as executor:
        jobs = []
        for ns in nameservers:
            jobs.append(executor.submit(checker.ns_exists, ns))

        return [job.result() for job in jobs]


def main():
    nameservers = get_nameservers('output.csv')

    a = scan_nameservers_parallel(nameservers)
    print(a)

if __name__ == '__main__':
    main()
