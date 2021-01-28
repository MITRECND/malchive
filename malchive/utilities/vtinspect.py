#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright(c) 2021 The MITRE Corporation. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at:
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
import sys
import json
import struct
import socket
import os.path
import logging
import argparse
import hashlib
import requests
import progressbar

__version__ = "1.4.0"
__author__ = "Jason Batchelor"

log = logging.getLogger(__name__)


class VirusTotalAPI:
    """
    Gets specific configuration IoCs from the malware.

    :ivar dict params: Parameters to inform query to VT API.
    :ivar str base: Base URL for queries to be made against.
    """

    def __init__(self, apikey):
        """
        Initialize VirusTotal interface.

        :param str apikey: API key to use.
        """

        self.params = {'apikey': apikey}
        self.base = 'https://www.virustotal.com/vtapi/v2'

    def search_file(self, resource, allinfo):
        """
        Search for information based on a supplied hash.

        :param str resource: Hash to search on.
        :param bool allinfo: Show extra verbose information about the hash.

        :return: JSON dump of response data from VirusTotal
        :rtype: dict
        """

        self.params['allinfo'] = int(allinfo)
        self.params['resource'] = resource
        response = requests.get('%s/%s' % (self.base, 'file/report'),
                                params=self.params, verify=True)
        response_json = response.json()
        return json.dumps(response_json, indent=4, sort_keys=False)

    def get_submission_info(self, resource):
        """
        Get submitter information for resource.

        :param str resource: Hash to search on.

        :return: JSON dump of response data from VirusTotal
        :rtype: dict
        """

        self.params['resource'] = resource
        response = requests.get('%s/%s' % (self.base, 'file/submissions'),
                                params=self.params, verify=True)
        response_json = response.json()

        if len(response_json) == 0:
            # Doesn't return anything if a match fails so
            # we manufacture one here
            return {"verbose_msg": "The requested resource is not among "
                                   "the finished, queued or pending scans"}

        return json.dumps(response_json, indent=4, sort_keys=False)

    def download_file(self, hash):
        """
        Download file corresponding to supplied hash value.

        :param str hash: Hash of file to download.

        :return: JSON dump of response data from VirusTotal
        :rtype: response
        """

        self.params['hash'] = hash
        response = requests.get('%s/%s' % (self.base, 'file/download'),
                                params=self.params, verify=True)

        return response

    def download_pcap(self, hash):
        """
        Download PCAP information gathered corresponding to the supplied hash.

        :param str hash: Hash to search on.

        :return: JSON dump of response data from VirusTotal
        :rtype: response
        """

        self.params['hash'] = hash
        response = requests.get('%s/%s' % (self.base, 'file/network-traffic'),
                                params=self.params, verify=True)

        return response

    def rescan(self, hash):
        """
        Search for information based on a supplied hash.

        :param str hash: Hash to search on.

        :return: JSON dump of response data from VirusTotal
        :rtype: dict
        """

        self.params['resource'] = hash
        response = requests.post('%s/%s' % (self.base, 'file/rescan'),
                                 params=self.params)
        response_json = response.json()

        return response_json

    def behaviour(self, hash):
        """
        Search for sandbox information corresponding to the supplied hash.

        :param str hash: Hash to search on.

        :return: JSON dump of response data from VirusTotal
        :rtype: dict
        """

        self.params['hash'] = hash
        response = requests.get('%s/%s' % (self.base, 'file/behaviour'),
                                params=self.params, verify=True)
        response_json = response.json()
        return json.dumps(response_json, indent=4, sort_keys=False)

    def comments(self, hash):
        """
        Search for user comments corresponding to the supplied hash.

        :param str hash: Hash to search on.

        :return: JSON dump of response data from VirusTotal
        :rtype: dict
        """

        self.params['resource'] = hash
        response = requests.get('%s/%s' % (self.base, 'comments/get'),
                                params=self.params, verify=True)
        response_json = response.json()
        return json.dumps(response_json, indent=4, sort_keys=False)

    def search_url(self, resource, scan, allinfo):
        """
        Search for reputation data corresponding to the supplied url.

        :param str resource: URL to search on.
        :param bool scan: Bool to force a scan for a URL not in the VirusTotal
        database.
        :param bool allinfo: Retrieve more verbose information about the
        supplied URL.

        :return: JSON dump of response data from VirusTotal
        :rtype: dict
        """

        self.params['allinfo'] = int(allinfo)
        self.params['resource'] = resource
        self.params['scan'] = int(scan)

        response = requests.post('%s/%s' % (self.base, 'url/report'),
                                 params=self.params)
        response_json = response.json()

        return json.dumps(response_json, indent=4, sort_keys=False)

    def search_domain(self, domain):
        """
        Search for data corresponding to the submitted domain.

        :param str domain: Domain to search on.

        :return: JSON dump of response data from VirusTotal
        :rtype: dict
        """

        self.params['domain'] = domain
        response = requests.get('%s/%s' % (self.base, 'domain/report'),
                                params=self.params, verify=True)
        response_json = response.json()
        return json.dumps(response_json, indent=4, sort_keys=False)

    def search_ip(self, ip):
        """
        Search for data corresponding to the submitted IP address.

        :param str ip: IP address to search on.

        :return: JSON dump of response data from VirusTotal
        :rtype: dict
        """

        self.params['ip'] = ip
        response = requests.get('%s/%s' % (self.base, 'ip-address/report'),
                                params=self.params, verify=True)
        response_json = response.json()
        return json.dumps(response_json, indent=4, sort_keys=False)

    def query_submissions(self, query, offset=None):
        """
        Execute a search modifier compliant file search query against
        VirusTotal.

        :param str query: Search modifier to use.
        :param str offset: Search offset given from VT API when a query has
        more than 300 results.

        :return: JSON dump of response data from VirusTotal
        :rtype: dict
        """

        if offset is not None:
            self.params['offset'] = offset

        self.params['query'] = query
        response = requests.post('%s/%s' % (self.base, 'file/search'),
                                 params=self.params, verify=True)
        response_json = response.json()

        return response_json


def process_hashes(opt, vt):

    for h in opt.hashes:
        # Verify hash is md5/sha1/sha256
        if not (re.match(r'^[a-fA-F\d]{32}$', h) or
                re.match(r'^[a-fA-F\d]{40}$', h) or
                re.match(r'^[a-fA-F\d]{64}$', h)):
            log.warning('Invalid hash supplied, skipping %s' % h)
            continue
        # Get detailed file information
        if opt.info:
            print(vt.search_file(h, opt.verbose))
        # Get detailed info from submitters
        if opt.submitter:
            print(vt.get_submission_info(h))
        # Download the specimen
        if opt.download_file:
            log.info('Attempting to retrieve file...')
            result = vt.download_file(h)

            if result.status_code == 404:
                log.warning('404 returned, %s not found in database...' % h)
            elif result.status_code == 200:
                name = '%s.vt' % h.lower()
                with open(name, 'wb') as f:
                    f.write(result.content)
                print('Retrieved file from VT, saved locally as %s' % name)
                check_payload_integrity(h, result.content)
            else:
                log.warning(
                    'Unable to retrieve file, response code was %s. '
                    'Try again in a few minutes...' % result.status_code)

        # Download the pcap
        if opt.download_pcap:
            log.info('Attempting to retrieve pcap...')
            result = vt.download_pcap(h)
            if result.status_code == 404:
                log.warning('404 returned, file not found in database...')
            elif result.status_code == 200 and \
                    result.content.startswith(b'\xd4\xc3\xb2\xa1'):
                name = '%s.pcap' % h.lower()
                with open(name, 'wb') as f:
                    f.write(result.content)
                print('Retrieved file from VT, saved locally as %s' % name)
            else:
                log.warning(
                    'Unable to retrieve PCAP for %s. PCAP data may not '
                    'exist for it. Response code: %s'
                    % (h, result.status_code))

        # Rescan the supplied hash/file
        if opt.rescan:
            result = vt.rescan(h)

            if result['response_code'] == 0:
                log.error('There was an error rescanning. '
                          'The hash may not be in the database.')
            elif result['response_code'] == 1:
                print('Rescan request successful, please navigate to the '
                      'provided URL and await the results...\n%s' %
                      result['permalink'])

        # Get behaviour of file
        if opt.behaviour:
            print(vt.behaviour(h))
        # Get user submitted comments
        if opt.comments:
            print(vt.comments(h))


def check_payload_integrity(h, buff):

    result_hash = ''
    # Verify hash is md5/sha1/sha256
    if re.match(r'^[a-fA-F\d]{32}$', h):
        result_hash = hashlib.md5(buff).hexdigest()
    if re.match(r'^[a-fA-F\d]{40}$', h):
        result_hash = hashlib.sha1(buff).hexdigest()
    if re.match(r'^[a-fA-F\d]{64}$', h):
        result_hash = hashlib.sha256(buff).hexdigest()

    if h.lower() != result_hash.lower():
        log.error('The retrieved file does not match the provided '
                  'hash value! %s != %s' %
                  (h.lower(), result_hash.lower()))


def process_net_indicators(opt, vt):

    if opt.url:
        for url in opt.url:
            # Verify url
            if not re.match(r'^(http|https)://.*?\..*', url):
                log.error(
                    'Invalid URL supplied, skipping %s.\nEnsure the '
                    'http:// or https:// prefix is at the beginning...'
                    % url)
                continue

            # Get detailed URL information
            if opt.force_url:
                # User coaching
                while True:
                    ans = input(
                        'Forcing a URL scan will add a public record '
                        'to the VirusTotal database for the URL you '
                        'submitted if it\'s not found in the existing '
                        'dataset. \nAre you sure? (y/n) ')
                    if ans == 'y':
                        break
                    elif ans == 'n':
                        print('Aborting URL scan of %s...' % url)
                        continue
                    else:
                        print('Please provide either \'y\' or \'n\'')

                print('Initiating a scan request on your behalf...')
            print(vt.search_url(url, opt.force_url, opt.verbose))

    if opt.domain_name:
        for d in opt.domain_name:
            # Verify domain
            if len(d.split(".")) > 1 and d.startswith('.') is True:
                log.warning(
                    'Invalid domain supplied, skipping %s.\nProvide a '
                    'valid domain, with a basename prefix \
(ex: google.com)...' % d)
                continue
            # Get detailed domain name information
            print(vt.search_domain(d))

    if opt.ip:
        for ip_addr in opt.ip:
            # Very simple verify IP, VT will do additional checks but
            # this serves as an initial gate
            try:
                struct.unpack("!L", socket.inet_aton(ip_addr))[0]
            except socket.error:
                log.warning('Invalid IP address, %s, skipping...' % ip_addr)
                continue
            # Get detailed IP address information
            print(vt.search_ip(ip_addr))


def process_bulk_query(opt, vt):

    hash_list = []
    target_dir = opt.target_directory

    if target_dir != '.':
        try:
            log.info('Writing to directory: %s' % target_dir)
            os.makedirs(target_dir)
        except OSError:
            if not os.path.isdir(target_dir):
                log.error('Could not create %s' % target_dir)
                return

    if not opt.query:
        log.error('A search modifier query must be provided.')
        return

    print('Compiling search results. This may take some time '
          'depending on the search...')

    # Execute search modifier compliant query
    answer = vt.query_submissions(opt.query)

    if 'hashes' not in list(answer.keys()):
        print(json.dumps(answer, indent=4, sort_keys=False))
        return

    if len(answer['hashes']) >= opt.limit != 0:
        hash_list.extend(answer['hashes'][:opt.limit])
        log.warning('User defined threshold reached...')
    else:
        hash_list.extend(answer['hashes'])

        while 'offset' in list(answer.keys()):
            offset = answer['offset']
            answer = vt.query_submissions(opt.query, offset)
            new_size = len(hash_list) + len(answer['hashes'])
            if new_size >= opt.limit != 0:
                hash_list.extend(
                    answer['hashes'][:(opt.limit - len(hash_list))])
                log.warning('User defined threshold reached...')
                break
            else:
                hash_list.extend(answer['hashes'])

    if opt.pull_files and len(hash_list) > 0:

        while not opt.force_download:
            ans = input(
                'Query returned %s results. '
                'Proceed with collection? (y/n) ' % len(hash_list))
            if ans == 'y':
                break
            elif ans == 'n':
                print('Aborting collection!')
                return
            else:
                print('Please provide either \'y\' or \'n\'')

        print('Attempting to pull files across %s query matches...'
              % len(hash_list))
        bar = progressbar.ProgressBar(redirect_stdout=True,
                                      max_value=len(hash_list))

        counter = 0
        fail_count = 0
        failed = []
        for h in hash_list:
            result = vt.download_file(h)
            if result.status_code == 200:
                name = '%s/%s.vt' % (target_dir, h)
                with open(name, 'wb') as f:
                    f.write(result.content)
                check_payload_integrity(h, result.content)
            else:
                fail_count += 1
                failed.append(h)

            bar.update(counter)
            counter += 1

        if fail_count > 0:
            log.warning(
                'Unable to retrieve files for %s candidates.\n'
                'Failed list: \n%s'
                % (fail_count, '\n'.join(failed)))

    if opt.pull_pcaps and len(hash_list) > 0:

        while not opt.force_download:
            ans = input(
                'Query returned %s results. '
                'Proceed with collection? (y/n) ' % len(hash_list))
            if ans == 'y':
                break
            elif ans == 'n':
                print('Aborting collection!')
                return
            else:
                print('Please provide either \'y\' or \'n\'')

        print('Attempting to pull pcaps across %s query matches on files...'
              % len(hash_list))
        bar = progressbar.ProgressBar(redirect_stdout=True,
                                      max_value=len(hash_list))

        counter = 0
        fail_count = 0
        failed = []
        for h in hash_list:
            result = vt.download_pcap(h)
            if result.status_code == 200 and \
                    result.content.startswith(b'\xd4\xc3\xb2\xa1'):
                name = '%s/%s.pcap' % (target_dir, h)
                with open(name, 'wb') as f:
                    f.write(result.content)
            else:
                fail_count += 1
                failed.append(h)

            bar.update(counter)
            counter += 1

        if fail_count > 0:
            log.warning(
                'Unable to retrieve PCAP for %s candidates. '
                'PCAP data may not exist for them.\nFailed list: \n%s'
                % (fail_count, '\n'.join(failed)))

    if not opt.pull_files and not opt.pull_pcaps or len(hash_list) == 0:
        print('Query returned %s unique results...' % len(hash_list))


def initialize_parser():
    parser = argparse.ArgumentParser(
        prog='vtinspect',
        description='Query VirusTotal database based on supplied indicators '
                    'such as; md5, sha1, sha256, IP, domain, or URL. '
                    'At least one of either is required to use this script. '
                    'A \'.vt.key\' file must also be present in the user '
                    'home directory with the format '
                    '{ "key" : "API_KEY_HERE" }')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Get more verbose output if supported.')

    subparsers = parser.add_subparsers(
        dest='subparser_name',
        help='Select from a variety of options on how to query the '
             'VirusTotal database.')

    file_parser = subparsers.add_parser(
        'hash',
        help='Issue VT queries based on multiple hashes from various files.')
    file_parser.add_argument('hashes',
                             nargs='*',
                             help='List of hashes (md5/sha1/sha256) for '
                                  'inspection.')
    file_parser.add_argument('-i', '--info',
                             action='store_true',
                             help='Search VirusTotal to pull file '
                                  'information.')

    file_parser.add_argument('-s', '--submitter',
                             action='store_true',
                             help='Get information on the submission source.')
    file_parser.add_argument('-b', '--behaviour',
                             action='store_true',
                             help='Search VirusTotal to pull behaviour '
                                  'information from Cuckoo Sandbox instance '
                                  '(only done on VT for PE files under 10MB).')
    file_parser.add_argument('-c', '--comments',
                             action='store_true',
                             help='Retrieve comments from others associated '
                                  'with the provided file.')
    file_parser.add_argument('-df', '--download-file',
                             action='store_true',
                             help='Download file from VirusTotal and '
                                  'save as \'[hash].vt\'.')
    file_parser.add_argument('-dp', '--download-pcap',
                             action='store_true',
                             help='Download any relevant pcap traffic '
                                  'and save as \'[hash].pcap\'.')
    file_parser.add_argument('-r', '--rescan',
                             action='store_true',
                             help='Force VirusTotal to rescan the file with '
                                  'it\'s current AV definitions.')

    net_parser = subparsers.add_parser(
        'net',
        help='Issue VT queries various network indicators, such as; IPs, '
             'domains, and URLs.')
    net_parser.add_argument('-u', '--url',
                            nargs='*',
                            help='List of URLs for inspection.')
    net_parser.add_argument('--force-url',
                            action='store_true',
                            help='Force a scan of the URL if it is not '
                                 'in the database. Can only be used '
                                 'with the --url command.')
    net_parser.add_argument('-dn', '--domain-name',
                            nargs='*',
                            help='List of domain names for inspection.')
    net_parser.add_argument('-ip', '--ip',
                            nargs='*',
                            help='List of IP addresses for inspection.')

    bulk_parser = subparsers.add_parser(
        'bulk',
        help='Execute a search modifier compliant file search query against '
             'VirusTotal. Returns the first 300 matching hits sorted '
             'according to the last submission date in descending order. '
             'Example: \'type:peexe size:90kb+ positives:5+ '
             'behaviour:"taskkill"\'. '
             'Reference: https://www.virustotal.com/intelligence/help/'
             'file-search/#search-modifiers')
    bulk_parser.add_argument(
        'query',
        type=str,
        help='Search modifier compliant file search query. Enclosed in single '
             'quotes.')
    bulk_parser.add_argument('-pf',
                             '--pull-files',
                             action='store_true',
                             help='Pull all files returned from a '
                                  'VirusTotal query.')
    bulk_parser.add_argument('-pp',
                             '--pull-pcaps',
                             action='store_true',
                             help='Pull all pcaps returned from a '
                                  'VirusTotal query.')
    bulk_parser.add_argument('--force-download',
                             action='store_true',
                             help='Ignore user prompt indicating query '
                                  'results and download all query file '
                                  'or subordinate PCAP matches.')
    bulk_parser.add_argument('-l', '--limit',
                             type=int,
                             default=0,
                             help='Enforce a maximum limit of returned '
                                  'results. Useful for loose VT queries '
                                  'that may return thousands of results '
                                  'to parse. (default: unlimited)')
    bulk_parser.add_argument('-t', '--target-directory',
                             type=str,
                             default='.',
                             help='Target directory to write files.')

    return parser


def main():
    p = initialize_parser()
    args = p.parse_args()

    root = logging.getLogger()
    logging.basicConfig()
    root.setLevel(logging.INFO)

    vt_key = '%s/.vt.key' % os.path.expanduser('~')
    api_key = ''

    if os.path.exists(vt_key):
        k = json.load(open(vt_key))
        api_key = k['key']
    else:
        log.error('Could not find file %s for API key.' % vt_key)
        log.error('Please create a JSON compliant file named \'.vt.key\' '
                  'in your home directory with \'key\' as the key name '
                  'and your VT API key as the value.')
        sys.exit(2)

    vt = VirusTotalAPI(api_key)

    if args.subparser_name == 'hash':
        process_hashes(args, vt)
    if args.subparser_name == 'net':
        process_net_indicators(args, vt)
    if args.subparser_name == 'bulk':
        process_bulk_query(args, vt)


if __name__ == '__main__':
    main()
