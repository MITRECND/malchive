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

# flake8: noqa

from setuptools import setup

# --- SCRIPTS ----------------------------------------------------------------

# Entry points to create convenient scripts automatically

entry_points = {
    'console_scripts': [
        # decoders
        'maldec-pivy=malchive.decoders.pivy:main',
        'maldec-cobaltstrike_payload=malchive.decoders.cobaltstrike_payload:main',
        'maldec-sunburst=malchive.decoders.sunburst:main',
        'maldec-sunburst_dga=malchive.decoders.sunburst_dga:main',
        'maldec-apollo=malchive.decoders.apollo:main',
        'maldec-rzstreet_dumper=malchive.decoders.rzstreet_dumper:main',

        # utilities
        'malutil-add=malchive.utilities.add:main',
        'malutil-apihash=malchive.utilities.apihash:main',
        'malutil-byteflip=malchive.utilities.byteflip:main',
        'malutil-comguidtoyara=malchive.utilities.comguidtoyara:main',
        'malutil-petimestamp=malchive.utilities.petimestamp:main',
        'malutil-entropycalc=malchive.utilities.entropycalc:main',
        'malutil-findapihash=malchive.utilities.findapihash:main',
        'malutil-genrsa=malchive.utilities.genrsa:main',
        'malutil-gensig=malchive.utilities.gensig:main',
        'malutil-hiddencab=malchive.utilities.hiddencab:main',
        'malutil-killaslr=malchive.utilities.killaslr:main',
        'malutil-negate=malchive.utilities.negate:main',
        'malutil-rotate=malchive.utilities.rotate:main',
        'malutil-sub=malchive.utilities.sub:main',
        'malutil-superstrings=malchive.utilities.superstrings:main',
        'malutil-vtinspect=malchive.utilities.vtinspect:main',
        'malutil-xor=malchive.utilities.xor:main',
        'malutil-xor-pairwise=malchive.utilities.xor_pairwise:main',
        'malutil-dotnetdumper=malchive.utilities.dotnetdumper:main',
        'malutil-aplibdumper=malchive.utilities.aplibdumper:main',
        'malutil-peresources=malchive.utilities.peresources:main',
        'malutil-pepdb=malchive.utilities.pepdb:main',
        'malutil-b64dump=malchive.utilities.b64dump:main',
        'malutil-cobaltstrike_malleable_restore=malchive.utilities.cobaltstrike_malleable_restore:main',
        'malutil-ssl_cert=malchive.utilities.ssl_cert:main',
        'malutil-brute_xor=malchive.utilities.brute_xor:main',
        'malutil-hashes=malchive.utilities.hashes:main',
        'malutil-pecarver=malchive.utilities.pecarver:main',
        'malutil-reverse_bytes=malchive.utilities.reverse_bytes:main',
        'malutil-guid_recovery=malchive.utilities.guid_recovery:main',

        # active discovery
        'maldisc-meterpreter_reverse_shell=malchive.active_discovery.meterpreter_reverse_shell:main',
        'maldisc-spivy=malchive.active_discovery.spivy:main',
        'maldisc-cobaltstrike_beacon=malchive.active_discovery.cobaltstrike_beacon:main',
        'maldisc-shadowpad=malchive.active_discovery.shadowpad:main',
    ],
}

# --- PACKAGES ---------------------------------------------------------------

packages = [
        'malchive',
        'malchive.utilities',
        'malchive.helpers',
        'malchive.decoders',
        'malchive.active_discovery',
        ]

install_requires = [
        'asyncio',
        'async_timeout',
        'aiohttp',
        'asyncio_dgram',
        'cffi',
        'timeout',
        'pefile>=2023.2.7',
        'capstone',
        'tabulate',
        'progressbar2',
        'pycryptodome',
        'python-registry',
        'requests',
        'netstruct',
        'pysqlite3',
        'ipaddress',
        'netaddr',
        'validators',
        'py-tlsh',
        'tld',
]


def main():

    setup(
        name='malchive',
        version='2.1',
        packages=packages,
        include_package_data=True,
        python_requires='>=3.11',
        extras_require={
            'extras': ['python-camellia'],
            },
        install_requires=install_requires,
        url='https://github.com/MITRECND/malchive',
        license='Copyright 2021 The MITRE Corporation. All rights reserved.',
        author='MITRE CTAC',
        description='Malware analysis tools, libraries, and decoders.',
        entry_points=entry_points,
        download_url='https://github.com/MITRECND/malchive',
    )


if __name__ == "__main__":
    main()
