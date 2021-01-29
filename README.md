# Malchive #

The malchive serves as a compendium for a variety of capabilities mainly pertaining to malware analysis, such as scripts supporting day to day binary analysis and decoder modules for various components of malicious code.

The goals behind the 'malchive' are to:
* Allow teams to centralize efforts made in this realm and enforce communication and continuity
* Have a shared corpus of tools for people to build on
* Enforce clean coding practices
* Allow others to interface with project members to develop their own capabilities
* Promote a positive feedback loop between Threat Intel and Reverse Engineering staff
* Make static file analysis more accessible
* Serve as a vehicle to communicate the unique opportunity space identified via deep dive analysis

## Documentation ##

At its core, malchive is a bunch of standalone scripts organized in a manner that the authors hope promotes the project's goals.

To view the documentation associated with this project, **checkout the wiki page**!

Scripts within the malchive are split up into the following core categories:

* **Utilities** - These scripts may be run standalone to assist with static binary analysis or as modules supporting a broader program. Utilities always have a standalone component.
* **Helpers** - These modules primarily serve to assist components in one or more of the other categories. They generally do not have a stand-alone component and instead serve the intents of those that do.
* **Binary Decoders** - The purpose of scripts in this category is to retrieve, decrypt, and return embedded data (typically inside malware).
* **Active Discovery** - Standalone scripts designed to emulate a small portion of a malware family's protocol for the purposes of discovering active controllers.

## Installation ##

The malchive is a packaged distribution that is easily installed and will automatically create console stand-alone scripts.

### Steps ###

You will need to install some dependencies for some of the required Python modules to function correctly.
* First do a source install of [YARA](https://github.com/VirusTotal/yara/releases) and make sure you compile using `--dotnet`
* Next source install the [YARA Python](https://github.com/VirusTotal/yara-python/releases/) package.
* Ensure you have sqlite3-dev installed
    - Debian: libsqlite3-dev
    - Red Hat: sqlite-devel / `pip install pysqlite3`

You can then clone the malchive repo and install...
* `pip install .` when in the parent directory.
* To remove, just `pip uninstall malchive`

### Scripts ###

Console scripts stemming from `utilities` are appended with the prefix `malutil`, `decoders` are appended with `maldec`, and `active discovery` scripts are appended with `maldisc`. This allows for easily identifiable malchive scripts via tab autocompletion.

```buildoutcfg
; running superstrings from cmd line
malutil-superstrings 1.exe -ss
0x9535 (stack) lstrlenA
0x9592 (stack) GetFileSize
0x95dd (stack) WriteFile
0x963e (stack) CreateFileA
0x96b0 (stack) SetFilePointer
0x9707 (stack) GetSystemDirectoryA

; running a decoder from cmd line
maldec-pivy test.exe_
{
    "MD5": "2973ee05b13a575c06d23891ab83e067",
    "Config": {
        "PersistActiveSetupName": "StubPath",
        "DefaultBrowserKey": "SOFTWARE\\Classes\\http\\shell\\open\\command",
        "PersistActiveSetupKeyPart": "Software\\Microsoft\\Active Setup\\Installed Components\\",
        "ServerId": "TEST - WIN_XP",
        "Callbacks": [
            {
                "callback": "192.168.1.104",
                "protocol": "Direct",
                "port": 3333
            },
            {
                "callback": "192.168.1.111",
                "protocol": "Direct",
                "port": 4444
            }
        ],
        "ProxyCfgPresent": false,
        "Password": "test$321$",
        "Mutex": ")#V0qA.I4",
        "CopyAsADS": true,
        "Melt": true,
        "InjectPersist": true,
        "Inject": true
    }
}

; cmd line use with other common utilities
echo -ne 'eJw9kLFuwzAMRIEC7ZylrVGgRSFZiUbBZmwqsMUP0VfcnuQn+rMde7KLTBIPj0ce34tHyMUJjrnw
p3apz1kicjoJrDRlQihwOXmpL4RmSR5qhEU9MqvgWo8XqGMLJd+sKNQPK0dIGjK+e5WANIT6NeOs
k2mI5NmYAmcrkbn4oLPK5gZX+hVlRoKloMV20uQknv2EPunHKQtcig1cpHY4Jodie5pRViV+rp1t
629J6Dyu4hwLR97LINqY5rYILm1hhlvinoyJZavOKTrwBHTwpZ9yPSzidUiPt8PUTkZ0FBfayWLp
a71e8U8YDrbtu0aWDj+/eBOu+jRkYabX+3hPu9LZ5fb41T+7fmRf' | base64 -d | zlib-flate -uncompress | malutil-xor - [KEY]
```

### Interfacing ###

Utilities, decoders, and discovery scripts in this collection are designed to support single ad-hoc analysis as well as inclusion into other frameworks. After installation, the malchive should be part of your Python path. At this point accessing any of the scripts is straight forward.

Here are a few examples:

```buildoutcfg
; accessing decoder modules
import sys
from malchive.decoders import testdecoder

p = testdecoder.GetConfig(open(sys.argv[1], 'rb').read())
print('password', p.rc4_key)
for c in p.callbacks:
    print('c2 address', c)

; accessing utilities
from malchive.utilities import xor
ret = xor.GenericXor(buff=b'testing', key=[0x51], count=0xff)
print(ret.run_crypt())

; accessing helpers
from malchive.helpers import winfunc
key = winfunc.CryptDeriveKey(b'testdatatestdata')
```

To understand more about a given module, see the associated wiki entry.

## Contributing ##

Contributing to the malchive is easy, just ensure the following requirements are met:
* When writing utilities, decoders, or discovery scripts, consider using the [available templates](https://github.com/mitrecnd/malchive/blob/main/malchive/extras/) or review existing code if you're not sure how to get started.
* Make sure modification or contributions pass pre-commit tests.
* Ensure the contribution is placed in one of the component folders.
* Updated the setup file if needed with an entry.
* Python3 is a must.

## Legal ##

©2021 The MITRE Corporation. ALL RIGHTS RESERVED.

Approved for Public Release; Distribution Unlimited. Public Release Case Number 21-0153
