# Malnalyze

A tool that gives hashes, exiftool data and links to online malware analyzer (such as VirusTotal)

- [Malnalyze](#malnalyze)
  * [Installation](#installation)
  * [Configuration](#configuration)
  * [Usage](#usage)


## Installation

Simply clone the repo and install dependency

```bash
$ sudo apt install libfuzzy-dev exiftool
$ git clone https://github.com/Guisch/malnalyze
$ cd malnalyze
$ pip3 install -r requirements.txt
```

## Configuration

The file `config.json` contains base url for online malware analyzer:
- Virustotal
- Malware Bazaar
- Hybrid Analysis

VirusTotal allows members with paid subscription to do some advanced search through their "intel" portal.
`intel_search` allow you to enable or disable the exiftool field in the `intel_OR` and `intel_AND` link.

## Usage

Check usage with `--help` command argument

```bash
$ python3 malnalyze.py --help
usage: malnalyze.py [-h] [--config CONFIG] file [file ...]

Fetch information from a file from various sources in a single command

positional arguments:
  file                  Path to the file to analyze

optional arguments:
  -h, --help            show this help message and exit
  --config CONFIG, -c CONFIG
                        Path to config file (default=.../malnalyze/config.json)
```

Example on the script itself

```bash
$ python3 malnalyze.py malnalyze.py
Hash ============================================================================
md5: 4a66235e6d40b881ed3d2234de632922
sha1: e778d14acaaf15e788b3fbd9ef697d57c3f576c7
sha256: e7ec4d7c3b992d0c0c60cef1db9707733b370e58b7a8bb0496bcd08a73b4ff48
ssdeep: 96:KJ6dhH2PJUm61wRIZut6hhPN1h5oLkHrzHceDCM:i6nH2PJUm614IZPHF1hlHrzHceOM

Exiftool ========================================================================
SourceFile: malnalyze.py
ExifTool:ExifToolVersion: 10.8
File:FileName: malnalyze.py
File:Directory: .
File:FileSize: 5612
File:FileModifyDate: 2021:02:10 19:09:47+01:00
File:FileAccessDate: 2021:02:09 19:39:29+01:00
File:FileInodeChangeDate: 2021:02:10 19:09:47+01:00
File:FilePermissions: 664
File:FileType: env script
File:FileTypeExtension:
File:MIMEType: text/x-env

Stat ============================================================================
st_atime: 1612895969.7980175
st_atime_ns: 1612895969798017489
st_blksize: 4096
st_blocks: 16
st_ctime: 1612980587.2524781
st_ctime_ns: 1612980587252478136
st_dev: 2052
st_gid: 1000
st_ino: 94634358
st_mode: 33204
st_mtime: 1612980587.2524781
st_mtime_ns: 1612980587252478136
st_nlink: 1
st_rdev: 0
st_size: 5612
st_uid: 1000

Virustotal ======================================================================
md5: https://www.virustotal.com/gui/search/4a66235e6d40b881ed3d2234de632922
sha1: https://www.virustotal.com/gui/search/e778d14acaaf15e788b3fbd9ef697d57c3f576c7
sha256: https://www.virustotal.com/gui/search/e7ec4d7c3b992d0c0c60cef1db9707733b370e58b7a8bb0496bcd08a73b4ff48
ssdeep: https://www.virustotal.com/gui/search/96%3AKJ6dhH2PJUm61wRIZut6hhPN1h5oLkHrzHceDCM%3Ai6nH2PJUm614IZPHF1hlHrzHceOM
intel_AND: https://www.virustotal.com/intelligence/search/?query=metadata%3Amalnalyze.py+AND+metadata%3Aenv+script
intel_OR: https://www.virustotal.com/intelligence/search/?query=

Bazaar ==========================================================================
md5: https://bazaar.abuse.ch/browse.php?search=md5%3A4a66235e6d40b881ed3d2234de632922
sha1: https://bazaar.abuse.ch/browse.php?search=sha1%3Ae778d14acaaf15e788b3fbd9ef697d57c3f576c7
sha256: https://bazaar.abuse.ch/browse.php?search=sha256%3Ae7ec4d7c3b992d0c0c60cef1db9707733b370e58b7a8bb0496bcd08a73b4ff48

Hybridanalysis ==================================================================
md5: https://www.hybrid-analysis.com/search?query=4a66235e6d40b881ed3d2234de632922
sha1: https://www.hybrid-analysis.com/search?query=e778d14acaaf15e788b3fbd9ef697d57c3f576c7
sha256: https://www.hybrid-analysis.com/search?query=e7ec4d7c3b992d0c0c60cef1db9707733b370e58b7a8bb0496bcd08a73b4ff48
ssdeep: https://www.hybrid-analysis.com/advanced-search-results?terms%5Bssdeep%5D%3D96%3AKJ6dhH2PJUm61wRIZut6hhPN1h5oLkHrzHceDCM%3Ai6nH2PJUm614IZPHF1hlHrzHceOM
filename AND filetype: https://www.hybrid-analysis.com/advanced-search-results?terms%5Bfilename%5D%3Dmalnalyze.py&terms%5Bfiletype_desc%5D%3Denv+script

```