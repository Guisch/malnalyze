#!/usr/bin/env python3

import argparse
import os
import json
import hashlib
import ssdeep
import exiftool
import urllib.parse


def parse_args():
    parser = argparse.ArgumentParser(description="Fetch information from a file from various sources in a single "
                                                 "command")

    base_path = os.path.dirname(os.path.realpath(__file__))
    default_config_file = os.path.join(base_path, "config.json")

    parser.add_argument('--config', '-c',
                        nargs=1,
                        required=False,
                        default=default_config_file,
                        help=f'Path to config file (default={default_config_file})')
    parser.add_argument('files',
                        metavar='file',
                        type=argparse.FileType('rb'),
                        nargs='+',
                        help='Path to the file to analyze')

    args = parser.parse_args()

    return {
        'config_file_path': args.config,
        'files': args.files
    }


def read_json_file(file_path):
    file = open(file_path, "rb")
    file_json = json.load(file)
    file.close()

    return file_json


def hash_file_sha256(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()


def hash_file_sha1(file_bytes):
    return hashlib.sha1(file_bytes).hexdigest()


def hash_file_md5(file_bytes):
    return hashlib.md5(file_bytes).hexdigest()


def hash_file_ssdeep(file_bytes):
    return ssdeep.hash(file_bytes)


def get_metadata(file_path):
    with exiftool.ExifTool() as et:
        metadata = et.get_metadata(file_path)
    return metadata


def get_stat(file_path):
    s_obj = os.stat(file_path)
    return {k: getattr(s_obj, k) for k in dir(s_obj) if k.startswith('st_')}


def get_file_infos(file):
    file_bytes = file.read()
    file_infos = {
        'hash': {
            'md5': hash_file_md5(file_bytes),
            'sha1': hash_file_sha1(file_bytes),
            'sha256': hash_file_sha256(file_bytes),
            'ssdeep': hash_file_ssdeep(file_bytes),
        },
        'exiftool': get_metadata(file.name),
        'stat': get_stat(file.name)
    }

    return file_infos


def print_file_infos(infos):
    for cat in infos:
        print(cat.title() + " " + (80 - len(cat)) * "=")
        for key in infos[cat]:
            print(key + ": " + str(infos[cat][key]))
        print()


def check_vt_intel_search(infos, config):
    keys = [x for x in infos['exiftool']]

    for k in keys:
        if k not in config['virustotal']['intel_search']:
            config['virustotal']['intel_search'][k] = {
                'AND': False,
                'OR': False
            }

    return config


def get_vt(infos, config):
    vt_config = config['virustotal']
    url_base_search = vt_config['url_base_search']
    url_base_intel = vt_config['url_base_intel']

    metadata_AND = [f"metadata:{infos['exiftool'][x]}" for x in infos['exiftool'] if
                    vt_config['intel_search'][x]['AND']]
    metadata_OR = [f"metadata:{infos['exiftool'][x]}" for x in infos['exiftool'] if vt_config['intel_search'][x]['OR']]

    infos['virustotal'] = {
        'md5': url_base_search + urllib.parse.quote_plus(infos['hash']['md5']),
        'sha1': url_base_search + urllib.parse.quote_plus(infos['hash']['sha1']),
        'sha256': url_base_search + urllib.parse.quote_plus(infos['hash']['sha256']),
        'ssdeep': url_base_search + urllib.parse.quote_plus(infos['hash']['ssdeep']),
        'intel_AND': url_base_intel + urllib.parse.quote_plus(' AND '.join(metadata_AND)),
        'intel_OR': url_base_intel + urllib.parse.quote_plus(' OR '.join(metadata_OR))
    }

    return infos


def get_bazaar(infos, config):
    bz_config = config['bazaar']
    url_base_search = bz_config['url_base_search']

    infos['bazaar'] = {
        'md5': url_base_search + urllib.parse.quote_plus("md5:" + infos['hash']['md5']),
        'sha1': url_base_search + urllib.parse.quote_plus("sha1:" + infos['hash']['sha1']),
        'sha256': url_base_search + urllib.parse.quote_plus("sha256:" + infos['hash']['sha256']),
    }

    return infos


def get_hybridanalysis(infos, config):
    ha_config = config['hybridanalysis']
    url_base_search = ha_config['url_base_search']
    url_base_advanced_search = ha_config['url_base_advanced_search']

    infos['hybridanalysis'] = {
        'md5': url_base_search + urllib.parse.quote_plus(infos['hash']['md5']),
        'sha1': url_base_search + urllib.parse.quote_plus(infos['hash']['sha1']),
        'sha256': url_base_search + urllib.parse.quote_plus(infos['hash']['sha256']),
        'ssdeep': url_base_advanced_search + urllib.parse.quote_plus("terms[ssdeep]=" + infos['hash']['ssdeep']),
        'filename AND filetype': url_base_advanced_search +
                                 urllib.parse.quote_plus("terms[filename]=" + infos['exiftool']['File:FileName']) +
                                 "&" +
                                 urllib.parse.quote_plus("terms[filetype_desc]=" + infos['exiftool']['File:FileType'])
    }

    return infos


def main():
    options = parse_args()
    config = read_json_file(options['config_file_path'])

    for f in options['files']:
        infos = get_file_infos(f)
        config = check_vt_intel_search(infos, config)
        infos = get_vt(infos, config)
        infos = get_bazaar(infos, config)
        infos = get_hybridanalysis(infos, config)

        print_file_infos(infos)

    with open(options['config_file_path'], 'w') as f:
        json.dump(config, f, indent=4)


if __name__ == '__main__':
    main()
