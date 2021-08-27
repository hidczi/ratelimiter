#!/usr/bin/env python3


import telnetlib
import time
import re
import subprocess as sp
import argparse
import readline
import signal


# re variables
answer_re = r'^[yYnN]$'
ip_re = r'(:?(2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)$'
hostname_re = r'(:?\d\d-[A-Z]+-[A-Z]+\d+-[A-Z]+-\d$)'
subscriber_id_re = '7\d{10}'

username = 'username'
password = 'password'

prompt = f'\033[94m\nratelimiter$\033[00m'

parser = argparse.ArgumentParser(description='profchan')

parser.add_argument('ip', help='IP address or hostname')
parser.add_argument('-l', dest='limit', help='the name of the poliсer')
parser.add_argument('-s', dest='subscriber_id', help='subscriber id')

args = parser.parse_args()

ip = args.ip
limit = args.limit
subscriber_id = args.subscriber_id

def signal_handler(sig, frame):
    print('\r')
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

def to_bytes(line):
    return f'{line}\n'.encode('utf-8')

def preprint(output):
    output = output.replace("\r\n", "\n")
    output = re.sub('\\n\\n\{master\}', '', output)
    return output

def limitchecker(subif_conf, limit, telnet):
    print(subif_conf)
    while True:
        show_policer = f'show configuration firewall | no-more'

        telnet.write(to_bytes(show_policer))
        time.sleep(3)
        poliсers_config = telnet.read_very_eager().decode('utf-8')
        if not re.findall(limit, poliсers_config):
            print(f'{prompt} the filter with the name {limit} was not found')
            limit = limit_input()
            continue
        else:
            if re.findall(limit, subif_conf):
                print(f'{prompt} the port configuration matches the selected profile')
                answer = input(f'{prompt} re-input? y/n: ')
                if not re.match(answer_re, answer):
                    print(f'{prompt} invalid value.')
                    continue
                else:
                    if answer.lower() == 'n':
                        exit(0)
                    else:
                        limit = limit_input()
                        continue
            else:
                break
    return limit

def sid_input():
    while True:
        subscriber_id = input(f'{prompt} subscriber id: ')
        if not re.match(subscriber_id_re, subscriber_id):
            print(f'{prompt} invalid value for subscriber id')
            while True:
                answer = input(f'{prompt} re-input? y/n: ')
                if not re.match(answer_re, answer):
                    print(f'{prompt} invalid value.')
                    continue
                else:
                    if answer.lower() == 'n':
                        exit(0)
                    else:
                        break
        else:
            break
    return subscriber_id

def limit_input():
    limit = input(f'{prompt} name of the poliсer: ')
    return limit

def shandchint(ip, username, password, subscriber_id, limit):
    with telnetlib.Telnet(ip) as telnet:
        print(f'{prompt} looking for. wait, please')
        search_command = f'show interfaces descriptions | match {subscriber_id}'

        telnet.read_until(b'ogin:')
        telnet.write(to_bytes(username))
        telnet.read_until(b'assword:')
        telnet.write(to_bytes(password))


        time.sleep(1)
        telnet.write(to_bytes(search_command))
        time.sleep(12)
        subif = telnet.read_very_eager().decode('utf-8')
        subif = re.findall(r'ae\d+\.\d+', subif)
        subif = subif[0]

        if subif == 'None':
            print('no matches found')
        else:
            sh_conf_int = f'show configuration interfaces {subif}'

            telnet.write(to_bytes(sh_conf_int))
            subif_conf = telnet.read_until(b"{master}").decode('utf-8')
            to_preprint = re.sub(r'.* ae\d+\.\d+.*', f'\ninterfaces {subif}: \n', subif_conf)
            subif_conf = preprint(to_preprint)
            limit = limitchecker(subif_conf, limit, telnet)
            while True:
                answer = input(f'{prompt} right? y/n: ')
                if not re.match(answer_re, answer):
                    print(f'{prompt} invalid value.')
                    continue
                else:
                    if answer.lower() == 'n':
                        exit(0)
                    else:
                        sh_conf_policer = f'show configuration firewall policer {limit}'

                        telnet.write(to_bytes(sh_conf_policer))
                        i, m, output = telnet.expect([b'{master}'], timeout=3)
                        to_preprint = output.decode('utf8')
                        to_preprint = re.sub(r'.*wall policer.*', f'\npolicer {limit}: \n', to_preprint)
                        policer_config = preprint(to_preprint)

                        print(policer_config)

                        while True:
                            answer = input(f'{prompt} change rate limit? y/n: ')
                            if not re.match(answer_re, answer):
                                print(f'{prompt} invalid value.')
                                continue
                            else:
                                if answer.lower() == 'n':
                                    exit(0)
                                else:
                                    edit_int = f'edit interfaces {subif}\n'
                                    edit_policer = f'edit family inet policer\n'
                                    bandwidth = f'set bandwidth {limit.lower()}\n'
                                    setinput = f'set input {limit}\n'
                                    setoutput = f'set output {limit}\n'

                                    telnet.write(b'configure private\n')
                                    telnet.write(to_bytes(edit_int))
                                    telnet.write(to_bytes(bandwidth))
                                    telnet.write(to_bytes(edit_policer))
                                    telnet.write(to_bytes(setinput))
                                    telnet.write(to_bytes(setoutput))
                                    telnet.write(b'top\n')
                                    time.sleep(1)
                                    input_config = telnet.read_very_eager().decode('utf-8')

                                    telnet.write(b'show | compare\n')
                                    i, m, output = telnet.expect([b'{master}'], timeout=15)
                                    to_preprint = output.decode('utf-8')
                                    to_preprint = re.sub(r'show \| compare', f'\nshow | compare:\n', to_preprint)
                                    show_comp = preprint(to_preprint)
                                    print(show_comp)

                                    telnet.write(b'commit check\n')
                                    i, m, output = telnet.expect([b'{master}'], timeout=30)
                                    to_preprint = output.decode('utf-8')
                                    to_preprint = re.sub(r'.*# commit check', f'\ncommit check:\n', to_preprint)
                                    commit_check = preprint(to_preprint)
                                    if not re.findall(r'succeeds', commit_check):
                                        print(commit_check)
                                        telnet.write(b'rollback\n')
                                        telnet.write(b'quit\n')
                                        telnet.write(b'quit\n')
                                        print(f'{prompt} configuration rollback' f'{prompt} bye-bye\n')
                                        exit(0)
                                    else:
                                        print(commit_check)

                                        while True:
                                            answer = input(f'{prompt} go? y/n: ')
                                            if not re.match(answer_re, answer):
                                                print(f'{prompt} invalid value.')
                                                continue
                                            else:
                                                if answer.lower() == 'n':
                                                    exit(0)
                                                else:
                                                    telnet.read_until(b'#')
                                                    telnet.write(b'commit and-quit\n')
                                                    i, m, output = telnet.expect([b'{master}'] , timeout=20)
                                                    to_preprint = output.decode('utf-8')
                                                    to_preprint = re.sub(r'.*commit and-quit', f'\ncommit and-quit:\n', to_preprint)
                                                    commit_qiut = preprint(to_preprint)
                                                    print(f'{commit_qiut}\n')
                                                    break
                                    break
                            break
                        break

status, result = sp.getstatusoutput('ping -c1 -w2 ' + str(args.ip))
if status != 0:
    print(f'{prompt} the {args.ip} is unavailable.\n')
    exit(0)

if not re.match(ip_re, args.ip) and not re.match(hostname_re, args.ip):
    print(f'{prompt} {args.ip} cannot be an IP address hostname.\n')
    exit(1)

if subscriber_id == None:
    subscriber_id = sid_input()

if limit == None:
    limit = limit_input()

shandchint(ip, username, password, subscriber_id, limit)
