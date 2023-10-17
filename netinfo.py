import argparse
import json
import os
import pwd
import re
import socket
import subprocess
import psutil
from colorama import Fore, Back, Style, init



program_info = {}
# Load program_info from JSON file
with open("program_info.json", "r") as file:
    program_info = json.load(file)

init()


def get_host_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip


def get_port_status(port):
    if port == 'None':
        return 'None'
    elif port == 'Unusual':
        return 'Unusual'
    elif port.isdigit():
        return 'Normal'
    else:
        return 'Unknown'


def get_protocol_name(port):
    try:
        # Get the protocol name for the given port number
        protocol_name = socket.getservbyport(port)
        return protocol_name
    except (socket.error, socket.herror, socket.gaierror, socket.timeout):
        return "Unknown"


def to_int(s):
    try:
        v = int(s)
        return v
    except ValueError:
        return 0


def get_network_info():
    # Get program connections
    special_hosts = {'0.0.0.0': 'all IP4',
                     '*': 'all IP',
                     '[::]': 'all IP6',
                     '[::ffff:127.0.0.1]': 'IP6 localhost'
                     }

    programs = {}
    connections = []
    try:
        output = subprocess.check_output(['ss', '-tupenO', '--tcp', 'state', 'established', 'state', 'listening'])
        lines = output.decode().split('\n')[1:-1]
        for line in lines:

            parts = line.split()
            protocol = parts[0]
            state = parts[1]
            laddr = parts[4]
            raddr = parts[5]

            version = 'all'
            name = ''
            uid = ''
            pid = ''
            username = 'Unknown'

            if laddr[0] == '[':
                version = '6'
            elif laddr[0].isdigit():
                version = '4'

            for p in parts[6:]:
                if p == 'v6only:1':
                    version = '6'
                elif p.startswith('uid:'):
                    uid = p[4:]
                    try:
                        # Retrieve the username associated with the UID
                        user_info = pwd.getpwuid(int(uid))
                        username = user_info.pw_name
                    except KeyError:
                        pass
                elif p.startswith('users:'):
                    # Use regular expressions to extract program names and PIDs
                    matches = re.findall(r'\(\"([^\"]+)\",pid=(\d+)', p)

                    # Extracted data
                    program_names = [match[0] for match in matches]
                    pids = [int(match[1]) for match in matches]
                    # print("=========================================")
                    # print("Program Names:", program_names)
                    # print("PIDs:", pids)

            pid = pids[0]
            protocol += version

            if pid in programs:
                program = programs[pid]
                # print(f"old program {program['pids']}")
            else:
                # print(f"new program >{pids}<")
                program_name = program_names[0]
                if program_name in program_info:
                    # print(f"about to get description from {program_name}: {program_info[program_name]}")
                    description = program_info[program_name]['description']
                else:
                    description = 'We have no information about this program'
                program = {'pids': pids,
                           'pid': pids,
                           'names': program_names,
                           'name': program_name,
                           'uid': uid,
                           'username': username,
                           'listen': [],
                           'established': [],
                           'description': description
                           }

                # access via any pid
                for pid in pids:
                    programs[pid] = program

            (lhost, lport) = laddr.rsplit(':', 1)
            (rhost, rport) = raddr.rsplit(':', 1)

            lprot = get_protocol_name(to_int(lport))
            rprot = get_protocol_name(to_int(rport))
            # print(f"lport:{lport}({lprot}) <---> rport:{rport}({rprot})")
            #
            if rhost in special_hosts:
                hostname = special_hosts[rhost]
            else:
                try:
                    hostname, _, _ = socket.gethostbyaddr(rhost)
                    # print(f"The hostname for IP address {rhost} is {hostname}")
                except (socket.herror, socket.gaierror):
                    # print(f"Could not resolve the hostname for IP address {rhost}")
                    hostname = 'unknown'

            conn = {
                'protocol': protocol,
                'lport': lport,
                'lprot': lprot,
                'rhost': rhost,
                'rname': hostname,
                'rport': rport,
                'rprot': rprot
            }
            if state == 'LISTEN':
                program['listen'].append([protocol, lport])
                # print(f"{program_names[0]} listen ++>{conn}<++")
            else:
                # print(f"before len={len(program['established'])}")
                program['established'].append(conn)
                # print(f"after len={len(program['established'])}")
                # print(f"{program['name']} added established ++>{conn}<++")
                # for conn in program['established']:
                #     print(f"{conn} ")

    except subprocess.CalledProcessError:
        pass

    return programs

def qualify_network_connections(network_info):
    done = []
    for (pid, pgm) in network_info.items():
        if pid in done:
            continue
        done.extend(pgm['pids'])
        pgm['Behavior'] = 'Normal'
        name = pgm['name']
        if name not in program_info:
            pgm['Behavior'] = 'Unusual'
            for c in pgm['established']:
                c['Behavior'] = 'Unusual'
            pgm['Behavior_Listen'] = 'Unusual'
            continue

        pgm_behavior = program_info[name]
        pgm['Behavior'] = 'Normal'
        for k, behavior_items in pgm_behavior.items():
            if k == 'username':
                if pgm['username'] != behavior_items:
                    pgm['Behavior'] = 'Unusual'
                    continue

            elif k == 'listen':
                pgm['Behavior_Listen'] = 'Normal'
                for p in pgm['listen']:
                    if p not in behavior_items:
                        pgm['Behavior_Listen'] = 'Unusual'
                        continue

            elif k == 'established':
                for c in pgm['established']:
                    c['Behavior'] = 'Normal'
                    for p, pv in behavior_items.items():
                        # print(f"About to check if {c[p]} in {pv} >>> {c[p] in pv} <<< {type(c[p])} == {type(pv[0])}")
                        if c[p] not in pv:
                            c['Behavior'] = 'Unusual'
                            continue


RESET = Style.RESET_ALL


colors = {'Prog': {"Normal": Fore.WHITE, 'Unusual': Fore.CYAN},
          'Desc': {"Normal": Fore.WHITE, 'Unusual': Fore.CYAN},
          'List': {"Normal": Fore.GREEN, 'Unusual': Fore.CYAN},
          'lpor': {"Normal": Fore.GREEN, 'Unusual': Fore.CYAN},
          }


BOX_COLOR = Fore.BLUE
width = os.get_terminal_size().columns


def fbl(text, behavior):
    line_color = colors[text[:4]][behavior]
    return f"{BOX_COLOR}│{RESET} {line_color}{text.ljust(width - 5)}{RESET} {BOX_COLOR}│{RESET}"


def print_network_info(network_info, output: str = 'text'):
    print(f"netinfo.py --output={output} ")
    if output == 'text':
        for (pid, pgm) in network_info.items():
            print("")
            print(f"Program: {pgm['name']} ({pid})")
            print(f"UID: {pgm['uid']}, User: {pgm['username']}")
            ll = pgm['listen']
            if len(ll) == 0:
                print(f"Listening Ports: None")
            else:
                print(f"Listening Ports: ['{pgm['listen'][0][0]}', '{pgm['listen'][0][1]}']")

            for conn in pgm['established']:
                host = f"{conn['rhost']}({conn['rname']})"
                print(f"lport:{conn['lport'].ljust(15)} host:{host.ljust(45)} port:{conn['rport'].ljust(15)}  ")
            print()
    elif output == 'box':
        # Get terminal width
        is_open = False

        done = []
        for (pid, pgm) in network_info.items():
            if pid in done:
                continue

            done.extend(pgm['pids'])
            if is_open:
                print(f"{Fore.BLUE}└" + "─" * (width - 3) + f"┘{RESET}")
            is_open = True
            print(f"{Fore.BLUE}┌" + "─" * (width - 3) + f"┐{RESET}")
            print(fbl(f"Program: {pgm['name']} ({pid}) UID: {pgm['uid']}, User: {pgm['username']} {pgm['Behavior']}", pgm['Behavior']))
            print(fbl(f"Description: {pgm['description']}", pgm['Behavior']))
            ll = pgm['listen']
            if len(ll) == 0:
                print(fbl(f"Listening Ports: None {pgm['Behavior_Listen']}", pgm['Behavior_Listen']))
            else:
                print(fbl(f"Listening Ports: ['{pgm['listen'][0][0]}', '{pgm['listen'][0][1]}'] {pgm['Behavior_Listen']}", pgm['Behavior_Listen']))

            for conn in pgm['established']:
                host = f"{conn['rhost']}({conn['rname']})"
                # print(conn)

                lp = f"lport:{conn['lport']}"
                if conn['lprot'] != 'Unknown':
                    lp += f"({conn['lprot']})"
                lp = f"{lp.ljust(35)}"

                rp = f"port:{conn['rport']}"
                if conn['rprot'] != 'Unknown':
                    rp = f"{rp}({conn['rprot']})"
                rp = f"{rp.ljust(35)}"

                cline = f"{lp} host:{host.ljust(60)} {rp} {conn['Behavior']}"

                print(fbl(cline, conn['Behavior']))

        print(f"{Fore.BLUE}└" + "─" * (width - 3) + f"┘{RESET}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Display Network Information")
    parser.add_argument("--output", type=str, help="Type of output to generate")
    args = parser.parse_args()
    output = args.output
    network_info = get_network_info()
    qualify_network_connections(network_info)
    print_network_info(network_info, output=output)