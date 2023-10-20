import json
import curses
import os
import subprocess
from docopt import docopt
import socket
from colored import fore, back, style

query = ''' 
SELECT 
    p.pid,
    p.name AS program_name,
    p.uid,
    p.gid,
    u.username,
    os.local_address,
    os.local_port,
    s.name AS local_service,
    os.remote_address,
    os.remote_port,
    sr.name AS remote_service,
    os.state,
    CASE os.protocol
        WHEN 1 THEN 'icmp'
        WHEN 6 THEN 'tcp'
        WHEN 17 THEN 'udp'
        ELSE 'unknown'
    END AS protocol
FROM processes p
JOIN process_open_sockets os ON p.pid = os.pid
LEFT JOIN users u ON p.uid = u.uid
LEFT JOIN etc_services s ON os.local_port = s.port AND (CASE os.protocol WHEN 6 THEN 'tcp' WHEN 17 THEN 'udp' ELSE 'unknown' END) = s.protocol
LEFT JOIN etc_services sr ON os.remote_port = sr.port AND (CASE os.protocol WHEN 6 THEN 'tcp' WHEN 17 THEN 'udp' ELSE 'unknown' END) = sr.protocol
WHERE os.state = 'LISTEN' OR os.state = 'ESTABLISHED'
ORDER BY p.pid, os.state Desc;
'''


def fetch_network_info():
    # Using osquery to get the list of all programs with established and/or listening ports
    cmd = ['osqueryi', '--json', query]
    result = subprocess.check_output(cmd)
    return json.loads(result)


no_info = {"user": "Unknown",
           "listen": [],
           "established": {},
           "description": "No Information Available",
           "documentation_link": "https://github.com/JerryWestrick/netinfo"
           }


def compare_output(expected_program_info, network_data):
    output = []
    last_program = ''
    expected_info = None
    rports = []
    lports = []
    listen = []
    pl = []
    behavior = 'Normal'

    for entry in network_data:
        program_name = entry['program_name']

        if last_program != program_name:  # Program Break
            if last_program != '':  # Write last program
                output.append(pl)
                pl = []

            last_program = program_name  # This Program is now last

            behavior = 'Normal'
            expected_info = expected_program_info.get(program_name, no_info)
            if expected_info == no_info:
                behavior = 'Unusual'
                rports = []
                lports = []
                listen = []
            else:
                established = expected_info.get('established', {})
                # print(f"expected_info: {expected_info}")
                listen = expected_info.get('listen', None)
                rports = established.get('rport', None)
                lports = established.get('lport', None)

            pl.append(
                (behavior, f"Program: {program_name} ({entry['pid']}) UID: {entry['uid']}, User: {entry['username']}"))
            pl.append((behavior, f"Descrip: {expected_info['description']}"))

        ls = entry['local_service']
        if ls != '':
            ls = f"({ls})"
        loc = f"{entry['local_port']}{ls}"

        if entry['state'] == 'LISTEN':
            if listen and entry['local_port'] in listen:
                pl.append(('Normal', f"Listen :  {entry['local_address']}:{entry['local_port']}{ls}"))
            else:
                pl.append(('Unusual', f"Listen :  {entry['local_address']}{entry['local_port']}{ls} Unusual"))

        if entry['state'] == 'ESTABLISHED':
            if lports:
                if entry['local_port'] not in lports:
                    behavior = 'Unusual'
            if rports:
                if entry['remote_port'] not in rports:
                    behavior = 'Unusual'

            remote_host = ''
            try:
                remote_host = socket.gethostbyaddr(entry['remote_address'])[0]
            except (socket.herror, OSError):
                pass
            if remote_host != '':
                remote_host = f"({remote_host})"

            rs = entry['remote_service']
            if rs != '':
                rs = f"({rs})"

            rem = f"{entry['remote_address']}{remote_host}:{entry['remote_port']}{rs}"
            pl.append((behavior, f"Connect: {loc.ljust(35)} remote: {rem.ljust(70)}"))

    if last_program != '':
        output.append(pl)
    return output


def print_text(output):
    for p in output:
        print()
        for b, l in p:
            print(l, b)


R = style('reset')
B = fore('steel_blue')


def c(k, n):
    colors = {
        "P_N": fore('white'),
        "P_U": fore('dark_turquoise'),
        "D_N": fore('white'),
        "D_U": fore('dark_turquoise'),
        "L_N": fore('green'),
        "L_U": fore('dark_turquoise'),
        "C_N": fore('green'),
        "C_U": fore('dark_turquoise'),
        "B_N": fore('green'),
        "B_U": fore('dark_turquoise'),
    }

    color = f"{k}_{n}"
    return colors[color]


width = os.get_terminal_size().columns
max_text_width = width - 12     # 2 (Bar and space), 8 (len('Unusual') and space) 2 (space and Bar)


def print_box_long_description(line, b):
    first_char = line[0]
    words = line.split()
    lp = words.pop(0)
    while len(words):
        if len(lp) + len(words[0]) < max_text_width:
            lp = f"{lp} {words.pop(0)}"
        else:
            print(f"{B}│ {c(first_char, b[0])}{lp.ljust(max_text_width)} {c('B', b[0])}{b.rjust(7)} {B}│{R}")
            lp = '        '
    if len(lp) > 0:
        print(f"{B}│ {c(first_char, b[0])}{lp.ljust(max_text_width)} {c('B', b[0])}{b.rjust(7)} {B}│{R}")

def print_box(output):
    for p in output:
        print(f"{B}┌" + "─" * (width - 2) + f"┐{R}")
        for b, l in p:
            if len(l) > max_text_width:
                print_box_long_description(l, b)
            else:
                print(f"{B}│ {c(l[0], b[0])}{l.ljust(max_text_width)} {c('B', b[0])}{b.rjust(7)} {B}│{R}")

        print(f"{B}└" + "─" * (width - 2) + f"┘{R}")



def cp(line, behavior):
    cpd = {'P': 1, 'D': 2, 'L': 3, 'C': 4}
    rv = cpd[line]
    if behavior == 'U':
        rv += 5
    return rv


# Function to draw a box based on the provided content
def draw_box(win, content, max_x, selected):

    bcp = 5
    if selected:
        bcp = 10

    win.addstr("┌" + "─" * (max_x - 2) + "┐\n", curses.color_pair(bcp))
    for behavior, text in content:
        win.addstr("│ ", curses.color_pair(bcp))
        win.addstr(f"{text.ljust(max_x - 12)} {behavior.rjust(7)}", curses.color_pair(cp(text[0], behavior[0])))
        win.addstr(" │\n", curses.color_pair(bcp))
    win.addstr(f"└" + "─" * (max_x - 2) + f"┘\n", curses.color_pair(bcp))
    return len(content) + 2


ChosenProgram = None


def display_programs(stdscr, output):
    # Initialize colors and set up the screen
    curses.start_color()
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)     # Program Normal
    curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_BLACK)     # Description Normal
    curses.init_pair(3, curses.COLOR_GREEN, curses.COLOR_BLACK)     # Listening Normal
    curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK)     # Established Normal
    curses.init_pair(5, curses.COLOR_BLUE, curses.COLOR_BLACK)      # Box Default
    curses.init_pair(6, curses.COLOR_YELLOW, curses.COLOR_BLACK)    # Program Unusual
    curses.init_pair(7, curses.COLOR_YELLOW, curses.COLOR_BLACK)    # Description Unusual
    curses.init_pair(8, curses.COLOR_BLUE, curses.COLOR_BLACK)      # Listening Unusual
    curses.init_pair(9, curses.COLOR_BLUE, curses.COLOR_BLACK)      # Established Unusual
    curses.init_pair(10, curses.COLOR_WHITE, curses.COLOR_BLACK)    # Box Selected
    curses.curs_set(0)  # Hide cursor
    stdscr.clear()

    # Create window for the boxes
    max_y, max_x = stdscr.getmaxyx()
    box_win = curses.newwin(max_y - 2, max_x - 3, 1, 1)
    box_win.scrollok(True)

    selected = 0
    top_of_page = 0
    bottom_of_page = 0

    def redraw_boxes(top, sel):
        box_win.clear()

        # Draw as many boxes as fit in box_window
        bop = top
        free_lines = max_y
        for pgm in output[top:]:
            if free_lines > len(pgm):
                free_lines = free_lines - draw_box(box_win, pgm, max_x - 4, sel == bop)
                bop += 1
            else:
                draw_box(box_win, pgm[:free_lines], max_x - 4, False)
                break
        box_win.refresh()
        return bop

    while True:
        bottom_of_page = redraw_boxes(top_of_page, selected)

        key = stdscr.getch()

        if key == curses.KEY_UP and selected > 0:
            selected -= 1
            if selected < top_of_page:
                top_of_page = selected
        elif key == curses.KEY_DOWN and selected < len(output):
            selected += 1
            if selected > bottom_of_page:
                top_of_page = top_of_page + 1

        elif key == curses.KEY_ENTER or key in [10, 13]:  # Enter key
            # Future implementation: Display detailed info about the selected program or execute "explain" routine
            return output[selected]
            break


__doc__ = """ 
ninfo.py  
Usage:
    ninfo.py (text|box|curses)

Options: 
    -h, --help              Show this help message. 
"""


def main():
    arguments = docopt(__doc__, version='Example 1')

    # Load Program descriptions
    with open("program_info.json", 'r') as f:
        expected_program_info = json.load(f)

    # fetch network information
    network_data = fetch_network_info()
    # print(tabulate(network_data, headers="keys", tablefmt="fancy_grid"))

    # compare expected behavior to current network
    output = compare_output(expected_program_info, network_data)

    if arguments['curses']:
        # Run the interactive session
        pgm = curses.wrapper(display_programs,  output)

        print_box([pgm])

    if arguments['text']:
        print_text(output)

    if arguments['box']:
        print_box(output)


if __name__ == '__main__':
    main()
