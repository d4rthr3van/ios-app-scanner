import subprocess

import magic
from colorama import Fore, Style


def run_otool_command(command_arguments):
    result = subprocess.run(args=command_arguments, stdout=subprocess.PIPE)
    return result.stdout.decode()


def pie_flag(otool_result):
    if otool_result.find('PIE') != -1:
        print(Fore.GREEN + 'ANALYSIS : PIE check - PIE flag is present on the binary' + Fore.RESET)
    else:
        print(Fore.RED + 'ANALYSIS : PIE check - PIE flag is not present on the binary' + Fore.RESET)


def stack_canaries(otool_result):
    chk_fail = otool_result.find('stack_chk_fail')
    chk_guard = otool_result.find('stack_chk_guard')
    if chk_guard != -1 and chk_fail != -1:
        print(Fore.GREEN + 'ANALYSIS : Canaries check - Stack Canaries flag is present on the binary' + Fore.RESET)
    else:
        print(Fore.RED + 'ANALYSIS : Canaries check - Stack Canaries flag is not present on the binary' + Fore.RESET)


def arc_flag(otool_result):
    if otool_result.find('objc_release') != -1:
        print(
            Fore.GREEN + 'ANALYSIS : ARC Check - Automatic Reference Counting flag is present on the binary' + Fore.RESET)
    else:
        print(
            Fore.RED + 'ANALYSIS : ARC Check - Automatic Reference Counting flag is not present on the binary' + Fore.RESET)


def encrypted_binary(otool_result):
    if otool_result.find('cryptid 1') != -1:
        print(Fore.GREEN + 'ANALYSIS : Encryption check - The binary is encrypted' + Fore.RESET)
    else:
        print(Fore.RED + 'ANALYSIS : Encryption check - The binary is not encrypted' + Fore.RESET)


def weak_hashing(otool_result):
    vulnerable_hashing_function_list = ['_CC_MD5', '_CC_SHA1']
    for element in vulnerable_hashing_function_list:
        if otool_result.find(element) != -1:
            print(
                Fore.RED + 'ANALYSIS : Hashing function Check - \'{func}\' hashing function found on the binary'.format(
                    func=element) + Fore.RESET)
        else:
            print(
                Fore.GREEN + 'ANALYSIS : Hashing function Check - \'{func}\' hashing function NOT found on the binary'.format(
                    func=element) + Fore.RESET)


def insecure_random(otool_result):
    output_random = otool_result.find('_random')
    output_srand = otool_result.find('_srand')
    output_rand = otool_result.find('_rand')
    if output_random != -1 or output_srand != -1 or output_rand != -1:
        print(Fore.RED + 'ANALYSIS : Insecure random Check - Insecure random function found on the binary' + Fore.RESET)
    else:
        print(
            Fore.GREEN + 'ANALYSIS : Insecure random Check - Insecure random function NOT found on the binary' + Fore.RESET)


def get_language(otool_result):
    if otool_result.find('swift') != -1:
        print(Fore.BLUE + 'INFO: SWIFT language used to develop the application' + Fore.RESET)
    else:
        print(Fore.BLUE + 'INFO : No SWIFT language used to develop the application' + Fore.RESET)


def vulnerable_functions(otool_result):
    vulnerable_functions_list = ['_malloc', '_gets', '_memcpy', '_strncpy', '_strlen', '_vsnprintf', '_sscanf',
                                 '_strtok',
                                 '_alloca', '_sprintf', '_printf', '_vsprintf']
    for element in vulnerable_functions_list:
        if otool_result.find(element) != -1:
            print(Fore.RED + 'ANALYSIS : Unsafe functions Check - \'{func}\' function found on the binary'.format(
                func=element) + Fore.RESET)
        else:
            print(Fore.GREEN + 'ANALYSIS : Unsafe functions Check - \'{func}\' function NOT found on the binary'.format(
                func=element) + Fore.RESET)


def plist_permissions_check(plist_file):
    if 'binary' in magic.from_file(plist_file):
        subprocess.run(args=['plutil', '-convert', 'xml1', plist_file], stdout=subprocess.PIPE)
    plist_file_open = open(plist_file, 'r')
    plist_lines = plist_file_open.readlines()

    for i, line in enumerate(plist_lines):
        if line.strip().find("Usage") != -1:
            print(Fore.BLUE + 'PERMISSION INFO : {} requested'.format(line.strip().strip('</key>')) + Fore.RESET)
            print(Fore.BLUE + 'PERMISSION REASON : ' + plist_lines[i + 1].strip().strip('</string>') + Fore.RESET)


def run_checks(binary_path):
    # Get otool output
    otool_header = run_otool_command(['otool', '-hv', binary_path])
    otool_symbols = run_otool_command(['otool', '-Iv', binary_path])
    otool_arch = run_otool_command(['otool', '-arch', 'all', '-Vl', binary_path])
    otool_language = run_otool_command(['otool', '-L', binary_path])

    # Print results
    pie_flag(otool_header)
    stack_canaries(otool_symbols)
    arc_flag(otool_symbols)
    encrypted_binary(otool_arch)
    weak_hashing(otool_symbols)
    insecure_random(otool_symbols)
    vulnerable_functions(otool_symbols)
    get_language(otool_language)
