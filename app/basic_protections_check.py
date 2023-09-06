import subprocess
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


def weak_hashing_md5(otool_result):
    if otool_result.find('_CC_MD5') != -1:
        print(Fore.RED + 'ANALYSIS : MD5 Check - MD5 hashing function found on the binary' + Fore.RESET)
    else:
        print(Fore.GREEN + 'ANALYSIS : MD5 Check - MD5 hashing function NOT found on the binary' + Fore.RESET)


def weak_hashing_sha1(otool_result):
    if otool_result.find('_CC_SHA1') != -1:
        print(Fore.RED + 'ANALYSIS : SHA1 Check - SHA1 hashing function found on the binary' + Fore.RESET)
    else:
        print(Fore.GREEN + 'ANALYSIS : SHA1 Check - SHA1 hashing function NOT found on the binary' + Fore.RESET)


def insecure_random(otool_result):
    output_random = otool_result.find('_random')
    output_srand = otool_result.find('_srand')
    output_rand = otool_result.find('_rand')
    if output_random != -1 or output_srand != -1 or output_rand != -1:
        print(Fore.RED + 'ANALYSIS : Insecure random Check - Insecure random function found on the binary' + Fore.RESET)
    else:
        print(
            Fore.GREEN + 'ANALYSIS : Insecure random Check - Insecure random function NOT found on the binary' + Fore.RESET)


def insecure_malloc(otool_result):
    if otool_result.find('_malloc') != -1:
        print(Fore.RED + 'ANALYSIS : Malloc Check - Malloc function found on the binary' + Fore.RESET)
    else:
        print(Fore.GREEN + 'ANALYSIS : Malloc Check - Malloc function NOT found on the binary' + Fore.RESET)


def vulnerable_functions(otool_result):
    vulnerable_functions_list = ['_gets', '_memcpy', '_strncpy', '_strlen', '_vsnprintf', '_sscanf', '_strtok', '_alloca', '_sprintf', '_printf', '_vsprintf']
    for element in vulnerable_functions_list:
        if otool_result.find(element) != -1:
            print(Fore.RED + 'ANALYSIS : {func} Check - {func} function found on the binary'.format(func=element) + Fore.RESET)
        else:
            print(Fore.GREEN + 'ANALYSIS : {func} Check - {func} function NOT found on the binary'.format(func=element) + Fore.RESET)


def plist_permissions_check(plist_file):
    try:
        plist_file_open = open(plist_file, 'r')
        plist_lines = plist_file_open.readlines()
        for line in plist_lines:
            if line.strip().find("Usage") != -1:
                print(Fore.BLUE + 'PERMISSION INFO : {} requested'.format(line.strip().strip('</key>')))
    except:
        print(Fore.YELLOW + 'WARNING : Plist could not be read' + Fore.RESET)


def run_checks(binary_path):
    # Get otool output
    otool_header = run_otool_command(['otool', '-hv', binary_path])
    otool_symbols = run_otool_command(['otool', '-Iv', binary_path])
    otool_arch = run_otool_command(['otool', '-arch', 'all', '-Vl', binary_path])

    # Print results
    pie_flag(otool_header)
    stack_canaries(otool_symbols)
    arc_flag(otool_symbols)
    encrypted_binary(otool_arch)
    weak_hashing_md5(otool_symbols)
    weak_hashing_sha1(otool_symbols)
    insecure_random(otool_symbols)
    insecure_malloc(otool_symbols)
    vulnerable_functions(otool_symbols)
