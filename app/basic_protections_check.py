import subprocess
from colorama import Fore, Style


def run_otool_command(command_arguments):
    result = subprocess.run(args=command_arguments, stdout=subprocess.PIPE)
    return result.stdout.decode()


def pie_flag(binary_path):
    output = run_otool_command(['otool', '-hv', binary_path]).find('PIE')
    if output != -1:
        print(Fore.GREEN + 'ANALYSIS : PIE check - PIE flag is present on the binary' + Fore.RESET)
    else:
        print(Fore.RED + 'ANALYSIS : PIE check - PIE flag is not present on the binary' + Fore.RESET)


def stack_canaries(binary_path):
    output = run_otool_command(['otool', '-I', '-v', binary_path])
    chk_fail = output.find('stack_chk_fail')
    chk_guard = output.find('stack_chk_guard')
    if chk_guard != -1 and chk_fail != -1:
        print(Fore.GREEN + 'ANALYSIS : Canaries check - Stack Canaries flag is present on the binary' + Fore.RESET)
    else:
        print(Fore.RED + 'ANALYSIS : Canaries check - Stack Canaries flag is not present on the binary' + Fore.RESET)


def arc_flag(binary_path):
    output = run_otool_command(['otool', '-I', '-v', binary_path]).find('objc_release')
    if output != -1:
        print(
            Fore.GREEN + 'ANALYSIS : ARC Check - Automatic Reference Counting flag is present on the binary' + Fore.RESET)
    else:
        print(
            Fore.RED + 'ANALYSIS : ARC Check - Automatic Reference Counting flag is not present on the binary' + Fore.RESET)


def encrypted_binary(binary_path):
    output = run_otool_command(['otool', '-arch', 'all', '-Vl', binary_path]).find('cryptid 1')
    if output != -1:
        print(Fore.GREEN + 'ANALYSIS : Encryption check - The binary is encrypted' + Fore.RESET)
    else:
        print(Fore.RED + 'ANALYSIS : Encryption check - The binary is not encrypted' + Fore.RESET)


def weak_hashing_md5(binary_path):
    output = run_otool_command(['otool', '-Iv', binary_path]).find('_CC_MD5')
    if output != -1:
        print(Fore.RED + 'ANALYSIS : MD5 Check - MD5 hashing function found on the binary' + Fore.RESET)
    else:
        print(Fore.GREEN + 'ANALYSIS : MD5 Check - MD5 hashing function NOT found on the binary' + Fore.RESET)


def weak_hashing_sha1(binary_path):
    output = run_otool_command(['otool', '-Iv', binary_path]).find('_CC_SHA1')
    if output != -1:
        print(Fore.RED + 'ANALYSIS : SHA1 Check - SHA1 hashing function found on the binary' + Fore.RESET)
    else:
        print(Fore.GREEN + 'ANALYSIS : SHA1 Check - SHA1 hashing function NOT found on the binary' + Fore.RESET)


def insecure_random(binary_path):
    output = run_otool_command(['otool', '-Iv', binary_path]).find('_random')
    output_srand = run_otool_command(['otool', '-Iv', binary_path]).find('_srand')
    output_rand = run_otool_command(['otool', '-Iv', binary_path]).find('_rand')
    if output != -1 or output_srand != -1 or output_rand != -1:
        print(Fore.RED + 'ANALYSIS : Insecure random Check - Insecure random function found on the binary' + Fore.RESET)
    else:
        print(
            Fore.GREEN + 'ANALYSIS : Insecure random Check - Insecure random function NOT found on the binary' + Fore.RESET)


def insecure_malloc(binary_path):
    output = run_otool_command(['otool', '-Iv', binary_path]).find('_malloc')
    if output != -1:
        print(Fore.RED + 'ANALYSIS : Malloc Check - Malloc function found on the binary' + Fore.RESET)
    else:
        print(Fore.GREEN + 'ANALYSIS : Malloc Check - Malloc function NOT found on the binary' + Fore.RESET)


def vulnerable_functions(binary_path):
    output = run_otool_command(['otool', '-Iv', binary_path]).find('objc_release')
    if output != -1:
        print(Fore.GREEN + 'ARC Check - Automatic Reference Counting flag is present on the binary' + Fore.RESET)
    else:
        print(Fore.RED + 'ARC Check - Automatic Reference Counting flag is not present on the binary' + Fore.RESET)


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
    pie_flag(binary_path)
    stack_canaries(binary_path)
    arc_flag(binary_path)
    encrypted_binary(binary_path)
    weak_hashing_md5(binary_path)
    weak_hashing_sha1(binary_path)
    insecure_random(binary_path)
    insecure_malloc(binary_path)
