# Deletes the specified directory
import os
import shutil

import magic
from colorama import Fore


def delete_directory(old_dir):
    """
    Deletes a directory and all the contents contained on it

    Args:
        old_dir (str): Absolute path to the directory that will be deleted

    Returns:
        None
    """
    for filename in os.listdir(old_dir):
        file_path = os.path.join(old_dir, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print(Fore.RED + 'Failed to delete %s. Reason: %s' % (file_path, e) + Fore.RESET)


def get_application_binary_file(working_directory):
    """
    Searches for a Mach-O executable inside a folder with an .app application structure

    Args:
        working_directory (str): Absolute path to the directory containing the iOS application

    Returns:
        Absolute path to the binary
    """
    if 'Payload' in os.listdir(working_directory):
        payload_dir = working_directory + '/Payload/'
        if len(os.listdir(payload_dir)) >= 1:
            app_found = False
            for element in os.listdir(payload_dir):
                if app_found:
                    break
                if '.app' in element:
                    app_found = True
                    app_path = payload_dir + element
                    for dirpath, _, filenames in os.walk(os.path.abspath(app_path)):
                        for file in filenames:
                            if 'executable' in magic.from_file(os.path.join(dirpath, file)):
                                application_binary_absolute_path = os.path.join(dirpath, file)
                                print(
                                    Fore.GREEN + 'INFO : Application binary found on ' + application_binary_absolute_path + ' | Application type: ' + magic.from_file(
                                        os.path.join(dirpath, file)) + Fore.RESET)
                                return application_binary_absolute_path
        else:
            print(Fore.RED + 'Payload folder is empty - something went wrong' + Fore.RESET)
    else:
        print(Fore.RED + 'No Payload folder found - something went wrong' + Fore.RESET)


def find_zipfile(working_directory):
    """
    Finds a .zip file (containing application resources) inside a working directory

    Args:
        working_directory (str): absolute path to the working directory supposedly containing a .zip file

    Returns:
        .zip file absolute path
    """
    zipfile_found = False
    zipfile_path = None

    for dirpath, _, filenames in os.walk(os.path.abspath(working_directory)):
        for file in filenames:
            if zipfile_found:
                break
            zipfile_path = os.path.join(dirpath, file)
            if file.find('.zip') != -1:
                zipfile_found = True

    return zipfile_path


def find_plist_file(working_directory):
    if 'Payload' in os.listdir(working_directory):
        payload_dir = working_directory + '/Payload/'
        if len(os.listdir(payload_dir)) >= 1:
            app_found = False
            for element in os.listdir(payload_dir):
                if app_found:
                    break
                if '.app' in element:
                    app_found = True
                    app_path = payload_dir + element
                    for dirpath, _, filenames in os.walk(os.path.abspath(app_path)):
                        for file in filenames:
                            if 'Info.plist' in file:
                                return os.path.join(dirpath, file)


if __name__ == '__main__':
    a = find_plist_file('/Users/jorgejro/Documents/dev/ios_app_scanner/Results/Netsuite')
    file1 = open(a, 'r')
    Lines = file1.readlines()

    for line in Lines:
        if line.strip().find("Usage") != -1:
            print(line.strip().strip('</key>'))
