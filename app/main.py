import os
import basic_protections_check
import extract_data_ipa
import analyze_utils
import argparse
from colorama import Fore


def make_working_directory(app_name):
    """
    Makes a directory to contain the application analysis results and files.
    Name of the directory created is the same as the IPA filename provided.

    Args:
         app_name (str): application name (will be the directory name)

    Returns:
        Absolute path to the created directory
    """
    new_path = r'../Results/{app_name}'.format(app_name=app_name)
    if not os.path.exists(new_path):
        print(Fore.BLUE + 'INFO : Creating working directory on path: {new_path}'.format(
            new_path=os.path.abspath(new_path)) + Fore.RESET)
        os.makedirs(new_path)
        return os.path.abspath(new_path)
    else:
        print(Fore.YELLOW + 'WARNING - Working directory already exists' + Fore.RESET)
        return os.path.abspath(new_path)


def ask_for_continue():
    """
    Simple menu for asking the user a yes/no answer

    Args:
        None

    Returns:
        User response (yes/no)
    """
    options = ['yes', 'no']
    user_input = ''
    input_message = "Pick an option - 'yes' will delete previous folder contents (yes/no):\n"
    while user_input.lower() not in options:
        user_input = input(input_message)
    return user_input


# Steps to analyze the IPA file
def analyze_ipa(ipa_path):
    # Get the IPA filename to create the temporary folder
    # E.G: /users/test/example.ipa -> example
    ipa_name = os.path.basename(ipa_path.strip('.ipa'))
    # E.G: /users/test/Results/example
    working_directory = make_working_directory(ipa_name)

    # Convert IPA to ZIP
    if len(os.listdir(working_directory)) == 0:
        print(Fore.BLUE + 'INFO : Working directory is empty - beginning conversion from IPA to ZIP' + Fore.RESET)
        extract_data_ipa.ipa_to_zip_file(ipa_path, working_directory)
    else:
        # If the working directory is not empty we ask the user if it wants to re-run the analysis (deleting all previous content)
        print(
            Fore.YELLOW + 'WARNING - Working directory is NOT empty - Do you want to override the analysis?' + Fore.RESET)
        user_response = ask_for_continue()
        if user_response.lower() == 'yes':
            print(Fore.BLUE + 'INFO : Deleting all working directory content' + Fore.RESET)
            analyze_utils.delete_directory(working_directory)
            print(Fore.BLUE + 'INFO : Delete completed - beginning conversion from IPA to ZIP' + Fore.RESET)
            extract_data_ipa.ipa_to_zip_file(ipa_path, working_directory)
        else:
            print(Fore.YELLOW + 'WARNING : Working directory for the application already exists' + Fore.RESET)
            return

    # Extract ZIP
    zipfile_path = analyze_utils.find_zipfile(working_directory)
    if zipfile_path is not None:
        print(Fore.BLUE + 'INFO : ZIP file found inside working directory - Beginning extraction' + Fore.RESET)
        extract_data_ipa.unzip_ipa(zipfile_path, working_directory)
        application_binary = analyze_utils.get_application_binary_file(working_directory)
        basic_protections_check.run_checks(application_binary)
        ipa_plist_file = analyze_utils.find_plist_file(working_directory)
        basic_protections_check.plist_permissions_check(ipa_plist_file)
    else:
        print(Fore.RED + 'ERROR : ZIP File not found on the working directory - Exiting')


def main():
    parser = argparse.ArgumentParser(description="Tool to perform basic binary security checks to an IPA application")
    parser.add_argument('-i', '--ipa', type=str, required=True, help="Absolute path to the .ipa file")
    args = parser.parse_args()
    ipa_path = args.ipa
    analyze_ipa(ipa_path)


if __name__ == "__main__":
    main()
