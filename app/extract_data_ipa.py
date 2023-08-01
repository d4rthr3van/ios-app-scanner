import shutil


def ipa_to_zip_file(ipa_path, copy_path):
    """
    Creates a .zip file copy from the .ipa file

    Args:
        ipa_path (str): absolute path to the .ipa file
        copy_path (str) : absolute path to the directory in which .zip file will be placed

    Returns:
        None
    """
    ipa_copy = ipa_path.strip('.ipa') + '.zip'
    shutil.copy(ipa_path, ipa_copy)
    shutil.move(ipa_copy, copy_path)


def unzip_ipa(zip_path, destination):
    """
    Unzips a .zip file

    Args:
        zip_path (str): absolute path to the .zip file
        destination (str) : absolute path to the directory in which .zip file will be extracted

    Returns:
        None
    """
    shutil.unpack_archive(zip_path, destination)
