import re


def find_app_identifier(plist_path):
    id_pattern = re.compile(r'[a-z]+\.[a-z]+\.[a-z]+')
    plist_open = open(plist_path, "rb")
    plist_read = plist_open.read()
    print(id_pattern.search(str(plist_read)))


def main():
    find_app_identifier('/Users/jorgejro/Documents/dev/ios_app_scanner/Results/Netsuite/Payload/SuitePhone2.app/Info.plist')


if __name__ == '__main__':
    main()
