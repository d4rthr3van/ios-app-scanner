# iOS App Scanner

iOS App Scanner is a simple command-line tool made with Python to help security researchers and developers identify 
potential security flaws in iOS applications.

## Installation

Use the requirements file included in the repo to install iOS App Scanner.

```bash
pip install -r requirements.txt
```

## Usage
To run the tool, once installed the requirements, just execute the main.py file.

```bash
python3 main.py -h    # To display help
python3 main.py -i /path/to/ipa     # To analyse an application
```

## Limitations
For the moment, the tool will only work on MacOS systems, as it uses [otool](https://www.unix.com/man-page/osx/1/otool/)
to explore the binary.

## Functionalities
At the moment, the tool will perform the next checks:
+ Extract .ipa assets