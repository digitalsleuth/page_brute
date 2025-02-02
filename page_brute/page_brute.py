#!/usr/bin/env python3
#
# 	page_brute.py
# 	by @matonis - secualexploits.blogspot.com - www.mike-matonis.com
# 	Summer of 2013
#
import sys
import argparse
import datetime
import glob
import os
import os.path
import binascii

try:
    import yara
except ModuleNotFoundError:
    print(
        "[!] ERROR: Could not import YARA. Make sure yara and yara-python are installed."
    )
    sys.exit()


FILE = PAGE_SIZE = RULES = SCANNAME = INVERT = RULETYPE = NULL_REFERENCE = (
    WORKING_DIR
) = None


def is_block_null(block):
    # Here we test to see if the block is null..if so, skip.
    RAW_BLOCK = binascii.hexlify(block)
    NULL_REF = binascii.hexlify(NULL_REFERENCE)
    return bool(RAW_BLOCK == NULL_REF)


def build_ruleset():
    if RULETYPE == "FILE":
        try:
            rules = yara.compile(str(RULES))
            print("[+] Ruleset Compilation Successful.")
            return rules
        except yara.Error:
            print(f"[!] Could not compile YARA rule: {RULES}.")
            sys.exit()

    elif RULETYPE == "FOLDER":
        RULEDATA = ""
        #::Get list of files ending in .yara

        RULE_COUNT = len(glob.glob1(RULES, "*.yar"))
        if RULE_COUNT != 0:
            for yara_file in glob.glob(os.path.join(RULES, "*.yar")):
                try:
                    yara.compile(str(yara_file))
                    print(f"[+] Syntax appears to be OK: {yara_file} ")
                    try:
                        with open(yara_file, "r", encoding="utf-8") as sig_file:
                            file_contents = sig_file.read()
                            RULEDATA = RULEDATA + "\n" + file_contents
                    except yara.Error:
                        print(
                            f"[!] SKIPPING: Could not open file for reading: {yara_file} "
                        )
                except yara.Error:
                    print(f"[!] SKIPPING: Could not compile rule: {yara_file} ")
            try:
                rules = yara.compile(source=RULEDATA)
                print("[+] SUCCESS! Compiled noted yara rulesets.")
                return rules
            except yara.Error:
                print(
                    "[!] Some catastropic error occurred in the compilation of signatureswithin the directory. Exiting."
                )
                sys.exit()
        else:
            print(f"[!] No files ending in .yar within: {RULES} ")
            sys.exit()

    elif RULETYPE == "DEFAULT":
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            RULES = os.path.join(script_dir, "default_signatures.yar")            
            rules = yara.compile(str(RULES))
            print("[+] Ruleset Compilation Successful.")
            return rules
        except yara.Error:
            print(f"[!] Could not compile YARA rule: {RULES}.")
            sys.exit()

    else:
        print("[!] ERROR: Possible catastrophic error on build_ruleset. Exiting.")
        sys.exit()


def print_procedures():
    print("[+] PAGE_BRUTE running with the following options:")
    print("=================")
    print(f"[-] FILE: {FILE}")
    print(f"[-] PAGE_SIZE: {PAGE_SIZE}")
    print(f"[-] RULES TYPE: {RULETYPE}")
    print(f"[-] RULE LOCATION: {RULES}")
    print(f"[-] INVERSION SCAN: {INVERT}")
    print(f"[-] WORKING DIR: {WORKING_DIR}")
    print("=================")


def main():

    global FILE
    global PAGE_SIZE
    global RULES
    global SCANNAME
    global INVERT
    global RULETYPE
    global NULL_REFERENCE

    argument_parser = argparse.ArgumentParser(
        description="Checks pages in pagefiles for YARA-based rule matches. Useful to identify forensic artifacts within Windows-based page files and characterize blocks based on regular expressions."
    )

    group_arg = argument_parser.add_argument_group()
    group_arg.add_argument(
        "-f",
        "--file",
        metavar="FILE",
        help="Pagefile or any chunk/block-based binary file",
    )
    group_arg.add_argument(
        "-p",
        "--size",
        metavar="SIZE",
        help="Size of chunk/block in bytes (Default 4096)",
        type=int,
    )
    group_arg.add_argument(
        "-o",
        "--scanname",
        metavar="SCANNAME",
        help="Descriptor of the scan session - used for output directory",
    )
    group_arg.add_argument(
        "-i",
        "--invert",
        help="Given scan options, match all blocks that DO NOT match a ruleset",
        action="store_true",
    )

    mutex_arg = argument_parser.add_mutually_exclusive_group()
    mutex_arg.add_argument(
        "-r",
        "--rules",
        metavar="RULEFILE",
        help="File/directory containing YARA signatures (must end with .yar)",
    )

    args = argument_parser.parse_args()

    if len(sys.argv) < 2:
        argument_parser.print_help()
        sys.exit(0)

    #::Check to see if file was provided::#
    if args.file:
        try:
            with open(args.file, "rb"):
                FILE = args.file
                print(f"[-] PAGE_BRUTE processing file: {FILE}")
        except FileNotFoundError:
            print(f"[!] Could not open {FILE}.")
            sys.exit(1)
    else:
        print("[!] No file provided. Use -f, --file to provide a file.")
        sys.exit(1)

    #::Check to see if page size provided::#
    if args.size:
        PAGE_SIZE = int(args.size)
    else:
        PAGE_SIZE = 4096
    NULL_REFERENCE = b"\x00" * PAGE_SIZE

    #::Check if --scan-name provided::#
    if args.scanname:
        SCANNAME = args.scanname
    else:
        SCANNAME = f'PAGE_BRUTE-{datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}-RESULTS'

    #::Check if --invert-match provided::#
    INVERT = bool(args.invert)

    #::Check if --rule-file provdided - if not, use default ruleset::#
    if args.rules:
        RULES = args.rules
        try:
            #::Is File?::#
            if os.path.isfile(RULES):
                RULETYPE = "FILE"
                print(f"[+] YARA rule of File type provided for compilation: {RULES}")
            elif os.path.isdir(RULES):
                print(f"[+] YARA rule of Folder type provided for compilation: {RULES}")
                RULETYPE = "FOLDER"
        except Exception as err:
            print(f"[!] Possible catastrophic error with the provided rule file {err}.")
            sys.exit(1)
    else:
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            default_sigs = os.path.join(script_dir, "default_signatures.yar")
            with open(default_sigs, "r", encoding="utf-8"):
                RULES = "default_signatures.yar"
                RULETYPE = "DEFAULT"
        except FileNotFoundError:
            print(
                '[!] Could not locate "default_signatures.yar". Find it or provide custom signatures via --rules. Exiting.'
            )
            sys.exit(1)

    #::Compile rules::#
    authoritative_rules = build_ruleset()
    #::Build directory structure
    global WORKING_DIR
    WORKING_DIR = SCANNAME
    if not os.path.exists(WORKING_DIR):
        os.makedirs(WORKING_DIR)
    #::Let People Know what we're doing::#
    print_procedures()
    #::Find Evil::#
    page_id = 0
    with open(FILE, "rb") as page_file:
        while True:
            matched = False
            raw_page = page_file.read(PAGE_SIZE)
            if raw_page == b"":
                print("Done!")
                print(f"Ending page_id is: {page_id}")
                break
            if not is_block_null(raw_page):
                #::Determine if block is null...:
                for matches in authoritative_rules.match(data=raw_page):
                    if INVERT is True:
                        matched = True
                    else:
                        CHUNK_OUTPUT_DIR = os.path.join(WORKING_DIR, matches.rule)
                        print(f"\t[!] FLAGGED BLOCK {str(page_id)}: {matches.rule}")

                        if not os.path.exists(CHUNK_OUTPUT_DIR):
                            os.makedirs(CHUNK_OUTPUT_DIR)

                        #::Save chunk to file::#
                        CHUNK_OUTPUT_FWD = os.path.join(
                            CHUNK_OUTPUT_DIR, str(page_id) + ".block"
                        )
                        with open(CHUNK_OUTPUT_FWD, "wb+") as page_export:
                            page_export.write(raw_page)

                if INVERT is True:
                    if matched is False:
                        CHUNK_OUTPUT_DIR = os.path.join(WORKING_DIR, "INVERTED-MATCH")
                        print(
                            f"\t[!] BLOCK DOES NOT MATCH ANY KNOWN SIGNATURE: {str(page_id)}"
                        )
                        if not os.path.exists(CHUNK_OUTPUT_DIR):
                            os.makedirs(CHUNK_OUTPUT_DIR)

                        CHUNK_OUTPUT_FWD = os.path.join(
                            CHUNK_OUTPUT_DIR, str(page_id) + ".block"
                        )
                        with open(CHUNK_OUTPUT_FWD, "wb+") as page_export:
                            page_export.write(raw_page)
            #::Increment Counter for offset increment::#
            page_id = page_id + 1


if __name__ == "__main__":
    main()
