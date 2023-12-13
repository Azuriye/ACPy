import hashlib
import random
import ctypes
import os
import json
import sys
import pyPacket as parser

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def check_admin():
    return os.getuid() == 0 if hasattr(os, 'getuid') else ctypes.windll.shell32.IsUserAnAdmin() != 0

def generate_random_steam_id64():
    return "7" + str(random.randint(1000000000000000, 9999999999999999))

def run_prechecks():
    if not check_admin():
        print("Please run this script as an admin for pydivert to function properly!")
        os._exit(1)
    else:
        print("Running pre-checks, if no errors displayed the script is loaded!")
        print("Close the script forcefully if stuck or not reproducing your desired effect!\n")

def generate_correct_md5(md5_dir):
    return hashlib.md5(open(md5_dir, 'rb').read()).hexdigest()

def load_config(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def main():
    clear_screen()

    # Configuration settings.
    config_file_path = sys.path[0] + '/config.json'
    config_data = load_config(config_file_path)

    checksum_spoof = config_data.get('EnableChecksum')
    md5_dir = config_data.get('CorrectMD5Checksum').replace("\\", "\\\\")
    steam_spoof = config_data.get('EnableSteamID64Spoof')
    steamID64 = config_data.get('customSteamID64')
    local_address = config_data.get('LocalIPv4Address')
    server_address = config_data.get('ServerIPv4Address')

    run_prechecks()

    try:
        if checksum_spoof:
            correct_md5 = generate_correct_md5(md5_dir)
        if steam_spoof and steamID64 == "":
            steamID64 = generate_random_steam_id64()
            print("steamID64 field empty, proceeding to generate a random steamID64...\n")
            print(f"randomly generated steamID64 is \033[1m{steamID64}\033[0m!\n")
        elif steam_spoof and (len(steamID64) != 17 or steamID64.isdigit() != True):
            print("Wrong steamID64 format! Please recheck.")
            os._exit(1)
        if checksum_spoof or steam_spoof:
            parser.parse(local_address, server_address, steam_spoof, checksum_spoof, correct_md5, steamID64)
        else:
            print("Check config.json.")

    except Exception as e:
        print(e)
        os._exit(1)

if __name__ == "__main__":
    main()
