import pydivert
import logging

STEAM_TICKET_MAGIC = b"STEAM_TICKET"
CHECKSUM_HEX_MAGIC = "4441949b9f7045cad2af3f5eb951d170a9"
STEAM_GET_REQUEST_HEX_1 = "474554202f4a534f4e253743"
STEAM_GET_REQUEST_HEX_2 = "3f677569643d"
STEAM_ID_HEX_PREFIX = "3dca0011"

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

def spoof_steam_auth(data, steamID64):
    if STEAM_TICKET_MAGIC not in data:
        if data[:12].hex() == STEAM_GET_REQUEST_HEX_1 or data[16:22].hex() == STEAM_GET_REQUEST_HEX_2:
            spoof_http_get_request(data, steamID64)
        elif data[2:6].hex() == STEAM_ID_HEX_PREFIX:
            spoof_steam_id(data, steamID64)
    else:
        logger.info("Steam auth ticket detected! Disabling steam_spoof option...")

    return bytes(data)

def spoof_http_get_request(data, steamID64):
    if data[:12].hex() == STEAM_GET_REQUEST_HEX_1:
        data[12:29] = bytes(steamID64, encoding="utf-8")

def spoof_steam_id(data, steamID64):
    packet_steam = data[6:23].decode("utf-8")
    data[6:23] = bytes(steamID64, encoding="utf-8")

    logger.info(f"{packet_steam} is the original steamID64, spoofing the \033[1msteamID64 to {steamID64}\033[0m provided under steamID64 field.")

def spoof_checksum(data, correct_md5):
    if data[2:19].hex() == CHECKSUM_HEX_MAGIC:
        packet_checksum = data[-16:].hex()
        data[-16:] = bytes.fromhex(correct_md5)

        logger.info(f"MD5 hash spoofed from {packet_checksum} to {correct_md5} to prevent checksum mismatch.")

    return bytes(data)

def parse(local_address, server_address, steam_spoof, checksum_spoof, correct_md5, steamID64):
    with pydivert.WinDivert(f"ip.SrcAddr = {local_address} and ip.DstAddr = {server_address} and tcp.PayloadLength > 34") as w:
        for packet in w:
            data = bytearray(packet.payload)

            if steam_spoof:
                edited_packet = spoof_steam_auth(data, steamID64)
            elif checksum_spoof:
                edited_packet = spoof_checksum(data, correct_md5)
            else:
                edited_packet = bytes(data)

            packet.payload = edited_packet
            w.send(packet)
