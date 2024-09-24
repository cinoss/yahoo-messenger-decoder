#!/usr/bin/python3

import collections
import logging
import sys
import argparse
import os
import struct
import re


logging.basicConfig(stream=sys.stdout, level=logging.ERROR)
logger = logging.getLogger(__name__)

BLOCK_HEADER_SIZE = 16
BLOCK_END_MARKER_SIZE = 4

import codecs
from datetime import datetime

counter_out = collections.Counter()
counter_in = collections.Counter()

# consider this for web version https://wizard-arena.ucoz.net/emoticons.html
EMOJI = [
    (';;)',	"😉"),
    (';))',	"🤭"),
    (';)',	"😉"),
    (':-??',	"😕 😔 😖 😯 😦"),
    (':-?',	"🤔 😔"),
    (':-"',	"😗 😙"),
    (':-*',	"😘 😗 😙 😚"),
    (':-/',	"😕"),
    (':-&',	"🤢"),
    (':-<',	"😥 😟 😞 😤"),
    (':-$',	"🤫 🤐 (🙊 😶)"),
    (':-B',	"🤓"),
    (':-j',	"😒"),
    (':-L',	"😖 😟 😞"),
    (':-O',	"😮😯"),
    (':-S',	"😟"),
    (':-SS',	"😨 😧 😱"),
    (':!!',	"⌚️ ⏲ ⏰ ⏱"),
    (':((',	"😢😭"),
    (':(',	"🙁"),
    (':(|)',	"🐵"),
    (':))',	"😀 😃 😄 😆"),
    (':)]',	"🤙?"),
    (':)',	"🙂😊"),
    (':)>-',	"✌️"),
    (':@)',	"🐷"),
    (':^o',	"🤥"),
    (':>',	"😤? 😏?"),
    (':|',	"😐😑"),
    (':D',	"😀😃"),
    (':O)',	"🤡"),
    (':o3',	"🐶"),
    (':P',	"😛 (😋 😖 😫)"),
    (':p',	"😛 (😋 😖 😫)"),
    (':x',	"😍 (😚 😘 😗 😙)"),
    ('(:|',	"😫 😪 😑 😐"),
    ('[-(',	"😡 😶 😒"),
    ('[-o<',	"🙏 (🙇)"),
    ('[-x',	"☝️"),
    ('@-)',	"😵 💫"),
    ('*-:)',	"💡 🕯"),
    ('/:)',	"Unicode 10) "),
    ('#-o',	"🤦?"),
    ('#:-S',	"😅 😥 😖?"),
    ('%-(',	"🙉"),
    ('<:-P',	"😛 (🎉 🎊)"),
    ('<):)',	"🤠"),
    ('>-)',	"👽 👾"),
    ('>:)',	"😈 👿 👹"),
    ('>:/',	"😏 (🤚)"),
    ('>:P',	"😝?"),
    ('|-)',	"😪 😫 😩"),
    ('~:>',	"🐔"),
    ('~X(',	"😖 😫 😵?"),
    ('$-)',	"🤑"),
    ('3:-O',	"🐮"),
    ('8-}',	"🤪"),
    ('8-|',	"🙄"),
    ('8-X',	"💀 ☠️"),
    ('B-)',	"😎 (🕶)"),
    ('L-)',	"#26"),
    ('O:)',	"😇 👼"),
    ('X(',	"😖 😣 😡"),
    ('>:D<',	"🤗"),
    ('\\:D/',	"🙌 💃"),
    ('^:)^',	"🙇?"),
    ('^#(^',	"👐?"),
    ('X_X',	"🙈 😵"),
    ('[..]',	"🤖 👾"),
    (':-bd',	"👍"),
    (':-c',	"🤙"),
    (':-h',	"👋"),
    (':-q',	"👎"),
    # (':bz',	"🐝"),
    ('(*)',	"⭐️ 🌟 (✨)"),
    ('(%)',	"☯️"),
    ('(~~)',	"🎃"),
    ('@};-',	"🌹"),
    ('**==',	"🇺🇸"),
    ('\\m/',	"🤘"),
    ('%%-',	"🍀"),
    ('~o)',	"☕️"),
    ('0-+',	"♀️ 👩"),
    ('o->',	"♂️ 👨"),
    ('o=>',	"⚣️ 🧑"),
]


def decrypt(data, key):
    # Pad the key to the size of the data
    pad = len(data) // len(key) + 1
    key = (key * pad)[:len(data)]

    # XOR the data and the key
    decoded_data = bytes(x ^ y for (x, y) in zip(data, key))

    # Decode the result as UTF-8
    return codecs.decode(decoded_data, 'utf-8', 'ignore')

import pytz
def decode_archive(local_user, peer_user, archive_filename, should_print=False):
    logger.info("Decoding file [%s] of user [%s] with [%s].",
                archive_filename, local_user, peer_user)
    logger.debug("Opening file [%s] of size [%s] bytes.",
                 archive_filename, os.path.getsize(archive_filename))

    total_read = 0
    archive_file = open(archive_filename, "rb")
    while True:
        # Read blocke header.
        header_bytes = archive_file.read(BLOCK_HEADER_SIZE)
        if len(header_bytes) == 0:
            break
        timestamp, field2, field3, size = struct.unpack("@iiii", header_bytes)

        # Read the message of length specified in the header.
        data_bytes = archive_file.read(size)

        end_marker_bytes = archive_file.read(BLOCK_END_MARKER_SIZE)
        end_marker = struct.unpack("@i", end_marker_bytes)
        total_read += BLOCK_HEADER_SIZE + \
            len(data_bytes) + BLOCK_END_MARKER_SIZE

        formatted_time = (datetime
            .fromtimestamp(timestamp)
            # .astimezone(pytz.timezone("Asia/Ho_Chi_Minh"))
            .isoformat()
        )

        try:
            user_name = [local_user, peer_user][field3] or field3
        except :
            user_name = field3

        if field3 == 0:
            counter_out[peer_user] += 1
        else:
            counter_in[peer_user] += 1

        message = decrypt(data_bytes, local_user.encode("utf-8"))
        for (key, value) in EMOJI:
            # print(key, value)
            message = message.replace(key, value[0])
        # Clean up [#000000m<font face="Arial" size="10">[#000000m<font face="Arial" size="10">text
        message = re.sub(r'(\[#\d{6}m)|(<font [^>]+>)', '', message)

        if should_print:
            print(" ".join([
                formatted_time,
                # str(field2),
                f'\N{ESC}[3{field3 % 4 + 2}m',
                str(user_name) + ':',
                '\u001b[0m',
                message
            ]))

    archive_file.close()


def parse_messages_peer(local_user, peer_user, peer_tree, args):
    if args.peer and not peer_user.startswith(args.peer): return
    logger.debug(
        "Parsing logs dir for user [%s] with peer [%s]", local_user, peer_user)
    files = list(peer_tree.items());
    files.sort()
    for k, v in files:
        # v should be a leaf of the tree (a file).
        if not v:
            # Rebuild the path to the file.
            dat_file = os.path.join(
                args.root, local_user, "Archive", "Messages", peer_user, k)
            if os.path.isfile(dat_file):
                decode_archive(local_user, peer_user, dat_file, should_print=bool(args.peer))


def parse_messages(local_user, messages_tree, args):
    if args.user and args.user != local_user: return
    logger.debug("Parsing Messages dir for user [%s]", local_user)
    for k, v in messages_tree.items():
        # Keys with None values are not profiles or are boken.
        if v:
            parse_messages_peer(local_user, k, v, args)


def parse_archive(local_user, archive_tree, args):
    logger.debug("Parsing Archive dir for user [%s]", local_user)
    if "Messages" in archive_tree:
        messages = archive_tree.get("Messages")
        # If Messages dir has contents, parse them.
        if messages:
            parse_messages(local_user, messages, args)


def parse_profile(local_user, profile_tree, args):
    logger.debug("Parsing tree for user [%s]", local_user)
    if "Archive" in profile_tree:
        # If Archive dir has contents, parse them.
        archive = profile_tree.get("Archive")
        if archive:
            parse_archive(local_user, archive, args)


def parse_profiles(profiles, args):
    logger.debug("Parsing profiles [%s]", list(profiles.keys()))
    for k, v in profiles.items():
        # Keys with None values are not profiles or are boken.
        if v:
            parse_profile(k, v, args)


def parse_dir_tree(path):
    path = os.path.abspath(path)
    if os.path.isdir(path):
        dir_dict = {}
        for filename in os.listdir(path):
            sub_path = os.path.join(path, filename)
            dir_dict[filename] = parse_dir_tree(sub_path)
        return dir_dict
    else:
        return None


def parse_args():
    parser = argparse.ArgumentParser(
        description="Yahoo Messenger archive decoder.")
    parser.add_argument("--root", help="Location of Profiles directory", default="./Profiles")
    parser.add_argument(
        "--user", help="Decode archives for specific user.", default=None)
    parser.add_argument(
        "--peer", help="Decode archives for peer.", default=None)
    args = parser.parse_args()

    return args


def main():
    args = parse_args()

    if os.path.isdir(args.root):
        profiles_path = os.path.abspath(args.root)
        print(profiles_path)
        logger.debug("Parsing Profiles directory: [%s]", profiles_path)
        dir_tree = parse_dir_tree(profiles_path)
        parse_profiles(dir_tree, args)
    else:
        logger.error("Specified Profiles directory does not exist.")
        sys.exit(1)


if __name__ == "__main__":
    main()
    def stats(counter):
        pairs = [(v, k) for k, v in counter.items()]
        pairs.sort()
        for (v, k) in pairs[-30:]:
            print(k, v)
    print("=" * 10)
    print("Incoming messages")
    print("-" * 10)
    stats(counter_in)

    print("=" * 10)
    print("Outoing messages")
    print("-" * 10)
    stats(counter_out)
