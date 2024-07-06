import pyshark
import json
import sys
import os


def extract_smb_info(pcap_file, output_folder):
    capture = pyshark.FileCapture(pcap_file, display_filter='smb2')
    data = []

    for packet in capture:
        smb_layer = packet['SMB2']
        timestamp = str(packet.sniff_time)
        source_ip = packet.ip.src
        source_port = packet.tcp.srcport
        destination_ip = packet.ip.dst
        destination_port = packet.tcp.dstport

        smb_command = int(smb_layer.cmd)
        smb_type = ''
        if smb_command == 5:  # SMB2 Write Request
            smb_type = 'SMB2 Write Request'
        elif smb_command == 8:  # SMB2 Read Request
            smb_type = 'SMB2 Read Request'

        if smb_type:
            try:
                file_name = smb_layer.get_field_value('filename') or "Unknown"
            except AttributeError:
                file_name = "Unknown"

            try:
                file_size = smb_layer.get_field_value('length') or "Unknown"
            except AttributeError:
                file_size = "Unknown"

            packet_data = {
                'SMB Type': smb_type,
                'Timestamp': timestamp,
                'Source IP': source_ip,
                'Source Port': source_port,
                'Destination IP': destination_ip,
                'Destination Port': destination_port,
                'File Name': file_name,
                'File Size': file_size,
                'Attachment': str(smb_layer)
            }

            data.append(packet_data)

    capture.close()

    # Create the output directory if it does not exist
    os.makedirs(output_folder, exist_ok=True)

    output_file = os.path.join(output_folder, 'sam_smb_metadata.json')
    with open(output_file, 'w') as json_file:
        json.dump(data, json_file, indent=4)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python sam_smb_extractor.py <path_to_pcap_file> <output_folder>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    output_folder = sys.argv[2]
    extract_smb_info(pcap_file, output_folder)
