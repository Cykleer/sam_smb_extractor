# sam_smb_extractor
# SMB Extractor

This script extracts metadata from SMB write and read requests in a given PCAP file and saves the extracted metadata to a JSON file.

## Requirements

- Python 3.x
- Pyshark

## Installation

1. Clone this repository:
    ```sh
    git clone https://github.com/cykleer/smb_extractor.git
    cd smb_extractor
    ```

2. Install the required dependencies:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

Run the script with the path to your PCAP file and the desired output JSON file:

```sh
python sam_smb_extractor.py <path_to_pcap_file> <output_json_file>
