import glob
import os
import ssl
import argparse
import urllib3
import json
import logging
import urllib.request
import base64
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.HTTPResponse)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script to import CICIDS2017 data from CSV into elasticsearch.")
    parser.add_argument("-e --es_host", dest="es_host", type=str, default="127.0.0.1",
                        help="Address to the elasticsearch instance. Defaults to 127.0.0.1/localhost.")
    parser.add_argument("-po --es_port", dest="es_port", type=int, default=9200,
                        help="Port of the elasticsearch instance. Defaults to 9200.")
    parser.add_argument("-u --es_user", dest="es_user", type=str, required=True,
                        help="Username of elasticsearch account which has to have write access to the target index. "
                             "Required.")
    parser.add_argument("-pa --es_password", dest="es_password", type=str, required=True,
                        help="Password of elasticsearch account. Required.")
    parser.add_argument("-i --es_index", dest="es_index", type=str, required=True,
                        help="Target index to write into. Required.")
    parser.add_argument("-m --http_method", dest="http_method", type=str, default="https",
                        help="Specify http method. Default method is https.")
    parser.add_argument("-l --logging", dest="logging", default="INFO",
                        help="Set logging severity. Defaults to INFO.")
    params = parser.parse_args()

    ES_HOST = params.es_host
    ES_PORT = params.es_port
    ES_USER = params.es_user
    ES_PW = params.es_password
    INDEX_NAME = params.es_index
    HTTP_METHOD = params.http_method
    LOGGING = params.logging

    # Create logging instance with file output
    LOG_FORMATTER = logging.Formatter(fmt="%(asctime)s :: %(levelname)s :: %(message)s", datefmt="%H:%M:%S")
    LOGGER = logging.getLogger(__name__)

    FILE_HANDLER = logging.FileHandler(Path(f"./run-{datetime.now().strftime('%d-%m-%YT%H-%M-%S')}.log"))
    FILE_HANDLER.setFormatter(LOG_FORMATTER)
    LOGGER.addHandler(FILE_HANDLER)

    CONSOLE_HANDLER = logging.StreamHandler()
    CONSOLE_HANDLER.setFormatter(LOG_FORMATTER)
    LOGGER.addHandler(CONSOLE_HANDLER)

    if LOGGING == "DEBUG":
        LOGGER.setLevel(logging.DEBUG)
    elif LOGGING == "WARNING":
        LOGGER.setLevel(logging.WARNING)
    elif LOGGING == "ERROR":
        LOGGER.setLevel(logging.ERROR)
    elif LOGGING == "CRITICAL":
        LOGGER.setLevel(logging.CRITICAL)
    else:
        LOGGER.setLevel(logging.INFO)

    # Reading in the csv files
    folder = "./data/"
    os.chdir(Path(folder))
    li = []
    for file in glob.glob("*.csv"):
        LOGGER.info(f"Found file '{file}'! Loading ...")
        df = pd.read_csv(filepath_or_buffer=file, header=0, sep=",", engine="python")

        # Remove weird whitespace character
        header = []
        for col in df.columns:
            if " " in col[0]:
                header.append(col[1:])
            else:
                header.append(col)
        df.columns = header

        # Monday data has seconds, all others don't
        if "Monday" in file:
            df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S")
        else:
            df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M")

        LOGGER.info(f"{df.info()}")
        LOGGER.info(f"{df.to_string(max_rows=10, max_cols=100)}")
        li.append(df)
    if not li:
        LOGGER.error("Couldn't find any csv file in the data folder, aborting.")
        exit(1)
    df = pd.concat(li, axis=0, ignore_index=True)
    li = []     # Clear memory

    LOGGER.info("Finished loading, preprocessing ...")
    # Fill inf values with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    # Drop rows with all values NaN
    df.dropna(how="all", inplace=True)
    # Fill NaN values with a 0
    df.fillna(0, inplace=True)
    # Replace empty and whitespace values with a 0
    df.replace(["", " "], 0, inplace=True)
    # Adjust DType of DataFrame columns
    df = df.astype({"Source Port": np.uint32,
                    "Destination Port": np.uint32,
                    "Protocol": np.uint8,
                    "Flow Duration": np.int32,
                    "Total Fwd Packets": np.uint32,
                    "Total Backward Packets": np.uint32,
                    "Total Length of Fwd Packets": np.uint32,
                    "Total Length of Bwd Packets": np.uint32,
                    "Fwd Packet Length Max": np.uint16,
                    "Fwd Packet Length Min": np.uint16,
                    "Bwd Packet Length Max": np.uint16,
                    "Bwd Packet Length Min": np.uint16,
                    "Flow IAT Max": np.int32,
                    "Flow IAT Min": np.int32,
                    "Fwd IAT Total": np.int32,
                    "Fwd IAT Max": np.int32,
                    "Fwd IAT Min": np.int32,
                    "Bwd IAT Total": np.int32,
                    "Bwd IAT Max": np.uint32,
                    "Bwd IAT Min": np.uint32,
                    "Fwd PSH Flags": np.uint8,
                    "Bwd PSH Flags": np.uint8,
                    "Fwd URG Flags": np.uint8,
                    "Bwd URG Flags": np.uint8,
                    "Fwd Header Length": np.uint64,
                    "Bwd Header Length": np.uint64,
                    "Fwd Packets/s": np.uint32,
                    "Bwd Packets/s": np.uint32,
                    "Min Packet Length": np.uint16,
                    "Max Packet Length": np.uint16,
                    "FIN Flag Count": np.uint8,
                    "SYN Flag Count": np.uint8,
                    "RST Flag Count": np.uint8,
                    "PSH Flag Count": np.uint8,
                    "ACK Flag Count": np.uint8,
                    "URG Flag Count": np.uint8,
                    "CWE Flag Count": np.uint8,
                    "ECE Flag Count": np.uint8,
                    "Fwd Header Length.1": np.int64,
                    "Fwd Avg Bytes/Bulk": np.uint8,
                    "Fwd Avg Packets/Bulk": np.uint8,
                    "Fwd Avg Bulk Rate": np.uint8,
                    "Bwd Avg Bytes/Bulk": np.uint8,
                    "Bwd Avg Packets/Bulk": np.uint8,
                    "Bwd Avg Bulk Rate": np.uint8,
                    "Subflow Fwd Packets": np.uint32,
                    "Subflow Fwd Bytes": np.uint32,
                    "Subflow Bwd Packets": np.uint32,
                    "Subflow Bwd Bytes": np.uint32,
                    "Init_Win_bytes_forward": np.int32,
                    "Init_Win_bytes_backward": np.int32,
                    "act_data_pkt_fwd": np.uint32,
                    "min_seg_size_forward": np.int32,
                    "Active Max": np.uint32,
                    "Active Min": np.uint32,
                    "Idle Max": np.uint32,
                    "Idle Min": np.uint32})
    # Sort the DataFrame by Stime
    df.sort_values(by=["Timestamp"], inplace=True, ignore_index=True)
    LOGGER.info("Finished!")
    LOGGER.debug(f"\n{df.to_string(max_rows=10, max_cols=100)}")
    LOGGER.debug(f"\n{df.dtypes}")

    count = 0
    LOGGER.info(f"Ready to send {df.shape[0]} docs to cluster, Starting!")
    # Begin creating one request body per DataFrame row and send it to elastic search
    for index, row in df.iterrows():
        count = count + 1
        if count % 5000 == 0:
            LOGGER.info(f"{count / df.shape[0] * 100:.2f}% ...")

        body = {
            "@timestamp": row["Timestamp"].strftime('%Y-%m-%dT%H:%M:%S'),
            "@version": "1",
            "ecs": {
                "version": "1.5.0"
            },
            "event": {
                "kind": "event",
                "dataset": "flow",
                "action": "network_flow",
                "category": "network_traffic",
                "start": row["Timestamp"].strftime('%Y-%m-%dT%H:%M:%S'),
                "duration": row["Flow Duration"] * 1000
            },
            "source": {
                "ip": row["Source IP"],
                "port": row["Source Port"],
                "packets": row["Total Fwd Packets"],
                "bytes": row["Total Length of Fwd Packets"]
            },
            "destination": {
                "ip": row["Destination IP"],
                "port": row["Destination Port"],
                "packets": row["Total Backward Packets"],
                "bytes": row["Total Length of Bwd Packets"]
            },
            "network": {
                "transport": row["Protocol"],
                "type": "ipv4",
                "bytes": row["Total Length of Fwd Packets"] + row["Total Length of Bwd Packets"],
                "packets": row["Total Fwd Packets"] + row["Total Backward Packets"]
            },
            "CICFlowMeter": {
                "flow_id": row["Flow ID"],
                "down_up_ratio": row["Down/Up Ratio"],
                "fwd": {
                    "psh_flags": row["Fwd PSH Flags"],
                    "urg_flags": row["Fwd URG Flags"],
                    "header_bytes": row["Fwd Header Length"],
                    "header_length": row["Fwd Header Length.1"],
                    "packets/s": row["Fwd Packets/s"],
                    "init_win_bytes": row["Init_Win_bytes_forward"],
                    "act_data_pkt": row["act_data_pkt_fwd"],
                    "min_segment_size": row["min_seg_size_forward"],
                    "packet_length": {
                        "max": row["Fwd Packet Length Max"],
                        "min": row["Fwd Packet Length Min"],
                        "mean": row["Fwd Packet Length Mean"],
                        "std": row["Fwd Packet Length Std"]
                    },
                    "IAT": {
                        "total": row["Fwd IAT Total"],
                        "max": row["Fwd IAT Max"],
                        "min": row["Fwd IAT Min"],
                        "mean": row["Fwd IAT Mean"],
                        "std": row["Fwd IAT Std"]
                    },
                    "avg": {
                        "segment_size": row["Avg Fwd Segment Size"],
                        "bytes/bulk": row["Fwd Avg Bytes/Bulk"],
                        "packets/bulk": row["Fwd Avg Packets/Bulk"],
                        "bulk_rate": row["Fwd Avg Bulk Rate"],
                    },
                    "subflow": {
                        "packets": row["Subflow Fwd Packets"],
                        "bytes": row["Subflow Fwd Bytes"],
                    }
                },
                "bwd": {
                    "psh_flags": row["Bwd PSH Flags"],
                    "urg_flags": row["Bwd URG Flags"],
                    "header_bytes": row["Bwd Header Length"],
                    "packets/s": row["Bwd Packets/s"],
                    "init_win_bytes": row["Init_Win_bytes_backward"],
                    "packet_length": {
                        "max": row["Bwd Packet Length Max"],
                        "min": row["Bwd Packet Length Min"],
                        "mean": row["Bwd Packet Length Mean"],
                        "std": row["Bwd Packet Length Std"]
                    },
                    "IAT": {
                        "total": row["Bwd IAT Total"],
                        "max": row["Bwd IAT Max"],
                        "min": row["Bwd IAT Min"],
                        "mean": row["Bwd IAT Mean"],
                        "std": row["Bwd IAT Std"]
                    },
                    "avg": {
                        "segment_size": row["Avg Bwd Segment Size"],
                        "bytes/bulk": row["Bwd Avg Bytes/Bulk"],
                        "packets/bulk": row["Bwd Avg Packets/Bulk"],
                        "bulk_rate": row["Bwd Avg Bulk Rate"],
                    },
                    "subflow": {
                        "packets": row["Subflow Bwd Packets"],
                        "bytes": row["Subflow Bwd Bytes"],
                    }
                },
                "flow": {
                    "bytes/s": row["Flow Bytes/s"],
                    "packets/s": row["Flow Packets/s"],
                    "IAT": {
                        "max": row["Flow IAT Max"],
                        "min": row["Flow IAT Min"],
                        "mean": row["Flow IAT Mean"],
                        "std": row["Flow IAT Std"]
                    }
                },
                "packets": {
                    "avg_size": row["Average Packet Size"],
                    "length": {
                        "max": row["Max Packet Length"],
                        "min": row["Min Packet Length"],
                        "mean": row["Packet Length Mean"],
                        "std": row["Packet Length Std"],
                        "variance": row["Packet Length Variance"],
                    }
                },
                "flag_count": {
                    "FIN": row["FIN Flag Count"],
                    "SYN": row["SYN Flag Count"],
                    "RST": row["RST Flag Count"],
                    "PSH": row["PSH Flag Count"],
                    "ACK": row["ACK Flag Count"],
                    "URG": row["URG Flag Count"],
                    "CWE": row["CWE Flag Count"],
                    "ECE": row["ECE Flag Count"],
                },
                "active": {
                    "max": row["Active Max"],
                    "min": row["Active Min"],
                    "mean": row["Active Mean"],
                    "std": row["Active Std"],
                },
                "idle": {
                    "max": row["Idle Max"],
                    "min": row["Idle Min"],
                    "mean": row["Idle Mean"],
                    "std": row["Idle Std"],
                }
            },
            "tags": ["CICIDS2017", row["Label"]],
            "type": "flow"
        }

        LOGGER.debug(f"Sending {body}")

        elastic_target = f"{HTTP_METHOD}://{ES_HOST}:{ES_PORT}/{INDEX_NAME}/_doc"
        req = urllib.request.Request(elastic_target)
        json_data = json.dumps(body)
        json_data_as_bytes = json_data.encode("utf-8")
        credentials = base64.b64encode(f"{ES_USER}:{ES_PW}".encode("utf-8")).decode("utf-8")
        req.add_header("Authorization", f"Basic {credentials}")
        req.add_header("Content-Type", "application/json; charset=utf-8")
        req.add_header("Content-Length", len(json_data_as_bytes))
        ssl._create_default_https_context = ssl._create_unverified_context
        response = urllib.request.urlopen(req, json_data_as_bytes)
        LOGGER.debug(f"Response {json.loads(response.read().decode('utf-8'))}")

    LOGGER.info("All done! Please check your index for completeness.")
