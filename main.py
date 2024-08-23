import pickle

import pyshark
import pandas as pd
from pandas import DataFrame
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split


pd.set_option('display.max_colwidth', None)



with open("model.pkl", "rb") as f:
    model = pickle.load(f)



def build_fields(packet):
    attributes = [
        ["frame_info", "encap_type"],    #
        ["frame_info", "time"],          #
        ["frame_info", "time_epoch"],    #
        ["frame_info", "number"],        # 
        ["frame_info", "len"],           # 
        ["frame_info", "cap_len"],       # 
        ["eth", "type"],            # Ethernet Type
        ["ip", "version"],          # Internet Protocol (IP) Version
        ["ip", "hdr_len"],          # IP header length (IHL)
        ["ip", "tos"],		    # IP Type of Service (TOS)
        ["ip", "id"],               # Identification
        ["ip", "flags"],            # IP flags
        ["ip", "flags.rb"],             # Reserved bit flag
        ["ip", "flags.df"],             # Don't fragment flag
        ["ip", "flags.mf"],             # More fragments flag
        ["ip", "frag_offset"],      # Fragment offset
        ["ip", "ttl"],              # Time to live
        ["ip", "proto"],            # Protocol (e.g. tcp == 6)
        ["ip", "checksum"],         # Header checksum (qualitative)
        ["ip", "src"],		    # Source IP Address
        ["ip", "dst"],		    # Destination IP Address
        ["ip", "len"],              # Total length
        ["ip", "dsfield"],          # Differentiated Services Field       
            
        ["tcp", "srcport"],	    # TCP source port
        ["tcp", "dstport"],	    # TCP Destination port        
        ["tcp", "seq"],             # Sequence number
        ["tcp", "ack"],             # Acknowledgment number
        ["tcp", "len"],             # TCP segment length
        ["tcp", "hdr_len"],         # Header length
        ["tcp", "flags"],           # Flags
        ["tcp", "flags.fin"],           # FIN flag
        ["tcp", "flags.syn"],           # SYN flag
        ["tcp", "flags.reset"],         # RST flag
        ["tcp", "flags.push"],          # PUSH flag
        ["tcp", "flags.ack"],           # ACK flag
        ["tcp", "flags.urg"],           # URG flag
        ["tcp", "flags.cwr"],           # Congestion Window Reduced (CWR) flags
        ["tcp", "window_size"],	    # Window Size
        ["tcp", "checksum"],	    # Checksum
        ["tcp", "urgent_pointer"],  # Urgent pointer
        ["tcp", "options.mss_val"]  # Maximum Segment Size
	]

    pkt_to_list = []

    columns = []
    for i in attributes:
        columns.append(str(i[0])+"."+str(i[1]))

    global df
    df.columns = columns

    for i in attributes:
        # try-except used for packet attribute validation, if not available, fill with ""
        try:
            pkt_to_list.append(getattr(getattr(packet, i[0]), i[1]))
        except:
            pkt_to_list.append("")

    df.loc[len(df)] = pkt_to_list # row of packet attributes on last position of the dataframe

    # TODO: processing data
    drop_names = ["eth.type","ip.version","ip.hdr_len","ip.tos","ip.id","ip.flags.rb",
                "ip.flags.mf","ip.frag_offset","frame_info.number",
              "frame_info.number","frame_info.encap_type","tcp.len",
             "tcp.urgent_pointer","tcp.options.mss_val",
              "frame_info.time","ip.dst","ip.src","frame_info.time_epoch"]


def build_packet(packets: list) -> pd.DataFrame:
    attributes = [
        ["frame_info", "encap_type"],    #
        ["frame_info", "time"],          #
        ["frame_info", "time_epoch"],    #
        ["frame_info", "number"],        # 
        ["frame_info", "len"],           # 
        ["frame_info", "cap_len"],       # 
        ["eth", "type"],            # Ethernet Type
        ["ip", "version"],          # Internet Protocol (IP) Version
        ["ip", "hdr_len"],          # IP header length (IHL)
        ["ip", "tos"],		    # IP Type of Service (TOS)
        ["ip", "id"],               # Identification
        ["ip", "flags"],            # IP flags
        ["ip", "flags.rb"],             # Reserved bit flag
        ["ip", "flags.df"],             # Don't fragment flag
        ["ip", "flags.mf"],             # More fragments flag
        ["ip", "frag_offset"],      # Fragment offset
        ["ip", "ttl"],              # Time to live
        ["ip", "proto"],            # Protocol (e.g. tcp == 6)
        ["ip", "checksum"],         # Header checksum (qualitative)
        ["ip", "src"],		    # Source IP Address
        ["ip", "dst"],		    # Destination IP Address
        ["ip", "len"],              # Total length
        ["ip", "dsfield"],          # Differentiated Services Field       
            
        ["tcp", "srcport"],	    # TCP source port
        ["tcp", "dstport"],	    # TCP Destination port        
        ["tcp", "seq"],             # Sequence number
        ["tcp", "ack"],             # Acknowledgment number
        ["tcp", "len"],             # TCP segment length
        ["tcp", "hdr_len"],         # Header length
        ["tcp", "flags"],           # Flags
        ["tcp", "flags.fin"],           # FIN flag
        ["tcp", "flags.syn"],           # SYN flag
        ["tcp", "flags.reset"],         # RST flag
        ["tcp", "flags.push"],          # PUSH flag
        ["tcp", "flags.ack"],           # ACK flag
        ["tcp", "flags.urg"],           # URG flag
        ["tcp", "flags.cwr"],           # Congestion Window Reduced (CWR) flags
        ["tcp", "window_size"],	    # Window Size
        ["tcp", "checksum"],	    # Checksum
        ["tcp", "urgent_pointer"],  # Urgent pointer
        ["tcp", "options.mss_val"]  # Maximum Segment Size
	]

    pkts_to_list = []

    columns = []
    for i in attributes:
        columns.append(str(i[0])+"."+str(i[1]))

    for packet in packets:
        pkt_to_list = []
        for i in attributes:
            # try-except used for packet attribute validation, if not available, fill with ""
            try:
                pkt_to_list.append(getattr(getattr(packet, i[0]), i[1]))
            except:
                pkt_to_list.append("")
        pkts_to_list.append(pkt_to_list)
    
    # TODO: convert pkts_to_list to Dataframe

    df = pd.DataFrame(pkts_to_list, columns=columns)

    return df

def processsing_data (df: DataFrame):
    drop_names = ["eth.type","ip.version","ip.hdr_len","ip.tos","ip.id","ip.flags.rb",
                "ip.flags.mf","ip.frag_offset","frame_info.number",
              "frame_info.number","frame_info.encap_type","tcp.len",
             "tcp.urgent_pointer","tcp.options.mss_val",
              "frame_info.time","ip.dst","ip.src","frame_info.time_epoch"]
    df_ip = df[["ip.src", "ip.dst", "frame_info.time"]]

    df = df.drop(columns=drop_names)
    df = df.dropna(subset=['tcp.srcport','ip.ttl'])
    hex_columns = ["tcp.checksum","tcp.flags","ip.dsfield","ip.checksum","ip.flags"]

    for col in hex_columns:
        df[col] = df[col].apply(lambda x: df[col].value_counts().index[0] if not x else x)

    df["ip.checksum"] = df["ip.checksum"].apply(lambda x: "0x00" if not x else x)

    for col in hex_columns:
        df[col] = df[col].apply(lambda x: float(int(x, 16)))
    
    scaler = StandardScaler()

    df.to_csv("export_realtime_to_32packet.csv",mode="a+")

    df = df.astype(float)

    df = scaler.fit_transform(df)


    return df, df_ip
    
    

def main():
    print("[INFO] Start capturing,,,")
    capture = pyshark.LiveCapture(interface="eth0",display_filter="tcp", disable_protocol="ssh")

    # pyshark.FileCapture


    while True:
        packets = []
        for packet in capture.sniff_continuously(packet_count=32):
            packets.append(packet)

        df = build_packet(packets)

        # TODO: Processing data
        try:
            df, df_ip = processsing_data(df)
        except Exception as e:
            print(e)
            continue

        # TODO: threading predicting packet
        preds = model.predict(df)

        for i in range(preds.shape[0]):
            if preds[i] == 1:
                print(f"[{df_ip['frame_info.time'][i]}][INFO] Detecting attack from {df_ip['ip.src'][i]} to {df_ip['ip.dst'][i]}")
        print("Normal")
if __name__ == "__main__":
    main()
