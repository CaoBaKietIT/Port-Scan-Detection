import pickle
import pyshark
import pandas as pd
from pandas import DataFrame
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

pd.set_option('display.max_colwidth', None)

df = pd.DataFrame(np.empty((0, 41)))     # 41 empty columns

with open("model.pkl", "rb") as f:
    model = pickle.load(f)

def processing_cvs (df):
    x=32
    for i in range (df.shape[0]//32-2):
        x=x+33
        print(x)

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

    df.to_csv("test.csv",mode="a+")

    df = df.astype(float)

    df = scaler.fit_transform(df)


    return df, df_ip

def main():
    pcap_file = "cap1.pcap"
    cap = pyshark.FileCapture(pcap_file, display_filter="tcp")	# filtering out just tcp packets
    cap.apply_on_packets(build_fields)
    cap.close()
    
    print(df.info())
    print(df.shape)
    df.to_csv('pcap_to_csv.csv', index=None, header=True)

if __name__ == "__main__":
    main()
