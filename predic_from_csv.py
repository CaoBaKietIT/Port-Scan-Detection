import pickle

import pyshark
import pandas as pd
from pandas import DataFrame
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
with open("model.pkl", "rb") as f:
    model = pickle.load(f)
    
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
    df = df.astype(float)
    df = scaler.fit_transform(df)
    return df, df_ip
    

def main():
    df= pd.read_csv("pcap_to_csv.csv")
    try:
        df, df_ip = processsing_data(df)
    except Exception as e:
        print(e)

    preds = model.predict(df)

    for i in range(preds.shape[0]):
        if preds[i] == 1:
            print(print(f"[{df_ip['frame_info.time'][i]}][INFO] Detecting attack from {df_ip['ip.src'][i]} to {df_ip['ip.dst'][i]}"))
        else:
            print("--normal--")
if __name__ == "__main__":
    main()
