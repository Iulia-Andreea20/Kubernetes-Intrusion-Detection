#!/usr/bin/env python3
import pathlib, dpkt, socket, pandas as pd, numpy as np, joblib, os
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_curve
from sklearn.utils.class_weight import compute_sample_weight
import matplotlib
import pathlib
import ipaddress
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DATA = pathlib.Path(os.environ.get("TRAIN_DIR", "training"))
ART  = pathlib.Path(os.environ.get("ART_DIR", "artifacts")); ART.mkdir(exist_ok=True)

def in_cidr(ip, cidr):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False

def pcap_to_df(path: pathlib.Path, label: int) -> pd.DataFrame:
    rows = []
    with open(path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue
                ip = eth.data
                proto = 6 if isinstance(ip.data, dpkt.tcp.TCP) else 17 if isinstance(ip.data, dpkt.udp.UDP) else 0
                if proto == 0:
                    continue
                l4 = ip.data
                syn = ack = fin = rst = psh = urg = 0
                if proto == 6:
                    fl = l4.flags
                    syn = 1 if (fl & dpkt.tcp.TH_SYN) else 0
                    ack = 1 if (fl & dpkt.tcp.TH_ACK) else 0
                    fin = 1 if (fl & dpkt.tcp.TH_FIN) else 0
                    rst = 1 if (fl & dpkt.tcp.TH_RST) else 0
                    psh = 1 if (fl & dpkt.tcp.TH_PUSH) else 0
                    urg = 1 if (fl & dpkt.tcp.TH_URG) else 0
                sip = inet_to_str(ip.src)
                dip = inet_to_str(ip.dst)
                rows.append({
                    "src_ip": sip,
                    "dst_ip": dip,
                    "src_port": int(l4.sport),
                    "dst_port": int(l4.dport),
                    "length": int(ip.len),
                    "proto": proto,
                    "syn": syn, "ack": ack, "fin": fin, "rst": rst, "psh": psh, "urg": urg,
                    "src_is_pod": int(in_cidr(sip, "10.244.0.0/16")),
                    "dst_is_pod": int(in_cidr(dip, "10.244.0.0/16")),
                    "dst_is_service": int(in_cidr(dip, "10.96.0.0/12")),
                    "label": label
                })
            except Exception:
                continue
    return pd.DataFrame(rows)

def main():
    wp   = pcap_to_df(DATA/"cluster-wordpress.pcap", 0)
    echo = pcap_to_df(DATA/"cluster.pcap", 0)
    att  = pcap_to_df(DATA/"cluster-attacks.pcap", 1)

    print({"wp": len(wp), "echo": len(echo), "att": len(att)})

    df_train = pd.concat([wp, att], ignore_index=True).sample(frac=1, random_state=42)
    df_hold  = echo.copy()

    enc_src = LabelEncoder().fit(df_train["src_ip"].astype(str).fillna(""))
    enc_dst = LabelEncoder().fit(df_train["dst_ip"].astype(str).fillna(""))

    def encode_with_unknown(s: pd.Series, classes) -> pd.Series:
        s = s.astype(str).fillna("")
        # unknowns get code -1 automatically
        return pd.Categorical(s, categories=list(classes)).codes.astype("int32")

    df_train["src_ip"] = encode_with_unknown(df_train["src_ip"], enc_src.classes_)
    df_train["dst_ip"] = encode_with_unknown(df_train["dst_ip"], enc_dst.classes_)
    df_hold["src_ip"]  = encode_with_unknown(df_hold["src_ip"],  enc_src.classes_)
    df_hold["dst_ip"]  = encode_with_unknown(df_hold["dst_ip"],  enc_dst.classes_)

    feature_cols = ["src_port","dst_port","length","proto",
                    "syn","ack","fin","rst","psh","urg",
                    "src_is_pod","dst_is_pod","dst_is_service"]

    X = df_train[feature_cols].values
    y = df_train["label"].values

    scaler = StandardScaler().fit(X)
    X = scaler.transform(X)

    X_hold = scaler.transform(df_hold[feature_cols].values)
    # X = df_train.drop(columns="label").values
    # y = df_train["label"].values

    # scaler = StandardScaler().fit(X)
    # X = scaler.transform(X)

    # X_tr, X_val, y_tr, y_val = train_test_split(X, y, test_size=0.2,
    #                                             stratify=y, random_state=42)

    clf = MLPClassifier(
        hidden_layer_sizes=(64, 32),
        activation="relu",
        solver="adam",
        max_iter=200,
        random_state=42,
        early_stopping=True,
        n_iter_no_change=10,
        validation_fraction=0.1,
        batch_size=4096
    )
    w_tr = compute_sample_weight(class_weight="balanced", y=y_tr)

    clf.fit(X_tr, y_tr, sample_weight=w_tr)

    y_val_pred = clf.predict(X_val)
    y_val_prob = clf.predict_proba(X_val)[:,1]
    print("\n=== Validation ===")
    print(classification_report(y_val, y_val_pred, digits=4))
    print(confusion_matrix(y_val, y_val_pred))

    prec, rec, thr = precision_recall_curve(y_val, y_val_prob)
    plt.figure(); plt.plot(rec, prec)
    plt.xlabel("Recall"); plt.ylabel("Precision"); plt.title("Precision–Recall")
    plt.grid(True, alpha=0.3); plt.tight_layout()
    plt.savefig(ART/"pr_curve_validation.png")

    # benign hold-out (echo) @ high-precision threshold
    tau = float(os.environ.get("THRESHOLD", "0.90"))
    X_hold = scaler.transform(df_hold.drop(columns="label", errors="ignore").values)
    p_hold = clf.predict_proba(X_hold)[:,1]
    fp = int((p_hold >= tau).sum())
    print(f"\n=== Hold-out benign @ threshold {tau} ===")
    print(f"Packets: {len(X_hold)}  False-positives: {fp}")

    joblib.dump(clf, ART/"ids_model.joblib")
    np.save(ART/"scaler_mean.npy", scaler.mean_)
    np.save(ART/"scaler_scale.npy", scaler.scale_)
    joblib.dump(enc_src, ART/"ip_src_encoder.joblib")
    joblib.dump(enc_dst, ART/"ip_dst_encoder.joblib")
    print("\nArtifacts saved in ./artifacts/")

if __name__ == "__main__":
    main()
