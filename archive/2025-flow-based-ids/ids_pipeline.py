#!/usr/bin/env python3
"""
ids_pipeline.py – Build & evaluate a baseline intrusion-detection model
Author:  <you>
"""

# 0. Imports & dependencies
import pathlib, joblib, numpy as np, pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import pyshark           # needs Wireshark/tshark installed – brew install wireshark
                         #  if you prefer pure-python, switch to dpkt (slower)

# 1. Utility: pcap  DataFrame
def pcap_to_df(pcap_path: pathlib.Path, label: int) -> pd.DataFrame:
    """
    Parse TCP/UDP packets in *pcap_path* and return a DF with 5 features + label.
    """
    capture = pyshark.FileCapture(str(pcap_path), display_filter="tcp or udp")
    rows = []
    for pkt in capture:
        try:
            rows.append(dict(
                length   = int(pkt.length),
                src_ip   = pkt.ip.src,
                dst_ip   = pkt.ip.dst,
                src_port = pkt.tcp.srcport if 'TCP' in pkt else pkt.udp.srcport,
                dst_port = pkt.tcp.dstport if 'TCP' in pkt else pkt.udp.dstport,
                label    = label
            ))
        except AttributeError:
            # skip non-IP packets (rare with the display_filter but safe)
            continue
    capture.close()
    return pd.DataFrame(rows)

# 2. Load your pcaps
ROOT   = pathlib.Path(__file__).parent / "training"
benign_train = pcap_to_df(ROOT / "cluster-wordpress.pcap", label=0)
attacks      = pcap_to_df(ROOT / "cluster-attacks.pcap",   label=1)
benign_hold  = pcap_to_df(ROOT / "source-ip-app.pcap",     label=0)   # unseen benign test

print(f"Rows  benign_train={len(benign_train)}, attacks={len(attacks)}, benign_hold={len(benign_hold)}")

# Combine WP benign + attacks for training/validation
df = pd.concat([benign_train, attacks], ignore_index=True).sample(frac=1, random_state=42)

# 3. Encode categorical IPs & scale features
enc_ip = LabelEncoder()
for col in ("src_ip", "dst_ip"):
    df[col]        = enc_ip.fit_transform(df[col])
    benign_hold[col] = enc_ip.transform(benign_hold[col])

X      = df.drop(columns="label").values
y      = df["label"].values

scaler = StandardScaler().fit(X)
X      = scaler.transform(X)

# Hold-out 20 % from the mixed set for validation
X_tr, X_val, y_tr, y_val = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42)

# Prepare the external benign set (no attacks here)
X_hold = scaler.transform(benign_hold.drop(columns="label"))
y_hold = benign_hold["label"].values                    # all zeros

# 4. Train baseline MLP
clf = MLPClassifier(hidden_layer_sizes=(64, 32),
                    activation="relu",
                    solver="adam",
                    max_iter=120,
                    class_weight="balanced",
                    random_state=42)

clf.fit(X_tr, y_tr)

# 5. Evaluate
print("\n=== Validation on mixed set (20 %) ===")
print(classification_report(y_val, clf.predict(X_val), digits=4))
print(confusion_matrix(y_val, clf.predict(X_val)))

print("\n=== Generalisation on HOLD-OUT benign set ===")
y_pred_hold = clf.predict(X_hold)
false_alarms = (y_pred_hold == 1).sum()
print(f"Packets: {len(y_hold)}  False-positives: {false_alarms}")

# 6. Persist artefacts
ART = pathlib.Path("artifacts")
ART.mkdir(exist_ok=True)

joblib.dump(clf,              ART / "ids_model.joblib")
np.save(ART / "scaler_mean",  scaler.mean_)
np.save(ART / "scaler_scale", scaler.scale_)
joblib.dump(enc_ip,           ART / "ip_encoder.joblib")

print("\nSaved model & preprocessors to ./artifacts/")
