import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
from sklearn.preprocessing import LabelEncoder

# Presupun că ai df_all cu toate datele combinate
# Adaugă coloana 'source' dacă nu există deja

# Antrenează să prezică SURSA, nu label-ul
X = df_all[['duration_s', 'tot_fwd_pkts', 'tot_bwd_pkts', 'tot_bytes',
            'fwd_pkt_len_mean', 'bwd_pkt_len_mean', 'flow_pkts_per_s', 'flow_iat_mean_s']]
y_source = df_all['source']  # 'k8s', 'cicids', 'unsw', 'botiot'

le = LabelEncoder()
y_source_encoded = le.fit_transform(y_source)

clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
scores = cross_val_score(clf, X, y_source_encoded, cv=5, scoring='accuracy')

print(f"Accuracy la prezicerea SURSEI dataset-ului: {scores.mean():.1%}")
print(f"(Dacă > 90%, modelul poate distinge sursele, deci poate 'trișa')")