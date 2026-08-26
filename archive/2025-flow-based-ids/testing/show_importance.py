import joblib
import pandas as pd

# Încarcă modelul XGBoost
model = joblib.load("../cluster/dizertatie/artifacts/model_xgb/ids_pipeline.joblib")
feature_cols = joblib.load("../cluster/dizertatie/artifacts/model_xgb/feature_cols.joblib")

# Afișează importanța
importance_df = pd.DataFrame({
    'feature': feature_cols,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

print(importance_df.to_string())