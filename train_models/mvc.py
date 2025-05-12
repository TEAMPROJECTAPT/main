import json
import joblib
import pandas as pd
import warnings
import os
import sys

from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import (
    VotingClassifier, GradientBoostingClassifier, ExtraTreesClassifier,
    BaggingClassifier, HistGradientBoostingClassifier
)
from sklearn.linear_model import RidgeClassifier, LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.linear_model import SGDClassifier, PassiveAggressiveClassifier
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis, QuadraticDiscriminantAnalysis
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from catboost import CatBoostClassifier
from sklearn.metrics import classification_report, accuracy_score

# ────────────────── 설정 ──────────────────
if not sys.warnoptions:
    warnings.simplefilter("ignore")
    os.environ["PYTHONWARNINGS"] = "ignore"

# ────────────────── 경로 설정 ──────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PARAMS_PATH = os.path.join(BASE_DIR, "best_params.json")
DATA_PATH = os.path.join(BASE_DIR, "2025_URL_DATASET.csv")
MODEL_PATH = os.path.join(BASE_DIR, "mvc_model.pkl")
PREPROCESSOR_PATH = os.path.join(BASE_DIR, "preprocessor.pkl")

# ────────────────── best_params 로드 ──────────────────
with open(PARAMS_PATH, "r") as f:
    best_params = json.load(f)

# ────────────────── 데이터셋 불러오기 ──────────────────
df = pd.read_csv(DATA_PATH)
X = df.drop(columns=["url", "label"], errors="ignore")
y = df["label"]

# ────────────────── 전처리 ──────────────────
preprocessor = Pipeline([
    ("imputer", SimpleImputer(strategy="mean")),
    ("scaler", StandardScaler())
])
X_scaled = preprocessor.fit_transform(X)

sss = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(sss.split(X_scaled, y))
X_train, X_test = X_scaled[train_idx], X_scaled[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

X_train, X_test = X_train.astype(float), X_test.astype(float)
y_train, y_test = y_train.astype(float), y_test.astype(float)

# ────────────────── 모델 구성 함수 ──────────────────
def get_model(name, params):
    if name == "lr":
        return LogisticRegression(
            C=params["lr_C"], solver="liblinear", class_weight="balanced", max_iter=300
        )
    if name == "xgb":
        return XGBClassifier(
            n_estimators=params["xgb_n"],
            max_depth=params["xgb_d"],
            learning_rate=params["xgb_lr"],
            subsample=params["xgb_sub"],
            colsample_bytree=params["xgb_col"],
            use_label_encoder=False, eval_metric="logloss",
            verbosity=0
        )
    if name == "lgbm":
        return LGBMClassifier(
            n_estimators=params["lgbm_n"],
            max_depth=params["lgbm_d"],
            learning_rate=params["lgbm_lr"],
            verbose=-1
        )
    if name == "cat":
        return CatBoostClassifier(
            iterations=params["cat_n"],
            depth=params["cat_d"],
            learning_rate=params["cat_lr"],
            verbose=0
        )
    if name == "mlp":
        return MLPClassifier(
            hidden_layer_sizes=(params["mlp_l1"],params["mlp_l2"]),
            alpha=params["mlp_alpha"],
            max_iter=500
        )
    if name == "svc":
        return SVC(
            C=params["svc_C"],
            probability=True,
            class_weight="balanced"
        )
    if name == "knn":
        return KNeighborsClassifier(
            n_neighbors=params["knn_k"]
        )
    if name == "et":
        return ExtraTreesClassifier(
            n_estimators=params["et_n"],
            max_depth=params["et_d"]
        )
    if name == "gb":
        return GradientBoostingClassifier(
            n_estimators=params["gb_n"],
            max_depth=params["gb_d"],
            learning_rate=params["gb_lr"]
        )
    if name == "hist":
        return HistGradientBoostingClassifier(
            max_iter=params["hist_iter"]
        )
    if name == "bag":
        return BaggingClassifier(
            n_estimators=params["bag_n"]
        )
    if name == "ridge":
        return RidgeClassifier(
            alpha=params["ridge_alpha"],
            class_weight="balanced"
        )
    if name == "dt":
        return DecisionTreeClassifier(
            max_depth=params["dt_d"],
            class_weight="balanced"
        )
    if name == "nb":
        return GaussianNB()
    if name == "rf":
        return RandomForestClassifier(
            n_estimators=params["rf_n"],
            max_depth=params["rf_d"],
            class_weight="balanced"
        )
    if name == "ada":
        return AdaBoostClassifier(
            n_estimators=params["ada_n"],
            learning_rate=params["ada_lr"]
        )
    if name == "sgd":
        return SGDClassifier(
            alpha=params["sgd_alpha"],
            max_iter=params["sgd_iter"],
            class_weight="balanced"
        )
    if name == "pa":
        return PassiveAggressiveClassifier(
            C=params["pa_C"],
            max_iter=params["pa_iter"],
            class_weight="balanced"
        )
    if name == "lda":
        return LinearDiscriminantAnalysis()
    if name == "qda":
        return QuadraticDiscriminantAnalysis()

# ────────────────── 모델 조합 생성 ──────────────────
model_keys = ["lr", "xgb", "lgbm", "cat", "mlp", "svc", "knn", "et", "gb", "hist", "bag", "ridge", "dt", "nb"]
models, weights = [], []
for key in model_keys:
    if best_params.get(f"use_{key}"):
        model = get_model(key, best_params)
        models.append((key, model))
        weights.append(best_params.get(f"{key}_w", 1))

voting_type = best_params["voting"]
final_model = VotingClassifier(estimators=models, voting=voting_type, weights=weights if voting_type == "soft" else None)

# ────────────────── 학습 및 평가 ──────────────────
final_model.fit(X_train, y_train)
y_pred = final_model.predict(X_test)
print("────────────────── Classification Report ──────────────────")
print(classification_report(y_test, y_pred))
print("- Accuracy:", round(accuracy_score(y_test, y_pred), 5))

# ────────────────── 모델 및 전처리기 저장 ──────────────────
joblib.dump(final_model, MODEL_PATH)
joblib.dump(preprocessor, PREPROCESSOR_PATH)
print(f"\n✅ saved to '{MODEL_PATH}'")
print(f"✅ saved to '{PREPROCESSOR_PATH}'")
