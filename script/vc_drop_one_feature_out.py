import json
import joblib
import pandas as pd
import warnings
import os
import sys
import matplotlib.pyplot as plt
import numpy as np

from sklearn.model_selection import StratifiedShuffleSplit, StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import (
    VotingClassifier, GradientBoostingClassifier, ExtraTreesClassifier,
    BaggingClassifier, HistGradientBoostingClassifier,
    RandomForestClassifier, AdaBoostClassifier
)
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from catboost import CatBoostClassifier
from sklearn.metrics import classification_report, accuracy_score, f1_score

# ────────────────── 경고 제거 ──────────────────
if not sys.warnoptions:
    warnings.simplefilter("ignore")
    os.environ["PYTHONWARNINGS"] = "ignore"
# ────────────────── 경로 설정 ──────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PARAMS_PATH = os.path.join(BASE_DIR, "best_params.json")
DATA_PATH = os.path.join(BASE_DIR, "2025_URL_DATASET.csv")

# ────────────────── best_params 로드 ──────────────────
with open(PARAMS_PATH, "r") as f:
    best_params = json.load(f)

# ────────────────── 데이터셋 로드 ──────────────────
df = pd.read_csv(DATA_PATH)
X = df.drop(columns=["url", "label"], errors="ignore")
y = df["label"]

# ────────────────── 전처리 ──────────────────
preprocessor_cv = Pipeline([
    ("imputer", SimpleImputer(strategy="mean")),
    ("scaler", StandardScaler())
])

sss = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(sss.split(X, y))
X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

preprocessor = Pipeline([
    ("imputer", SimpleImputer(strategy="mean")),
    ("scaler", StandardScaler())
])
X_train = preprocessor.fit_transform(X_train)
X_test = preprocessor.transform(X_test)

# ────────────────── 모델 구성 ──────────────────
def get_model(name, params):

    if name == "lr":
        return LogisticRegression(
            C = params["lr_C"],
            solver = "liblinear",
            class_weight = "balanced",
            max_iter = params["lr_iter"]
        )
    
    if name == "xgb":
        return XGBClassifier(
            n_estimators = params["xgb_n"],
            max_depth = params["xgb_d"],
            learning_rate = params["xgb_lr"],
            subsample = params["xgb_sub"],
            colsample_bytree = params["xgb_col"],
            reg_alpha = params["xgb_alpha"],
            reg_lambda = params["xgb_lambda"],
            gamma = params["xgb_gamma"],
            scale_pos_weight = params["xgb_spw"],
            use_label_encoder = False,
            eval_metric = "logloss",
            random_state = 42,
            verbosity = 0
        )
    
    if name == "lgbm":
        return LGBMClassifier(
            n_estimators = params["lgbm_n"],
            max_depth = params["lgbm_d"],
            learning_rate = params["lgbm_lr"],
            num_leaves = params["lgbm_leaves"],
            min_child_samples = params["lgbm_child"],
            reg_alpha = params["lgbm_alpha"],
            reg_lambda = params["lgbm_lambda"],
            random_state = 42,
            verbose = -1
        )
    
    if name == "cat":
        return CatBoostClassifier(
            iterations = params["cat_n"],
            depth = params["cat_d"],
            learning_rate = params["cat_lr"],
            l2_leaf_reg = params["cat_l2"],
            border_count = params["cat_border"],
            random_seed = 42,
            verbose = 0
        )
    
    if name == "mlp":
        return MLPClassifier(
            hidden_layer_sizes = (params["mlp_l1"], params["mlp_l2"]),
            alpha = params["mlp_alpha"],
            learning_rate_init = params["mlp_lr"],
            max_iter = params["mlp_iter"],
            random_state = 42
        )
    
    if name == "svc":
        return SVC(
            C = params["svc_C"],
            gamma = params["svc_gamma"],
            kernel = params["svc_kernel"],
            probability = True,
            class_weight = "balanced",
            random_state = 42
        )
    
    if name == "et":
        return ExtraTreesClassifier(
            n_estimators = params["et_n"],
            max_depth = params["et_d"],
            min_samples_split = params["et_split"],
            class_weight = "balanced",
            random_state = 42
        )
    
    if name == "gb":
        return GradientBoostingClassifier(
            n_estimators = params["gb_n"],
            learning_rate = params["gb_lr"],
            max_depth = params["gb_d"],
            min_samples_leaf = params["gb_leaf"],
            random_state = 42
        )
    
    if name == "hist":
        return HistGradientBoostingClassifier(
            max_iter = params["hist_iter"],
            learning_rate = params["hist_lr"],
            max_depth = params["hist_d"],
            min_samples_leaf = params["hist_leaf"],
            random_state = 42
        )
    
    if name == "bag":
        return BaggingClassifier(
            estimator = DecisionTreeClassifier(random_state=42),
            n_estimators = params["bag_n"],
            random_state = 42
        )
    
    if name == "dt":
        return DecisionTreeClassifier(
            max_depth = params["dt_d"],
            min_samples_split = params["dt_split"],
            class_weight = "balanced",
            random_state = 42
        )
    
    if name == "rf":
        return RandomForestClassifier(
            n_estimators = params["rf_n"],
            max_depth = params["rf_d"],
            min_samples_split = params["rf_split"],
            class_weight = "balanced",
            random_state = 42
        )
    
    if name == "ada":
        return AdaBoostClassifier(
            n_estimators = params["ada_n"],
            learning_rate = params["ada_lr"],
            random_state = 42
        )
    
    if name == "lda":
        return LinearDiscriminantAnalysis(
            solver = params["lda_solver"],
            shrinkage = params.get("lda_shrink", None),
        )

# ────────────────── 모델 조합 생성 ──────────────────
model_keys = [
    "lr", "xgb", "lgbm", "cat", "mlp", "svc",
    "et", "gb", "hist", "bag", "dt", "rf", "ada", "lda"
]
models, weights = [], []
for key in model_keys:
    if best_params.get(f"use_{key}"):
        model = get_model(key, best_params)
        models.append((key, model))
        weights.append(best_params.get(f"{key}_w", 1))

final_model = VotingClassifier(estimators=models, voting="soft", weights=weights)

# ─────────────────────────────────── 결과 출력 ───────────────────────────────────
feature_names = [col for col in df.columns if col not in ["url", "label"]]
results = []

for i, feature_to_drop in enumerate(feature_names):
    print(f"\n\n[Feature {i+1}/{len(feature_names)} 제외: '{feature_to_drop}'] ------------------------------")
    
    # 피처 하나 제외한 데이터 생성
    X_drop = df.drop(columns=["url", "label", feature_to_drop], errors="ignore")
    y_drop = df["label"]
    
    # 8:2 split (drop-one feature 기준)
    sss = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(sss.split(X_drop, y_drop))
    X_train_, X_test_ = X_drop.iloc[train_idx], X_drop.iloc[test_idx]
    y_train_, y_test_ = y_drop.iloc[train_idx], y_drop.iloc[test_idx]
    
    # 전처리
    preprocessor_ = Pipeline([
        ("imputer", SimpleImputer(strategy="mean")),
        ("scaler", StandardScaler())
    ])
    X_train_ = preprocessor_.fit_transform(X_train_)
    X_test_ = preprocessor_.transform(X_test_)
    
    # 모델 생성 (아래는 기존 코드 그대로 복사)
    models_, weights_ = [], []
    for key in model_keys:
        if best_params.get(f"use_{key}"):
            model_ = get_model(key, best_params)
            models_.append((key, model_))
            weights_.append(best_params.get(f"{key}_w", 1))
    final_model_ = VotingClassifier(estimators=models_, voting="soft", weights=weights_)
    
    # 평가 (drop-one)
    final_model_.fit(X_train_, y_train_)
    y_pred_ = final_model_.predict(X_test_)
    acc = accuracy_score(y_test_, y_pred_)
    # f1 = f1_score(y_test_, y_pred_, average="macro")   # 필요 없다면 생략
    print("- Accuracy: %.6f" % acc)
    results.append((feature_to_drop, acc))

# --- 결과 요약표 출력 및 시각화 ---
print("\n\n======== [Feature Drop 결과 요약] ========")
print("Feature Dropped\t\tAccuracy")
for f, acc in results:
    print(f"{f:<30}\t{acc:.6f}")

import matplotlib.pyplot as plt
import seaborn as sns

results_df = pd.DataFrame(results, columns=["Feature", "Accuracy"])
results_df = results_df.sort_values("Accuracy", ascending=False)  # 정확도 내림차순(높은게 위)

plt.figure(figsize=(12, 8))
sns.barplot(data=results_df, x="Accuracy", y="Feature", palette="viridis")

plt.title("Test Accuracy by Dropped Feature (Drop-One-Feature-Out)")
plt.xlabel("Test Accuracy (Drop-One)")
plt.ylabel("Dropped Feature")
plt.xlim(0.9, 1.00)
plt.tight_layout()
plt.savefig("drop_one_feature_accuracy.png")
plt.close()
print("✅ 중요도 이미지 저장 완료: drop_one_feature_accuracy.png")