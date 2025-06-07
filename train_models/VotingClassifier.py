import json
import joblib
import pandas as pd
import warnings
import os
import sys

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
MODEL_PATH = os.path.join(BASE_DIR, "vc_model.pkl")
PREPROCESSOR_PATH = os.path.join(BASE_DIR, "vc_preprocessor.pkl")

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

# ────────── [1] 교차검증 (CV) ──────────
cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
scores = []
for fold_num, (train_idx, val_idx) in enumerate(cv.split(X_train, y_train)):
    print(f"🌀 Fold {fold_num + 1}/3 - training...", flush=True)
    final_model.fit(X_train[train_idx], y_train.iloc[train_idx])
    pred = final_model.predict(X_train[val_idx])
    score = f1_score(y_train.iloc[val_idx], pred, average="macro")
    scores.append(score)
    print(f"✅ Fold {fold_num + 1} score: {score:.6f}", flush=True)
print("\n[CV] 3-Fold Cross Validation Result")
print(" - Mean: %.6f / Std: %.6f" % (pd.Series(scores).mean(), pd.Series(scores).std()))

# ────────── [2] 8:2 Train/Test 분할 ──────────
final_model.fit(X_train, y_train)
y_pred = final_model.predict(X_test)
print("\n[Test] Hold-out 8:2 분할 (test set)")
print("────────────────── Classification Report ──────────────────")
print(classification_report(y_test, y_pred, digits=6))
print("- Accuracy: %.6f" % accuracy_score(y_test, y_pred))
print("- F1 Macro: %.6f" % f1_score(y_test, y_pred, average="macro"))


# ────────────────── 모델 및 전처리기 저장 ──────────────────
joblib.dump(final_model, MODEL_PATH)
joblib.dump(preprocessor, PREPROCESSOR_PATH)
print(f"\n✅ saved to '{MODEL_PATH}'")
print(f"✅ saved to '{PREPROCESSOR_PATH}'")
