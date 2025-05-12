import os
import sys
import json
import warnings
import pandas as pd
import optuna

from tqdm import tqdm
from sklearn.model_selection import StratifiedShuffleSplit, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
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

# ───────────────── 설정 ─────────────────
if not sys.warnoptions:
    warnings.simplefilter("ignore")
    os.environ["PYTHONWARNINGS"] = "ignore"
optuna.logging.set_verbosity(optuna.logging.WARNING)

# ────────────────── 경로 설정 ──────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "2025_URL_DATASET.csv")
BEST_PARAMS_PATH = os.path.join(BASE_DIR, "best_params.json")

# ───────────────── 데이터 불러오기 ─────────────────
df = pd.read_csv(DATA_PATH)
X = df.drop(columns=["url", "label"], errors="ignore")
y = df["label"]

# ───────────────── 전처리: 결식값 대체 + 정규화 ─────────────────
preprocessor = Pipeline([
    ("imputer", SimpleImputer(strategy="mean")),
    ("scaler", StandardScaler())
])
X_scaled = preprocessor.fit_transform(X)

# ───────────────── Stratified Shuffle Split로 train/test 분리 ─────────────────
sss = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(sss.split(X_scaled, y))
X_train, X_test = X_scaled[train_idx], X_scaled[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

X_train, X_test = X_train.astype(float), X_test.astype(float)
y_train, y_test = y_train.astype(float), y_test.astype(float)

# ───────────────── Optuna tqdm ─────────────────
class TQDMCallback:
    def __init__(self, n_trials):
        self.pbar = tqdm(total=n_trials, desc="Optuna Progress", ncols=100)
    def __call__(self, study, trial):
        self.pbar.update(1)

# ───────────────── Optuna 목적 함수 정의 (VotingClassifier 조합 최적화) ─────────────────
def objective(trial):
    models = []
    weights = []
    voting = trial.suggest_categorical("voting", ["soft", "hard"])

    def add_model(name, model, weight_key):
        models.append((name, model))
        weights.append(trial.suggest_int(weight_key, 1, 5))

    # LogisticRegression
    if trial.suggest_categorical("use_lr", [True, False]):
        add_model(
            "lr", 
            LogisticRegression(
                C=trial.suggest_float("lr_C", 0.01, 1.0),
                solver="liblinear", class_weight="balanced",
                max_iter=300
            ),
            "lr_w"
        )
    # XGBClassifier
    if trial.suggest_categorical("use_xgb", [True, False]):
        add_model(
            "xgb",
            XGBClassifier(
                n_estimators=trial.suggest_int("xgb_n", 100, 300),
                max_depth=trial.suggest_int("xgb_d", 3, 10),
                learning_rate=trial.suggest_float("xgb_lr", 0.01, 0.2),
                subsample=trial.suggest_float("xgb_sub", 0.5, 1.0),
                colsample_bytree=trial.suggest_float("xgb_col", 0.5, 1.0),
                use_label_encoder=False, eval_metric="logloss", verbosity=0
            ),
            "xgb_w"
        )
    # LGBMClassifier
    if trial.suggest_categorical("use_lgbm", [True, False]):
        add_model(
            "lgbm",
            LGBMClassifier(
                n_estimators=trial.suggest_int("lgbm_n", 100, 300),
                max_depth=trial.suggest_int("lgbm_d", 3, 10),
                learning_rate=trial.suggest_float("lgbm_lr", 0.01, 0.2),
                verbose=-1
            ),
            "lgbm_w"
        )
    # CatBoostClassifier
    if trial.suggest_categorical("use_cat", [True, False]):
        add_model(
            "cat",
            CatBoostClassifier(
                iterations=trial.suggest_int("cat_n", 100, 300),
                depth=trial.suggest_int("cat_d", 3, 10),
                learning_rate=trial.suggest_float("cat_lr", 0.01, 0.2),
                verbose=0
            ),
            "cat_w"
        )
    # MLPClassifier
    if trial.suggest_categorical("use_mlp", [True, False]):
        add_model(
            "mlp",
            MLPClassifier(
                hidden_layer_sizes=(trial.suggest_int("mlp_l1", 50, 200),trial.suggest_int("mlp_l2", 20, 100)),
                alpha=trial.suggest_float("mlp_alpha", 1e-5, 1e-2),
                max_iter=500
            ),
            "mlp_w"
        )
    # SVC
    if trial.suggest_categorical("use_svc", [True, False]):
        add_model(
            "svc",
            SVC(
                C=trial.suggest_float("svc_C", 0.1, 10.0),
                probability=True,
                class_weight="balanced"
            ),
            "svc_w"
        )
    # KNeighborsClassifier
    if trial.suggest_categorical("use_knn", [True, False]):
        add_model(
            "knn",
            KNeighborsClassifier(
                n_neighbors=trial.suggest_int("knn_k", 3, 10)
            ),
            "knn_w"
        )
    # ExtraTreesClassifier
    if trial.suggest_categorical("use_et", [True, False]):
        add_model(
            "et",
            ExtraTreesClassifier(
                n_estimators=trial.suggest_int("et_n", 100, 300),
                max_depth=trial.suggest_int("et_d", 5, 30)
            ),
            "et_w"
        )
    # GradientBoostingClassifier
    if trial.suggest_categorical("use_gb", [True, False]):
        add_model(
            "gb",
            GradientBoostingClassifier(
                n_estimators=trial.suggest_int("gb_n", 100, 300),
                max_depth=trial.suggest_int("gb_d", 3, 10),
                learning_rate=trial.suggest_float("gb_lr", 0.01, 0.2)
            ),
            "gb_w"
        )
    # HistGradientBoostingClassifier
    if trial.suggest_categorical("use_hist", [True, False]):
        add_model(
            "hist",
            HistGradientBoostingClassifier(
                max_iter=trial.suggest_int("hist_iter", 100, 300)
            ),
            "hist_w"
        )
    # BaggingClassifier
    if trial.suggest_categorical("use_bag", [True, False]):
        add_model(
            "bag",
            BaggingClassifier(
                n_estimators=trial.suggest_int("bag_n", 10, 50)
            ),
            "bag_w"
        )
    # RidgeClassifier
    if trial.suggest_categorical("use_ridge", [True, False]):
        add_model(
            "ridge",
            RidgeClassifier(
                alpha=trial.suggest_float("ridge_alpha", 0.1, 5.0),
                class_weight="balanced"
            ),
            "ridge_w"
        )
    # DecisionTreeClassifier
    if trial.suggest_categorical("use_dt", [True, False]):
        add_model(
            "dt",
            DecisionTreeClassifier(
                max_depth=trial.suggest_int("dt_d", 3, 20),
                class_weight="balanced"
            ),
            "dt_w"
        )
    # GaussianNB
    if trial.suggest_categorical("use_nb", [True, False]):
        add_model(
            "nb",
            GaussianNB(),
            "nb_w"
        )
    # RandomForestClassifier
    if trial.suggest_categorical("use_rf", [True, False]):
        add_model(
            "rf",
            RandomForestClassifier(
                n_estimators=trial.suggest_int("rf_n", 100, 300),
                max_depth=trial.suggest_int("rf_d", 5, 30),
                class_weight="balanced"
            ),
            "rf_w"
        )
    # AdaBoostClassifier
    if trial.suggest_categorical("use_ada", [True, False]):
        add_model(
            "ada",
            AdaBoostClassifier(
                n_estimators=trial.suggest_int("ada_n", 50, 200),
                learning_rate=trial.suggest_float("ada_lr", 0.01, 1.0)
            ),
            "ada_w"
        )
    # SGDClassifier
    if trial.suggest_categorical("use_sgd", [True, False]):
        add_model(
            "sgd",
            SGDClassifier(
                alpha=trial.suggest_float("sgd_alpha", 1e-5, 1e-2),
                max_iter=trial.suggest_int("sgd_iter", 500, 1000),
                class_weight="balanced"
            ),
            "sgd_w"
        )
    # PassiveAggressiveClassifier
    if trial.suggest_categorical("use_pa", [True, False]):
        add_model(
            "pa",
            PassiveAggressiveClassifier(
                C=trial.suggest_float("pa_C", 0.1, 5.0),
                max_iter=trial.suggest_int("pa_iter", 500, 1000),
                class_weight="balanced"
            ),
            "pa_w"
        )
    # LinearDiscriminantAnalysis
    if trial.suggest_categorical("use_lda", [True, False]):
        add_model(
            "lda",
            LinearDiscriminantAnalysis(),
            "lda_w"
        )
    # QuadraticDiscriminantAnalysis
    if trial.suggest_categorical("use_qda", [True, False]):
        add_model(
            "qda",
            QuadraticDiscriminantAnalysis(),
            "qda_w"
        )

    

    if not models:
        return 0.0
    clf = VotingClassifier(estimators=models, voting=voting, weights=weights if voting == "soft" else None)
    if voting == "soft":
        for _, m in clf.estimators:
            if not hasattr(m, "predict_proba"):
                return 0.0
    return cross_val_score(clf, X_train, y_train, cv=5, scoring="f1_macro", n_jobs=-1).mean()

# ───────────────── 탐색 횟수 ─────────────────
n_trials = 5        # 횟수 조절
study = optuna.create_study(direction="maximize")
study.optimize(objective, n_trials=n_trials, callbacks=[TQDMCallback(n_trials)])

# ───────────────── 결과 출력 ─────────────────
print(f"\n- n_trials: {len(study.trials)}")

param_name_mapping = {
    "n": "n_estimators", "d": "max_depth", "lr": "learning_rate", "l1": "layer_1_size",
    "l2": "layer_2_size", "alpha": "regularization_alpha", "C": "penalty_C",
    "sub": "subsample", "col": "colsample_bytree", "iter": "max_iter"
}
model_keys = {
    "lr": "LogisticRegression", "xgb": "XGBoost", "lgbm": "LightGBM", "cat": "CatBoost",
    "mlp": "MLP", "svc": "SVC", "knn": "KNN", "et": "ExtraTrees", "gb": "GradientBoosting",
    "hist": "HistGradientBoosting", "bag": "Bagging", "ridge": "Ridge", "dt": "DecisionTree", "nb": "NaiveBayes",
    "rf": "RandomForest", "ada": "AdaBoost", "sgd": "SGD", "pa": "PassiveAggressive",
    "lda": "LDA", "qda": "QDA"
}

print("\n─────────────── Best Model Summary ───────────────\n")
print(f"Voting type: {study.best_trial.params['voting']}\n")

for key in model_keys:
    if study.best_trial.params.get(f"use_{key}"):
        print(f"Evaluation model: {model_keys[key]}")
        print(f"- weight: {study.best_trial.params.get(f'{key}_w', '-')}")
        for p in study.best_trial.params:
            if p.startswith(f"{key}_") and not p.endswith("_w"):
                short = p.replace(f"{key}_", "")
                name = param_name_mapping.get(short, short)
                val = study.best_trial.params[p]
                print(f"- {name}: {val:.6f}" if isinstance(val, float) else f"- {name}: {val}")
        print()

# ───────────────── Best params 저장 ─────────────────
with open(BEST_PARAMS_PATH, "w") as f:
    json.dump(study.best_trial.params, f, indent=2)

print(f"\n✅ saved to '{BEST_PARAMS_PATH}'")
