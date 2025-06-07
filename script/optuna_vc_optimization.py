import os
import sys
import json
import warnings
import pandas as pd
import optuna
import numpy as np
import time

from optuna.samplers import TPESampler
from sklearn.model_selection import StratifiedShuffleSplit, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
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
from sklearn.metrics import f1_score

# 여러 개의 터미널에서 python optuna_mvc_optimization.py 실행

# optuna dashboard 실행
# optuna-dashboard "mysql+pymysql://optuna:yourpassword@localhost/optuna_db"
# trial 진행 중에 실행시 반드시 좌측 하단 live update off
# google drive, colab, github codespaces 등에서 사용 x, 로컬 환경에서 사용
# db 동시 write 방지 목적임

# ──────────────────── 경고 제거 ────────────────────
if not sys.warnoptions:
    warnings.simplefilter("ignore")
    os.environ["PYTHONWARNINGS"] = "ignore"
optuna.logging.set_verbosity(optuna.logging.WARNING)

# ───────────────────────── 경로 설정 ─────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "2025_URL_DATASET.csv")
BEST_PARAMS_PATH = os.path.join(BASE_DIR, "best_params.json")
STUDY_DB_PATH = os.path.join(BASE_DIR, "optuna_study.db")

# ─────────────────── 데이터셋 로드 ───────────────────
df = pd.read_csv(DATA_PATH)
X = df.drop(columns=["url", "label"], errors="ignore").values
y = df["label"].values

# ──────────────────── 전처리 ────────────────────
sss = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(sss.split(X, y))
X_train, X_test = X[train_idx], X[test_idx]
y_train, y_test = y[train_idx], y[test_idx]

preprocessor = Pipeline([
    ("imputer", SimpleImputer(strategy="mean")),
    ("scaler", StandardScaler())
])
X_train = preprocessor.fit_transform(X_train)
X_test = preprocessor.transform(X_test)

# ────────────── trial 내부 fold 학습/검증 출력──────────────
def cross_val_with_progress(clf, X, y, cv=3):
    skf = StratifiedKFold(n_splits=cv, shuffle=True, random_state=42)
    scores = []
    for fold_num, (train_idx, val_idx) in enumerate(skf.split(X, y)):
        y_val = y[val_idx]
        print(f"🌀 Fold {fold_num + 1}/{cv} - training...", flush=True)
        # 실제값이 한 클래스만 있는 경우 fold skip
        if len(np.unique(y_val)) < 2:
            print(f"⚠️ Fold {fold_num+1} skipped (single class in y_val)", flush=True)
            continue
        try:
            clf.fit(X[train_idx], y[train_idx])
            pred = clf.predict(X[val_idx])
            # 예측값도 한 클래스만 나오면 skip
            if len(np.unique(pred)) < 2:
                print(f"⚠️ Fold {fold_num+1} skipped (single class in prediction)", flush=True)
                continue
            score = f1_score(y_val, pred, average="macro")
            scores.append(score)
            print(f"✅ Fold {fold_num + 1} score: {score:.4f}", flush=True)
        except Exception as e:
            print(f"❌ Fold {fold_num + 1} failed: {e}", flush=True)
    return np.mean(scores) if scores else None   # scores 없으면 None 반환

# 시간 형식 변환
def format_time(seconds):
    h = int(seconds) // 3600
    m = (int(seconds) % 3600) // 60
    s = int(seconds) % 60
    return f"{h}h {m}m {s}s"

# ────────── Optuna 목적 함수 정의 ──────────
def objective(trial):
    models, weights = [], []
    voting = "soft"

    def add_model(name, model, weight_key):
        models.append((name, model))
        weights.append(trial.suggest_int(weight_key, 1, 5))

    if trial.suggest_categorical("use_lr", [True, False]):
        add_model("lr", LogisticRegression(
            C = trial.suggest_float("lr_C", 0.01, 2.0, log = True),
            max_iter = trial.suggest_int("lr_iter", 100, 500),
            solver = "liblinear",
            class_weight = "balanced"
        ), "lr_w")

    if trial.suggest_categorical("use_xgb", [True, False]):
        add_model("xgb", XGBClassifier(
            n_estimators = trial.suggest_int("xgb_n", 100, 500),
            max_depth = trial.suggest_int("xgb_d", 3, 7 ),
            learning_rate = trial.suggest_float("xgb_lr", 0.01, 0.2),
            subsample = trial.suggest_float("xgb_sub", 0.6, 1.0),
            colsample_bytree = trial.suggest_float("xgb_col", 0.6, 1.0),
            reg_alpha = trial.suggest_float("xgb_alpha", 0, 5.0),
            reg_lambda = trial.suggest_float("xgb_lambda", 0, 5.0),
            gamma = trial.suggest_float("xgb_gamma", 0, 2.0),
            scale_pos_weight = trial.suggest_float("xgb_spw", 1.0, 5.0),
            use_label_encoder = False,
            eval_metric = "logloss",
            random_state = 42,
            verbosity = 0
        ), "xgb_w")

    if trial.suggest_categorical("use_lgbm", [True, False]):
        add_model("lgbm", LGBMClassifier(
            n_estimators = trial.suggest_int("lgbm_n", 100, 500),
            max_depth = trial.suggest_int("lgbm_d", 3, 7),
            learning_rate = trial.suggest_float("lgbm_lr", 0.01, 0.2),
            num_leaves = trial.suggest_int("lgbm_leaves", 31, 64),
            min_child_samples = trial.suggest_int("lgbm_child", 10, 30),
            reg_alpha = trial.suggest_float("lgbm_alpha", 0, 3.0),
            reg_lambda = trial.suggest_float("lgbm_lambda", 0, 3.0),
            random_state = 42,
            verbose = -1
        ), "lgbm_w")

    if trial.suggest_categorical("use_cat", [True, False]):
        add_model("cat", CatBoostClassifier(
            iterations = trial.suggest_int("cat_n", 100, 500),
            depth = trial.suggest_int("cat_d", 3, 7),
            learning_rate = trial.suggest_float("cat_lr", 0.01, 0.2),
            l2_leaf_reg = trial.suggest_float("cat_l2", 1, 5.0),
            border_count = trial.suggest_int("cat_border", 32, 128),
            random_seed = 42,
            verbose = 0
        ), "cat_w")

    if trial.suggest_categorical("use_mlp", [True, False]):
        add_model("mlp", MLPClassifier(
            hidden_layer_sizes = (
                trial.suggest_int("mlp_l1", 50, 200),
                trial.suggest_int("mlp_l2", 20, 100)
            ),  
            alpha = trial.suggest_float("mlp_alpha", 1e-5, 1e-3, log = True),
            learning_rate_init = trial.suggest_float("mlp_lr", 0.001, 0.01),
            max_iter = trial.suggest_int("mlp_iter", 300, 700),
            random_state = 42
        ), "mlp_w")

    if trial.suggest_categorical("use_svc", [True, False]):
        add_model("svc", SVC(
            C = trial.suggest_float("svc_C", 0.1, 5.0),
            gamma = trial.suggest_categorical("svc_gamma", ["scale", "auto"]),
            kernel = trial.suggest_categorical("svc_kernel", ["linear", "rbf"]),
            probability = True,
            class_weight = "balanced",
            random_state = 42
        ), "svc_w")

    if trial.suggest_categorical("use_et", [True, False]):
        add_model("et", ExtraTreesClassifier(
            n_estimators = trial.suggest_int("et_n", 100, 500),
            max_depth = trial.suggest_int("et_d", 5, 15),
            min_samples_split = trial.suggest_int("et_split", 2, 8),
            class_weight = "balanced",
            random_state = 42
        ), "et_w")

    if trial.suggest_categorical("use_gb", [True, False]):
        add_model("gb", GradientBoostingClassifier(
            n_estimators = trial.suggest_int("gb_n", 100, 500),
            learning_rate = trial.suggest_float("gb_lr", 0.01, 0.1),
            max_depth = trial.suggest_int("gb_d", 3, 7),
            min_samples_leaf = trial.suggest_int("gb_leaf", 5, 20),
            random_state = 42
        ), "gb_w")

    if trial.suggest_categorical("use_hist", [True, False]):
        add_model("hist", HistGradientBoostingClassifier(
            max_iter = trial.suggest_int("hist_iter", 100, 500),
            learning_rate = trial.suggest_float("hist_lr", 0.01, 0.1),
            max_depth = trial.suggest_int("hist_d", 3, 7),
            min_samples_leaf = trial.suggest_int("hist_leaf", 5, 20),
            random_state = 42
        ), "hist_w")

    if trial.suggest_categorical("use_bag", [True, False]):
        add_model("bag", BaggingClassifier(
            estimator=DecisionTreeClassifier(random_state=42),
            n_estimators = trial.suggest_int("bag_n", 10, 50),
            random_state = 42
        ), "bag_w")

    if trial.suggest_categorical("use_dt", [True, False]):
        add_model("dt", DecisionTreeClassifier(
            max_depth = trial.suggest_int("dt_d", 3, 10),
            min_samples_split = trial.suggest_int("dt_split", 2, 8),
            min_samples_leaf = trial.suggest_int("dt_split", 2, 8),
            class_weight = "balanced",
            random_state = 42
        ), "dt_w")

    if trial.suggest_categorical("use_rf", [True, False]):
        add_model("rf", RandomForestClassifier(
            n_estimators = trial.suggest_int("rf_n", 100, 500),
            max_depth = trial.suggest_int("rf_d", 5, 15),
            min_samples_split = trial.suggest_int("rf_split", 2, 8),
            class_weight = "balanced",
            random_state = 42
        ), "rf_w")

    if trial.suggest_categorical("use_ada", [True, False]):
        add_model("ada", AdaBoostClassifier(
            n_estimators = trial.suggest_int("ada_n", 50, 150),
            learning_rate = trial.suggest_float("ada_lr", 0.01, 0.5),
            random_state = 42,
        ), "ada_w")

    if trial.suggest_categorical("use_lda", [True, False]):
        solver = trial.suggest_categorical("lda_solver", ["lsqr", "eigen"])
        shrinkage_opt = trial.suggest_categorical("lda_shrink", ["auto", "none"])
        shrinkage = None if shrinkage_opt == "none" else shrinkage_opt
        add_model("lda", LinearDiscriminantAnalysis(
            solver = solver,
            shrinkage = shrinkage
        ), "lda_w")

    if len(models) < 2:
        print("⏭️ Fewer than 2 models selected. Pruning this trial.")
        raise optuna.exceptions.TrialPruned()

    clf = VotingClassifier(estimators=models, voting=voting, weights=weights)
    return cross_val_with_progress(clf, X_train, y_train)

# ───────────────── 탐색 횟수 ─────────────────
n_trials = 5511
sampler = TPESampler(
    n_startup_trials=3500,
    n_ei_candidates=100,
    multivariate=True,
    group=True
)
storage = optuna.storages.RDBStorage(
    url="mysql+pymysql://optuna:yourpassword@localhost/optuna_db",
    heartbeat_interval=60,  # 1분마다 heartbeat
    grace_period=120        # 2분 이상 응답 없으면 fail 처리
)
study = optuna.create_study(
    study_name="voting_opt_random3500",
    storage=storage,
    direction="maximize",
    sampler=sampler,
    load_if_exists=True,
)
start_time = time.time()

initial_trial_count = len(study.trials)
if initial_trial_count > 0:
    print(f"Resuming from Trial {initial_trial_count + 1} (already completed: {initial_trial_count})", flush=True)
else:
    print(f"Starting fresh with Trial 1", flush=True)

for i in range(len(study.trials), n_trials):
    try:
        trial = study.ask()
    except KeyError as e:
        print(f"❌ Trial 생성 실패: {e} → 다음 trial로 넘어감", flush=True)
        continue
    start_trial_time = time.time()

    try:
        # objective 내부 오류까지 잡기 위해 내부도 try로 감싸기
        try:
            score = objective(trial)
        except Exception as obj_err:
            print(f"❌ Trial {i+1} failed inside objective(): {obj_err}", flush=True)
            study.tell(trial, state=optuna.trial.TrialState.FAIL)
            continue

        elapsed_trial = time.time() - start_trial_time
        if score is None or (isinstance(score, float) and (np.isnan(score) or score < 0.0 or score > 1.0)):
            study.tell(trial, state=optuna.trial.TrialState.FAIL)
            print(f"⚠️ Trial {i+1} failed due to invalid score.", flush=True)
            continue

        trial.set_user_attr("score", score)
        trial.set_user_attr("elapsed_sec", round(elapsed_trial, 2))
        models_str = ", ".join(
            name.replace("use_", "") for name in trial.params if name.startswith("use_") and trial.params[name]
        )
        trial.set_user_attr("models", models_str)

        study.tell(trial, score)

        elapsed = time.time() - start_time
        avg_time = elapsed / (i + 1)
        eta = avg_time * (n_trials - i - 1)
        print(f"[Trial {trial.number+1}/{n_trials}] Score: {score:.4f} | Elapsed: {format_time(elapsed)} | ETA: {format_time(eta)}", flush=True)

    except Exception as e:
        print(f"❌ Trial {i+1} failed in outer block: {str(e).splitlines()[0]}", flush=True)
        study.tell(trial, state=optuna.trial.TrialState.FAIL)


# ───────────────── 결과 출력 ─────────────────
print(f"\n- n_trials: {len(study.trials)}")

param_name_mapping = {
    # ─────── 공통 ───────
    "n": "n_estimators",
    "d": "max_depth",
    "lr": "learning_rate",
    "iter": "max_iter",
    "alpha": "regularization_alpha",
    "C": "penalty_C",
    "sub": "subsample",
    "col": "colsample_bytree",
    "gamma": "min_split_loss",
    "spw": "scale_pos_weight",
    "lambda": "reg_lambda",
    "split": "min_samples_split",
    "leaf": "min_samples_leaf",

    # ───── MLP ─────
    "l1": "layer_1_size",
    "l2": "layer_2_size",
    "mlp_alpha": "regularization_alpha",
    "mlp_lr": "learning_rate_init",

    # ───── LGBM ─────
    "leaves": "num_leaves",
    "child": "min_child_samples",

    # ───── CatBoost ─────
    "border": "border_count",
    "cat_l2": "l2_leaf_reg",

    # ───── LDA / QDA ─────
    "shrink": "shrinkage",
    "reg": "reg_param",
    "lda_solver": "lda_solver_type",
    "lda_shrink": "lda_shrinkage_mode",

    # ───── SVC ─────
    "svc_gamma": "svc_gamma_mode",
    "svc_kernel": "svc_kernel_type"
}

model_keys = {
    "lr": "LogisticRegression",
    "xgb": "XGBoost",
    "lgbm": "LightGBM",
    "cat": "CatBoost",
    "mlp": "MLP",
    "svc": "SVC",
    "et": "ExtraTrees",
    "gb": "GradientBoosting",
    "hist": "HistGradientBoosting",
    "bag": "Bagging",
    "dt": "DecisionTree",
    "rf": "RandomForest",
    "ada": "AdaBoost",
    "lda": "LDA",
}

print("\n─────────────── Best Model Summary ───────────────\n")
print(f"Voting type: soft\n")

for key in model_keys:
    if study.best_trial.params.get(f"use_{key}"):
        print(f"Evaluation model: {model_keys[key]}")
        print(f"- weight: {study.best_trial.params.get(f'{key}_w', '-')}")

        for p in study.best_trial.params:
            if p.startswith(f"{key}_") and not p.endswith("_w"):
                short = p.replace(f"{key}_", "")
                name = param_name_mapping.get(short, short)
                val = study.best_trial.params[p]

                if isinstance(val, float):
                    print(f"- {name}: {val:.4f}")
                else:
                    print(f"- {name}: {val}")
        print()

# best_params 저장
with open(BEST_PARAMS_PATH, "w") as f:
    json.dump(study.best_trial.params, f, indent=2)

print(f"\n✅ saved to '{BEST_PARAMS_PATH}'")
