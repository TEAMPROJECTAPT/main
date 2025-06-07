if __name__ == '__main__':
    import pandas as pd
    import numpy as np
    import shap
    import joblib
    import matplotlib.pyplot as plt
    import seaborn as sns
    from tqdm import tqdm
    from joblib import Parallel, delayed
    import multiprocessing
    from sklearn.pipeline import Pipeline
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import RandomForestClassifier
    from xgboost import XGBClassifier
    from sklearn.linear_model import LogisticRegression

    # ----------------------------
    # 1. 데이터 로드 및 전처리
    # ----------------------------
    df = pd.read_csv("2025_URL_DATASET.csv")  #로컬 사용 시 경로 수정
    X = df.drop(columns=["url", "label"], errors="ignore")
    y = df["label"]
    feature_names = X.columns.tolist()

    preprocessor = Pipeline([
        ("imputer", SimpleImputer(strategy="mean")),
        ("scaler", StandardScaler())
    ])
    X_scaled = np.array(preprocessor.fit_transform(X))

    # ----------------------------
    # 2. 모델 불러오기
    # ----------------------------
    voting_model = joblib.load("vc_old_model.pkl")    #로컬 사용 시 경로 수정
    model_weights = voting_model.weights or [1] * len(voting_model.estimators)
    named_models = dict(voting_model.named_estimators_)

    # ----------------------------
    # 3. 모델 분리 (병렬 vs 직렬)                   #병렬: TreeExplainer, LinearExplainer /   직렬: KernelExplainer
    # ----------------------------
    parallel_models = {}
    serial_models = {}

    for name, model in named_models.items():
        if isinstance(model, (RandomForestClassifier, XGBClassifier, LogisticRegression)):
            parallel_models[name] = model
        else:
            serial_models[name] = model

    background = np.array(shap.sample(X_scaled, 50, random_state=42))  # memmap 방지

    # ----------------------------
    # 4. SHAP 계산 함수 (병렬 대상)
    # ----------------------------
    def compute_shap_for_model(model_name, model, position):
        print(f"🔍 {model_name} SHAP 계산 시작")

        if isinstance(model, (RandomForestClassifier, XGBClassifier)):
            explainer = shap.TreeExplainer(model)
        elif isinstance(model, LogisticRegression):
            explainer = shap.LinearExplainer(model, background)
        else:
            raise ValueError(f"{model_name}: 병렬 대상 아님")

        shap_values = []
        for x in tqdm(X_scaled, desc=f"{model_name} SHAP", position=position, leave=True, dynamic_ncols=True):
            x_reshaped = x.reshape(1, -1)
            shap_val = explainer(x_reshaped)
            values = shap_val[1].values if isinstance(shap_val, list) else shap_val.values
            shap_values.append(np.abs(values))

        shap_array = np.vstack(shap_values)
        feature_importance = np.mean(shap_array, axis=0).flatten()

        min_len = min(len(feature_names), len(feature_importance))
        df = pd.DataFrame({
            "Feature": feature_names[:min_len],
            f"{model_name}_SHAP_중요도": feature_importance[:min_len]
        })
        return model_name, df

    # ----------------------------
    # 5. 병렬 SHAP 실행
    # ----------------------------
    n_jobs = int(multiprocessing.cpu_count() * 0.7)     #본인 컴퓨터 사양이 괜찮다면 n_jobs=-1 설정(cpu 100%)
    print(f"⚙️ 병렬 처리에 사용할 코어 수: {n_jobs} / {multiprocessing.cpu_count()}")

    results = Parallel(n_jobs=n_jobs)(
        delayed(compute_shap_for_model)(name, model, position=i+1)
        for i, (name, model) in enumerate(parallel_models.items())
    )

    # ----------------------------
    # 6. 직렬 SHAP 실행 (KernelExplainer)
    # ----------------------------
    for i, (model_name, model) in enumerate(serial_models.items()):
        print(f"🔍 {model_name} (KernelExplainer) SHAP 직렬 계산 시작...")

        explainer = shap.KernelExplainer(model.predict_proba, background)
        shap_values = []

        disable_tqdm = X_scaled.shape[0] == 1
        for x in tqdm(X_scaled, desc=f"{model_name} SHAP", position=10+i, leave=True, dynamic_ncols=True, disable=disable_tqdm):
            x_reshaped = x.reshape(1, -1)
            shap_val = explainer(x_reshaped)
            values = shap_val[1].values if isinstance(shap_val, list) else shap_val.values
            shap_values.append(np.abs(values))

        shap_array = np.vstack(shap_values)
        feature_importance = np.mean(shap_array, axis=0).flatten()

        min_len = min(len(feature_names), len(feature_importance))
        df = pd.DataFrame({
            "Feature": feature_names[:min_len],
            f"{model_name}_SHAP_중요도": feature_importance[:min_len]
        })
        results.append((model_name, df))

    # ----------------------------
    # 7. Voting 가중치 반영
    # ----------------------------
    print("✅ 모델 가중치 반영 중...")

    model_importance = {name: df for name, df in results}
    final_df = list(model_importance.values())[0]
    for df in list(model_importance.values())[1:]:
        final_df = final_df.merge(df, on="Feature", how="outer")
    final_df.fillna(0, inplace=True)

    importance_cols = [col for col in final_df.columns if col.endswith("_SHAP_중요도")]
    weights_array = np.array(model_weights)
    final_df["SHAP_가중_중요도"] = final_df[importance_cols].values.dot(weights_array) / weights_array.sum()
    final_df = final_df.sort_values(by="SHAP_가중_중요도", ascending=False)

    # ----------------------------
    # 8. 저장 및 시각화
    # ----------------------------
    final_df.to_csv("shap_weighted_feature_importance.csv", index=False)

    plt.figure(figsize=(12, 8))
    sns.barplot(data=final_df.head(20), x="SHAP_가중_중요도", y="Feature", palette="viridis")
    plt.title("Top 20 SHAP Features importance")
    plt.tight_layout()
    plt.savefig("shap_weighted_feature_importance.png")
    plt.close()

    print("✅ SHAP 분석 완료!")
    print(" - shap_weighted_feature_importance.csv")
    print(" - shap_weighted_feature_importance.png")
