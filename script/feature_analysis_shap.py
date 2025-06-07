if __name__ == '__main__':
    import pandas as pd
    import numpy as np
    import shap
    import joblib
    import matplotlib.pyplot as plt
    import seaborn as sns
    from tqdm import tqdm

    from sklearn.pipeline import Pipeline
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import StandardScaler

    # -----------------------------
    # 1. 데이터 로드 및 전처리
    # -----------------------------
    df = pd.read_csv("2025_URL_DATASET.csv")
    X = df.drop(columns=["url", "label"], errors="ignore")
    y = df["label"]
    feature_names = X.columns.tolist()

    preprocessor = Pipeline([
        ("imputer", SimpleImputer(strategy="mean")),
        ("scaler", StandardScaler())
    ])
    X_scaled = preprocessor.fit_transform(X)

    # -----------------------------
    # 2. 모델 불러오기
    # -----------------------------
    voting_model = joblib.load("vc_model.pkl")
    named_models = dict(voting_model.named_estimators_)
    model_weights_dict = dict(zip(named_models.keys(), voting_model.weights or [1]*len(named_models)))

    selected_models = ['xgb', 'cat', 'mlp', 'gb', 'bag', 'dt']
    background = shap.sample(X_scaled, 10, random_state=42)

    # -----------------------------
    # 3. SHAP 계산 함수
    # -----------------------------
    def compute_shap(model_name, model):
        model_type = type(model).__name__
        print(f"\n🔍 {model_name} ({model_type}) SHAP 계산 시작")

        if model_type in [
            "XGBClassifier", "GradientBoostingClassifier",
            "CatBoostClassifier", "DecisionTreeClassifier"
        ]:
            explainer = shap.TreeExplainer(model)
        elif model_type in ["MLPClassifier", "BaggingClassifier"]:
            explainer = shap.KernelExplainer(model.predict_proba, background)
        else:
            return None

        shap_values = []

        for x in tqdm(X_scaled, desc=f"{model_name} SHAP", leave=True):
            x_reshaped = x.reshape(1, -1)
            shap_val = explainer(x_reshaped)

            if isinstance(shap_val, list):
                values = shap_val[1].values
            else:
                values = shap_val.values

            if isinstance(values, list):
                values = np.array(values)

            if values.ndim == 1:
                pass
            elif values.ndim == 2:
                if values.shape[0] == len(feature_names):
                    values = values.mean(axis=1)
                elif values.shape[1] == len(feature_names):
                    values = values.mean(axis=0)
                else:
                    return None
            elif values.ndim == 3:
                values = values[0].mean(axis=-1)
            else:
                return None

            shap_values.append(np.abs(values))

        shap_array = np.vstack(shap_values)
        feature_importance = np.mean(shap_array, axis=0).flatten()

        if len(feature_importance) != len(feature_names):
            return None

        df = pd.DataFrame({
            "Feature": feature_names,
            f"{model_name}_shap_importance": feature_importance
        })

        print(f"✅ {model_name} SHAP 완료")
        return model_name, df

    # -----------------------------
    # 4. SHAP 계산 전체 수행
    # -----------------------------
    results = []
    for name in selected_models:
        if name in named_models:
            result = compute_shap(name, named_models[name])
            if result:
                results.append(result)

    # -----------------------------
    # 5. 가중치 반영 평균 SHAP 계산
    # -----------------------------
    print("✅ 가중치 반영 중...")

    model_importance = {name: df for name, df in results}
    final_df = list(model_importance.values())[0]
    for df in list(model_importance.values())[1:]:
        final_df = final_df.merge(df, on="Feature", how="outer")
    final_df.fillna(0, inplace=True)

    importance_cols = [col for col in final_df.columns if col.endswith("_shap_importance")]
    weights_array = np.array([model_weights_dict[name] for name in model_importance.keys()])
    final_df["Weight"] = final_df[importance_cols].values.dot(weights_array) / weights_array.sum()
    final_df = final_df.sort_values(by="Weight", ascending=False)

    # -----------------------------
    # 6. 저장 및 시각화
    # -----------------------------
    final_df.to_csv("shap_weighted_feature_importance.csv", index=False)

    plt.figure(figsize=(12, 8))
    sns.barplot(data=final_df.head(20), x="Weight", y="Feature", palette="viridis")
    plt.title("Top 20 SHAP Features Importance")
    plt.xlabel("Weight")
    plt.ylabel("Features")
    plt.tight_layout()
    plt.savefig("shap_weighted_feature_importance.png")
    plt.close()

    print("✅ SHAP 분석 완료!")
    print(" - shap_weighted_feature_importance.csv")
    print(" - shap_weighted_feature_importance.png")
