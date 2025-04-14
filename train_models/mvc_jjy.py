from sklearn.ensemble import VotingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score
import pandas as pd

# 데이터 로드
df = pd.read_csv("2021_dataset.csv")
X = df.drop(columns=["Index", "class"], errors="ignore")
y = df["class"]

# 전처리: 결측치 처리 + 표준화
preprocessor = Pipeline([
    ("imputer", SimpleImputer(strategy="mean")),
    ("scaler", StandardScaler())
])
X_scaled = preprocessor.fit_transform(X)

# 훈련/테스트 분할
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# 모델 정의
rf = RandomForestClassifier(n_estimators=400, max_depth=18, class_weight="balanced_subsample", random_state=42)
mlp = MLPClassifier(hidden_layer_sizes=(150, 100, 50), alpha=0.0003, max_iter=600, early_stopping=True, random_state=42)
xgb = XGBClassifier(n_estimators=200, max_depth=10, learning_rate=0.05, subsample=0.9, colsample_bytree=0.8,
                    use_label_encoder=False, eval_metric="logloss", random_state=42)
lr = LogisticRegression(max_iter=500, C=0.3, solver="liblinear", class_weight="balanced", random_state=42)

# VotingClassifier (Soft Voting)
voting_clf = VotingClassifier(
    estimators=[("rf", rf), ("mlp", mlp), ("xgb", xgb), ("lr", lr)],
    voting="soft",
    weights=[4, 3, 5, 1]
)

# 학습
voting_clf.fit(X_train, y_train)

# 예측 및 평가
y_pred = voting_clf.predict(X_test)

# 성능 출력
print("✅ 최종 VotingClassifier (Soft Voting, SVC 제외) 성능\n")
print(classification_report(y_test, y_pred))  # precision, recall, f1-score 출력
print(f"정확도: {accuracy_score(y_test, y_pred):.4f}")
