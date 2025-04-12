import os
import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# 1. 데이터 로딩
DATA_PATH = os.path.join("..", "csv", "2021_dataset.csv")
df = pd.read_csv(DATA_PATH)

# 2. X, y 분리 (마지막 열이 label이라고 가정)
X = df.iloc[:, :-1]
y = df.iloc[:, -1]

# 🔧 XGBoost는 label이 0과 1이어야 하므로 -1을 0으로 변환
y = y.replace(-1, 0)

# 3. 학습/테스트 분리
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. 모델 생성 및 학습
model = XGBClassifier(n_estimators=100, eval_metric='logloss', random_state=42)
model.fit(X_train, y_train)

# 5. 평가
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# 모델 저장
# import joblib
# joblib.dump(model, 'xgb_model.pkl')
