import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.neural_network import MLPClassifier

# 1. 데이터 로딩
DATA_PATH = os.path.join("..", "csv", "2021_dataset.csv")
df = pd.read_csv(DATA_PATH)

# 2. X, y 분리
X = df.iloc[:, :-1]
y = df.iloc[:, -1]
y = y.replace(-1, 0)  # 0과 1로 변환

# 3. 학습/테스트 분리
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. 개별 모델 정의
DT = DecisionTreeClassifier(random_state=42)
RF = RandomForestClassifier(n_estimators=100, random_state=42)
ANN = MLPClassifier(hidden_layer_sizes=(50,), max_iter=500, random_state=42)

# 5. Max Vote Classifier (VotingClassifier)
MVC = VotingClassifier(estimators=[
    ('dt', DT),
    ('rf', RF),
    ('ann', ANN)
], voting='soft')

# 6. 모델 리스트
models = {
    'DT': DT,
    'RF': RF,
    'ANN': ANN,
    'MVC (DT+RF+ANN)': MVC
}

# 7. 학습 및 평가 
for name, model in models.items():
    print(f"\n🔎 모델: {name}")
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    print(f"✅ Accuracy: {accuracy_score(y_test, y_pred):.4f}")     #DT, RF, ANN, (DT,RF,ANN)
    print("📊 Classification Report:")
    print(classification_report(y_test, y_pred))

# 모델 저장
#import joblib  
#joblib.dump(model, 'mvc_model.pkl')