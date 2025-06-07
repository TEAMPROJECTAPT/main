from flask import Flask, request, jsonify
from phishing_detector import predict_url_phishing



app = Flask(__name__)

@app.route('/receive_url', methods=['POST'])
def receive_url():
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL이 없습니다.'}), 400

    try:
        print(f"📥 받은 URL: {url}")
        result = predict_url_phishing(url)

        print(f"✅ 예측 결과 → {result}")
        
        return jsonify({
            'message': 'URL 수신 및 분석 완료',
            'url': url,
            'result': result
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': '예측 중 오류 발생',
            'details': str(e)
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
