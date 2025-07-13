import os
import logging
import subprocess
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from threat_fetcher import fetch_threat_iocs
from llm_service import llm_service

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")
CORS(app)

@app.route('/')
def index():
    """Main page for threat intelligence dashboard"""
    return render_template('index.html')

@app.route('/api/threats')
def get_threats():
    """API endpoint to get threat intelligence data"""
    try:
        logger.info("Fetching threat intelligence data...")
        threats = fetch_threat_iocs()
        logger.info(f"Successfully fetched {len(threats)} threat entries")
        return jsonify({
            'success': True,
            'data': threats,
            'count': len(threats)
        })
    except Exception as e:
        logger.error(f"Error fetching threats: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'data': []
        }), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'threat-intel-aggregator'
    })

@app.route('/admin')
def admin_dashboard():
    """Admin dashboard for LLM configuration"""
    return render_template('admin.html')

@app.route('/api/llm-status')
def llm_status():
    """Check status of available LLM backends"""
    llm_service._check_available_backends()
    return jsonify({
        'success': True,
        'ollama': 'ollama' in llm_service.available_backends,
        'openai': 'openai' in llm_service.available_backends,
        'backends': llm_service.available_backends
    })

@app.route('/api/config-openai', methods=['POST'])
def config_openai():
    """Configure OpenAI API key"""
    try:
        data = request.get_json()
        api_key = data.get('api_key')
        
        if not api_key:
            return jsonify({'success': False, 'error': 'API key is required'}), 400
        
        # Set environment variable
        os.environ['OPENAI_API_KEY'] = api_key
        llm_service.openai_api_key = api_key
        llm_service._check_available_backends()
        
        return jsonify({'success': True, 'message': 'OpenAI API key configured successfully'})
    except Exception as e:
        logger.error(f"Error configuring OpenAI: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/test-summarize', methods=['POST'])
def test_summarize():
    """Test threat summarization"""
    try:
        data = request.get_json()
        text = data.get('text')
        
        if not text:
            return jsonify({'success': False, 'error': 'Text is required'}), 400
        
        summary = llm_service.summarize_threat(text)
        
        # Determine which backend was used
        backend = 'enhanced-fallback'
        if 'ollama' in llm_service.available_backends:
            backend = 'ollama'
        elif 'openai' in llm_service.available_backends:
            backend = 'openai'
        
        return jsonify({
            'success': True,
            'summary': summary,
            'backend': backend
        })
    except Exception as e:
        logger.error(f"Error testing summarization: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting Threat Intelligence Feed Aggregator...")
    app.run(host='0.0.0.0', port=5000, debug=True)