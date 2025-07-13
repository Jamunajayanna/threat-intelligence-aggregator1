import os
from app import app

if __name__ == '__main__':
    # Get configuration from environment variables or use defaults
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    print(f"🚀 Starting Threat Intelligence Aggregator...")
    print(f"🌐 Server: http://{host}:{port}")
    print(f"📊 Dashboard: http://localhost:{port}")
    print(f"⚙️  Admin Panel: http://localhost:{port}/admin")
    print(f"📡 API: http://localhost:{port}/api/threats")
    print(f"🔧 Debug Mode: {debug}")
    print(f"📝 Press Ctrl+C to stop")
    print("-" * 50)
    
    app.run(host=host, port=port, debug=debug)