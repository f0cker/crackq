"""Main Flask WSGI execution"""
from crackq import app

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
