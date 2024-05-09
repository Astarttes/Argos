from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return "servidor en funcion."

def start_server():
    app.run(debug=True, use_reloader=False)

if __name__ == "__main__":
    start_server()
