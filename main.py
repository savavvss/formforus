import flask as f

app = f.Flask(__name__)

@app.route('/')
def main():

    return f.render_template('index.html')



app.run(host='localhost', port=80, debug=True)