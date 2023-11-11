import flask as f

app = f.Flask(__name__)

@app.route('/')
def main():

    return f.render_template('index.html')



app.run(host='25.47.197.186', port=80, debug=True)