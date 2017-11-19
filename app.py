from flask import Flask, render_template, request, redirect, url_for, flash,session,abort
from sasa import md5_encode

app = Flask(__name__)
app.config.from_object(__name__)
app.config.update(dict(
    SECRET_KEY = 'HURRDURRHAHAHAHAHAHAHAHAHAHAHAHAHA'
))

@app.route('/')
@app.route('/index',methods=['GET','POST'])
def home():
    if request.method=='POST':
        text = request.form['message']
        ciphertext = md5_encode(text)
        flash("encoded")
        session['ciphertext']=ciphertext
        return redirect(url_for('show_encrypted'))
    return render_template('index.html')

@app.route('/show_encrypted')
def show_encrypted():
    if not session.get('ciphertext'):
        abort(401)
    ciphertext = session.get('ciphertext')
    return render_template('show_encrypted.html',ciphertext=ciphertext)


if __name__ == "__main__":
    app.run(host='0.0.0.0')
