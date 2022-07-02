import logging
from flask import Flask, session, flash, render_template, url_for, request, redirect
from werkzeug.utils import secure_filename
import sqlite3 as sql
import hashlib
import socket
import socket
import json
import random
import time


end = 0                                                # inicializacao do username

def recv_msg(connection: socket):
    try:
        header = int.from_bytes(connection.recv(2), "big")          # descodificar os 2 bytes, big endian para o header
        message_encoded = connection.recv(header)                   # ler o numero de bytes a que o header corresponde
        message_decoded = message_encoded.decode("utf-8")           # descodificar a data
    except:
        return False

    if len(message_decoded) == 0:                               # se nao existir data entao faz return
        return False
    try:
        message_recv = json.loads(message_decoded)              # se nao conseguir fazer load do json entao raise CDProtoBadFormat, se sim entao guarda na variavel
    except:
        return False

    print("Recieved: {}".format(message_recv))
    return message_recv

users = []

app = Flask(__name__)

app.secret_key=b'\xb5\x95\x96\xeeS\xc1\xa9\xc1\xc4\xdcA!2\x0e\x10\xa0'
app.config['UPLOAD_FOLDER'] = "static/images"
app.config['TEMP_DIR'] = "/tmp"

with sql.connect('mydb') as con:
    cur = con.cursor()
    cur.execute("""CREATE TABLE if not exists User (
        username text primary key,
        password text,
        challenge text);""")
    cur.execute("""create table if not exists Project (
        id int primary key,
        name text);""")
    cur.execute("""create table if not exists ProjectUser (
        idProject int,
        username text,
        hours int,
        area text,
        primary key (idProject, username),
        foreign key (idProject) references Project (id),
        foreign key (username) references User (username))""")
    cur.close()

app.config["ALLOWED_EXTENSIONS"] = {'png', 'jpg', 'jpeg'}
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]

@app.route('/')
def index():
    try :
        if session['logged']:
            # logged in
            user = session["username"]
            if user:
                # user exists
                with sql.connect('mydb') as con:
                    cur = con.cursor()
                    cur.execute(f"SELECT * FROM User WHERE username = \'{user}\'")
                    result = cur.fetchall()
                    cur.close()
                    if result != []:
                        app.logger.debug(f"{result}")
                        return render_template('home.html', user=result)
    except KeyError as k:
        return render_template("index.html")
    return render_template("index.html")

@app.route('/logout')
def logout():
    session['logged'] = False
    session['username'] = None
    return redirect("/")

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':

        user = request.form["username"]
        user_pass = request.form["password"]
        user_pass_rep = request.form["repeat_password"]

        if user_pass != user_pass_rep:
            return render_template("index.html", erro = True)

        # print("Starting to make challenge")

        hashed = user # + password
        final = ""
        for i in range(32):
            hashed = hashlib.md5(hashed.encode("utf-8", errors='static')).hexdigest()
            # print(f"hashed: {hashed}")
            final += hashed[i]

        password = hashlib.md5(user_pass.encode("utf-8", errors='static')).hexdigest()
        try:
            with sql.connect('mydb') as con:
                cur = con.cursor()
                cur.execute("INSERT INTO User(username, password, challenge) VALUES(?,?,?)", (user, password, final))
                con.commit()
                cur.close()
        except Exception as e:
            print(e)
            return render_template("index.html", erro = True)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('', 6105))
        sock.setblocking(False)

        msg = {'command': 'register'}
        data = json.dumps(msg).encode('utf-8')
        header = len(data).to_bytes(2, "big")
        print("Sent: {}".format(msg))
        sock.sendall(header+data) 

        sock.close()

        return render_template("index.html", erro = False)

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        user = request.form["username"]
        result = []
        try:
            with sql.connect('mydb') as con:
                cur = con.cursor()
                cur.execute(f"SELECT * FROM User WHERE username = \'{user}\'")
                result = cur.fetchall()
                cur.close()
        except:
            return render_template("index.html", erro = True)

        if result == []:
            return render_template("index.html", erro = True)

        (user, password, challenge) = result[0]

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('', 6105))
        sock.setblocking(False)
        
        my_list = [0] * int(16/2) + [1] * int(16/2)
        print(f"\t\t\t\t{challenge+password}")
        random.seed(challenge+password)
        random.shuffle(my_list)
        print(my_list)

        msg = {'command': 'login', 'challenge': challenge, 'username': user}
        data = json.dumps(msg).encode('utf-8')
        header = len(data).to_bytes(2, "big")
        print("Sent: {}".format(msg))
        sock.sendall(header+data)   

        error = False 

        mensagem = recv_msg(sock)
        while mensagem == False or mensagem['command'] != "finished":
            mensagem = recv_msg(sock)
            if mensagem == False:
                continue

            # {command: authentication, game: 1}

            if mensagem['command'] == "authentication":
                if mensagem['game'] != my_list:
                    error = True
                    print("ERRO")

                hashed = challenge
                challenge = ""
                for i in range(32):
                    hashed = hashlib.md5(hashed.encode("utf-8", errors='static')).hexdigest()
                    # print(f"hashed: {hashed}") 
                    challenge += hashed[i]
 
                msg = {'command': 'login', 'challenge': challenge, 'username': user}
                data = json.dumps(msg).encode('utf-8')
                header = len(data).to_bytes(2, "big")
                # print("Sent: {}".format(msg))
                sock.sendall(header+data)

                my_list = [0] * int(16/2) + [1] * int(16/2)
                random.seed(challenge+password)
                random.shuffle(my_list)


        if error:
            msg = {'command': 'Error'}
            data = json.dumps(msg).encode('utf-8')
            header = len(data).to_bytes(2, "big") 
            print("Sent: {}".format(msg))
            sock.sendall(header+data)
            sock.close()
            return render_template("index.html")

        session['logged'] = True
        session['username'] = user
        session["project_id"] = 1

        msg = {'command': 'Succeed'}
        data = json.dumps(msg).encode('utf-8')
        header = len(data).to_bytes(2, "big")
        print("Sent: {}".format(msg))
        sock.sendall(header+data)
        sock.close()
        return redirect("/home")


    return render_template("index.html")

@app.route('/home')
def home():
    try :
        a = session['logged']
    except KeyError as k:
        return redirect("/")
    if session['logged']:
        # logged in
        user = session["username"]
        if user :
            # user exists
            with sql.connect('mydb') as con:
                cur = con.cursor()
                cur.execute(f"SELECT User.username,User.password FROM User INNER JOIN ProjectUser On User.username = ProjectUser.username")
                result = cur.fetchall()
                cur.close()
                if result != []:
                    return render_template('home.html', user=result)
    return render_template('home.html')

if __name__ == "__main__":
    #Setup the logger
    file_handler = logging.FileHandler('output_sec.log')
    handler = logging.StreamHandler()
    file_handler.setLevel(logging.DEBUG)
    handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
       '%(asctime)s %(levelname)s: %(message)s '
       '[in %(pathname)s:%(lineno)d]'
    ))
    handler.setFormatter(logging.Formatter(
       '%(asctime)s %(levelname)s: %(message)s '
       '[in %(pathname)s:%(lineno)d]'
    ))
    app.logger.addHandler(handler)
    app.logger.addHandler(file_handler)
    #app.logger.error('first test message...')
    app.run(debug = True, port=5000)
