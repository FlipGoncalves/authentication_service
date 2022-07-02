import logging
import time
import random
import selectors
import socket
import json
import hashlib
import random
import sqlite3 as sql
import os
from common import encPass as eP
import hashlib
import sys

logging.basicConfig(filename="server.log", level=logging.DEBUG)

with sql.connect('mydb') as con:
    cur = con.cursor()
    cur.execute("""CREATE TABLE if not exists user_pass_pair (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username text NOT NULL,
        password text NOT NULL,
        salt text NOT NULL,
        server_name text NOT NULL
        )""")
    cur.close()


class Server:
    connecs = {}                                            

    secret_key=b'\xb5\x95\x96\xeeS\xc1\xa9\xc1\xc4\xdcA!2\x0e\x10\xa0'
    config = {}
    config['UPLOAD_FOLDER'] = "static/images"
    config['TEMP_DIR'] = "/tmp"
    config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
    config['PASSWORD_FILE'] = './password'
    config['SALT_FILE'] = './salt'

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sel = selectors.DefaultSelector()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', 6105))
        self.sock.listen(100)
        self.sel.register(self.sock, selectors.EVENT_READ, self.accept)
        self._pass = ""
        self.end = 0

        password_to_compare = None
        if os.path.isfile(self.config["PASSWORD_FILE"]):
            password_to_compare = input("Introduza a sua passe: ")
        else:
            password_to_save = input("Introduza uma nova passe: ")
            salt = os.urandom(16)
            # TODO add salt
            password_to_save_encoded = password_to_save.encode("utf-8", errors="static")
            password_to_save_encoded += salt
            if password_to_save != "":
                with open(self.config["PASSWORD_FILE"], "w") as f:
                    f.write(hashlib.md5(password_to_save_encoded).hexdigest())
                with open(self.config["SALT_FILE"], "wb") as f:
                    f.write(salt)

                self.config["PRIVATE_KEY"] = password_to_save  # hashed
            else:
                sys.exit(-1)

        if password_to_compare:
            password_saved = None
            with open(self.config["PASSWORD_FILE"], "r") as f:
                password_saved = f.readline()
            with open(self.config["SALT_FILE"], "rb") as f:
                salt = f.readline()

            hashed_pass = hashlib.md5(
                password_to_compare.encode("utf-8", errors="static") + salt
            ).hexdigest()
            if hashed_pass != password_saved:
                print("restart app and try again!")
                sys.exit(-1)
            else:
                self.config["PRIVATE_KEY"] = password_to_compare

        print("Starting server...")
        self.index = 0

    def accept(self, sock, mask):
        conn, addr = sock.accept()
        # conn.setblocking(False)
        self.connecs[conn] = []                                         # inicializacao da key correspondente à socket no dicionario
        # print("connected: {}".format(conn))
        self.sel.register(conn, selectors.EVENT_READ, self.read)

    def read(self, conn, mask):
        data_message = self.recv_msg(conn)                                   # receber a Message do client decoded
        try:
            if not data_message:
                print('-----Closing Connection to: {}-----'.format(self.connecs[conn]))
                self.sel.unregister(conn)
                self.connecs.pop(conn)
                conn.close()
                self.send_msg(conn, {'command': 'error', 'type': 'not data_message -> read -> Server'})
                return
        except:
            return
        print("Received: %s", data_message)

    def loop(self):
        while True:
            if self.end == 1:
                self.end = 0
                break
            events = self.sel.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)

    def send_msg(self, connection: socket, msg):
        data = json.dumps(msg).encode('utf-8')
        header = len(data).to_bytes(2, "big")
        print("Sent: {}".format(msg))
        connection.sendall(header+data)

    def recv_msg(self, connection: socket):
        header = int.from_bytes(connection.recv(2), "big")
        message_encoded = connection.recv(header)
        message_decoded = message_encoded.decode("utf-8")

        if len(message_decoded) == 0:
            return False
        try:
            message_recv = json.loads(message_decoded)                      # se nao conseguir fazer load do json entao envia mensagem de erro
        except:
            self.send_msg(connection, {'command': 'error', 'type': 'json_loads -> recv_msg -> Server'})
            return
        print("Received: {}".format(message_recv))

        if message_recv["command"] == "login":
            if self.index >= 160:
                message = {"command": "finished"}
                self.send_msg(connection, message)
                self.index = 0
            else:

                with sql.connect('mydb') as con:
                    cur = con.cursor()
                    user = message_recv["username"]
                    cur.execute(f"SELECT * FROM user_pass_pair WHERE username = \'{user}\'")
                    result = cur.fetchall()
                    print(result)
                    if result == []:
                        print("Not registered in UAP\nExiting...")
                        return
                    cur.close()

                (id, user, password, salt, DNS_name) = result[0]
                _pass = s.config["PRIVATE_KEY"]
                password = eP.decrypt(password, _pass)

                self.index += 1
                my_list = [0] * int(16/2) + [1] * int(16/2)
                password = hashlib.md5(password.decode().encode("utf-8", errors='static')).hexdigest()
                random.seed(message_recv["challenge"]+password)
                random.shuffle(my_list)

                message = {"command": "authentication", "game": my_list}
                self.send_msg(connection, message)

        if message_recv["command"] == "Succeed":
            print("POG")
            return

        if message_recv["command"] == "Error":
            print("FUCK")
            return

        if  message_recv["command"] == "register":
            self.end = 1
        return message_recv

#s = Server()

if __name__ == "__main__":
    s = Server()
    print("Menu:\n1- Inserir utilizador(es)\n2- Correr Server\n")
    option = input()
    while option != "quit":
        if option == "2":
            s.loop()
        if option == "1":
            while option == "1" or option == "Y":
                username = input("Username: ")
                password = input("Password: ")
                DNS_Name = input("DNS Name: ")
                option = input("Quer continuar a inserir ? (Y/N) ")
            
                salt = os.urandom(16)
                _pass = s.config["PRIVATE_KEY"]
                password=eP.encrypt(password.encode(), _pass, salt)

                try:
                    with sql.connect('mydb') as con:
                        cur = con.cursor()
                        cur.execute("INSERT INTO user_pass_pair(username, password, salt, server_name) VALUES(?,?,?,?)", (username, password, salt, DNS_Name))
                        con.commit()
                        cur.close()
                except Exception as e:
                    print(e)
        
        print("Menu:\n1- Inserir utilizador(es)\n2- Correr Server\n")
        option = input()
