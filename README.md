# project-2---authentication-equipa_27
- Filipe Gonçalves  98083
- Pedro Lopes       97827
- João Borges	    98155
- Gonçalo Machado   98359

# Running
To run the app_auth: `app_auth]$ python3 app.py`
The web application will run in `http://127.0.0.1:5000/` \\trocar port para o certo

To run the UAP: `uap]$ python3 uap.py`
After, a master password (that will be used to encode everything in the database) needs to be inserted.
The UAP will run in `http://127.0.0.1:ver o port correto/`

# Loggers
We have two loggers in this folder, for tests and everything else we thought was better to look at in a logger view.

# Database
Running the web application in the folder will create a database in this folder called `database.db `  \\falta ver a base de dados da UAP

# Project description

This project has the main purpose of implementing an authentication protocol in our application. The protocol that we used is an enhanced challenge-response authentication protocol (E-CHAP). The process of a user registering and login in while using our protocol consists of the following steps:

### Registering

For the protocol to work both the UAP and the application need to share a __secret__. This __secret__ will be the password that the user uses to register in both the UAP and the application. To do this, the user needs to:

- Register in our application using a username and a password. These will be saved in the application database ?after being hashed?
- Register his account in the UAP. For this he needs to put the DNS name of the website and the username-password pair that was used in that website. These will be saved in the UAP database after being encoded with the master password.

### Login in

The login process should be as follows:

- The user accesses the login page of the application
- The user inserts his username and clicks the login button
- The app will send the challenge, the username and the dns name to the UAP
- The UAP will ?combine the challenge with the password and hash it? and come up with a response and send it to the app. The app will receive the response, compare it with its own and send a new challenge. This will be repeated for N times. 
- After N times, if the app validates every response from the UAP, the user is validated and redirected to the app home page, already logged in

### The challenge

The username will be hashed 32 times in a for loop. In each iteration of the loop it will pick the correponding byte of the number of iteration, which means that in the first iteration, the username will be hashed and the first bit of the hashed username will be added to the final challenge string, in the second iteration the username will be hashed again, which means the username is hashed at this moment twice, and the second bit is picked and added to the end of the challenge string, and so forth.

### The protocol

The protocol consists on a naval battle 4x4 gameboard, represented with a bi-dimensional arraylist (which is actually an normal array, but for the sake of explanation, let's imagine it is a bi dimensional :) ). The "challenge" reffered in the app is the seed of the game which will later generate a board with the locations of each ship (1 represents a ship, and 0 water). The seed is sent to the uap and both the uap and the app will generate the board by adding the seed and the password, after that a board (bi-dimensional array) with half 0's and half 1's is created; the random.shuffle will shuffle the positions in the list according to the seed+password given.
This process will be done lots of times, the uap sends the result of the generated board and the app will compare his board with the board received, the app will only send an acknowledgement message and after that the uap and the app will calculate a new board with an added index; the app can't miss a single game, which means that the board from the uap has to be always the same as the one from the app. The app will only say if the uap got it right in every board at the end, so that if the uap misses a board in the middle of the process (the uap board is different from the app board), the uap won't know when he got it wrong.