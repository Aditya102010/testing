from flask import Flask, redirect, url_for, request,render_template,send_file, session
from flask_sqlalchemy import SQLAlchemy

import datetime
import sqlite3
import base64
import binascii
import os
import bcrypt

#creating an instance of Flask app
app = Flask(__name__,template_folder='templates')

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Ciphers.db'
app.config['SQLALCHEMY_BINDS'] = { 'user': 'sqlite:///User.db',
'role': 'sqlite:///Role.db',
'log' : 'sqlite:///Logs.db'

}
    
db = SQLAlchemy(app)

app.app_context().push()


class User(db.Model):
    """ Model for saving new user details
    The password gets saved in encrypted format (using bcrypt)."""
    __bind_key__ = 'user'
    id = db.Column(db.Integer,primary_key = True)
    name = db.Column(db.VARCHAR(50),nullable = False)
    username = db.Column(db.VARCHAR(50), nullable = False)
    password = db.Column(db.VARCHAR(50), nullable = False)
    

class Role(db.Model):
    """ creating the role for each new user added """
    __bind_key__  = 'role'
    id = db.Column(db.Integer,primary_key= True)
    username = db.Column(db.VARCHAR(50), nullable = False)
    role = db.Column(db.VARCHAR(50), nullable = False)


class ciphers(db.Model):
    """Saving all the ciphertexts """
    id = db.Column(db.Integer,primary_key = True)
    cipher = db.Column(db.VARCHAR(50),nullable = False)
    date = db.Column(db.VARCHAR(50), nullable = False)

class Logs(db.Model):
    "Logging each entry made by any certain user on the server side"
    __bind_key__ = 'log'
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.VARCHAR(50), nullable = False)
    cipher = db.Column(db.VARCHAR(50), nullable = False)
    date = db.Column(db.VARCHAR(50), nullable = False) 


@app.route('/')
def first_page():
    """ Renders the homepage """
    return render_template('login_form.html') 


@app.route('/towards_homepage', methods= ['POST', 'GET'])
def towards_homepage():
    """ Renders the homepage.html file under templates (Not in use in current version of project)"""
    return render_template('homepage.html')

@app.route('/registration_form')
def registration_form():
    """This route renders registration_form"""
    return render_template('registration_form.html')

global var
var = 0
@app.route('/register_new_user', methods = ['POST', 'GET'])
def register_new_user():
    """Route for handling registration of a user
    The user details are simultaeneously pushed into two databses i.e. User db and Role db"""
    global var  
    
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        access = request.form['access']
        if password =='' or username == '' or name =='' :
            return render_template('registration_form.html', info = 'Please fill all the fields')
        
        # here we put the new user data into database
        p = User(name = name, username = username, password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(14)))
        db.session.add(p)
        var = Role.query.count()
        q = Role(id = var, username = username, role = access)
        
        db.session.add(q)
        db.session.commit()
        return render_template('registration_form.html',info = 'You have sucessfully registered!')
    else :
        return "new user registration was failed"

def encrypt_plaintext(text):
    """Encrypts any plaintext value into a corresponding base64 value"""
    modified_plaintext = text.encode('utf-8')
    encoded_text = base64.b64encode(modified_plaintext)	
    return encoded_text

def decrypt_plaintext(text):
    """Decrypts any base64 encoded text into a corresponding plaintext """
    sample_string_bytes = base64.b64decode(text)
    sample_string = sample_string_bytes.decode("ascii")
    return sample_string	

@app.route('/delete/<string:id>')
def erase(id):
    """Deletion of a specific cipher entity from database through unique ID"""
    data = ciphers.query.get(id)
    db.session.delete(data)
    db.session.commit()
    return redirect('/')


@app.route('/delete_user/<string:id>')
def erase_user(id):
    """Deletion of a specific User database entity through the unique ID"""
    data = User.query.get(id)
    db.session.delete(data)
    db.session.commit()
    return redirect('/displayall_user')

@app.route('/delete_role/<string:id>')
def erase_role(id):
    """Deletion of a specific entity from Role database through the unique ID"""
    data = Role.query.get(id)
    db.session.delete(data)
    db.session.commit()
    return redirect('/displayall_roles')

@app.route('/delete_log/<string:id>')
def erase_log(id):
    """Deletion of a specific entity from Log database through the unique ID"""
    data = Logs.query.get(id)
    db.session.delete(data)
    db.session.commit()
    return redirect('/displayall_log')



@app.route('/displayall',methods = ['POST','GET'])
def displayall():
    """Querying all the entries of Cipher Database at once and presenting them onto a html template"""
    new_log = Logs.query.all()
    return render_template('index.html', log = new_log)

@app.route('/displayall_log', methods = ['POST', 'GET'])
def displayall_log():
    """ Displays the Database containing Every entry made by client, saved as a log on server side """
    log = Logs.query.all()
    return render_template('index_log.html', log = log)

@app.route('/displayall_user',methods = ['POST','GET'])
def displayall_user():
    """Querying all the entries of Cipher Database at once and presenting them onto a html template"""
    user = User.query.all()
    return render_template('index_user.html', user = user )
    
@app.route('/displayall_roles', methods = ['POST','GET'])
def displayall_roles():
    """Querying all the entries of Cipher Database at once and presenting them onto a html template"""
    role = Role.query.all()
    return render_template('index_role.html', role = role )

@app.route('/to_client_page')
def to_client_page():
    """Redirects the user to client page after login"""
    return render_template('client_page.html', info = 'You are logged in!')

@app.route('/to_manager_page')   
def to_manager_page():
    """Redirects the user to client page after login"""
    return render_template('manager_page.html', info = 'You are logged in!')

@app.route('/login', methods=['POST', 'GET'])
def login():
    """Handles the user login in the system after one enters there credentials
       Types of credential checks taking place :
       1. whether user has left the password or username field empty
       2. whether the user has entered incorrect username or password
       3. if the corresponding password for a username entered is correct (according to database)

       At the time of login another check is made w.r.t. the role of user"""
       
    if request.method == 'POST':
        username = request.form['username']
        raw_username = non_encrypted_username = username

        password = request.form['password']     
        raw_password = password
      
        db.session.query(User.id).filter_by()
        matching_users = db.session.query(Role.role).filter_by(username = non_encrypted_username)
        matching_password = User.query.filter_by(username = username)
        val = ""
        session['login'] = raw_username
        pass_to_check = ""
        for user in matching_users :
            val = user.role
      
        pass_to_check = ""
        for value in matching_password:
            pass_to_check  = value.password
           
        if raw_username == '' or raw_password == '':
            return render_template('login_form.html', info = 'Username and Password cannot be empty')

        if  bcrypt.checkpw(password.encode('utf-8'), pass_to_check):
            if val == "client":
                return redirect('/to_client_page')
            elif val == "manager":
                return redirect('/to_manager_page')

        else :
            return render_template('form.html', info = 'Invalid credentials!')

    else:
        return render_template('form.html')
       


@app.route('/download', methods = ['GET','POST'])
def download_file():
    """A file is created with base64 encoded value of plaintext (see below in this function).
    The webpage prompts User to provide a desired filename and thereafter the encrypted file
    gets saved onto the client desktop """

    if request.method == 'POST':
    
        SystemNumber =  request.form['SystemNumber']
        License = 'license' in request.form
    
        filename = request.form['filename']
        if SystemNumber == '': 
            return render_template('client_page.html', info = 'SystemNumber cannot be empty!')

        if filename == '':
            return render_template('client_page.html', info = 'Filename cannot be empty!')
       
        if License == True:
            License_pass_value = '1'
        else : 
            License_pass_value = '0'
        
        plaintext = "NonStop ESS License \nVersion : 1 \n SystemNumber : "+SystemNumber+"\nLicense :"+License_pass_value
        modified_plaintext = plaintext.encode('utf-8')
        encoded_text = base64.b64encode(modified_plaintext)	
        entry = Logs(username = session['login'], cipher = encoded_text,date = datetime.datetime.now())
        db.session.add(entry)
        db.session.commit()
        with open(filename,'wb') as binary_file:
            binary_file.write(encoded_text) 

        p = "base64_encoded_file.txt"
        return send_file(filename,as_attachment = True)
    else:
        return redirect('/')


@app.route('/decode_file', methods = ['POST','GET'])
def decode_file():
    """ Takes input in form of a base64 encoded file and then decrypts that file"""
    if request.method == 'POST':
        
        text_to_be_encoded = request.form['Choose File']
        if text_to_be_encoded == "":
            return render_template('manager_page.html', info = 'Please Select a File')
        file1 = open(text_to_be_encoded, "r+")  
        

        with open(text_to_be_encoded,'r') as file:
            to_print = file.read()
        base64_bytes = to_print.encode("ascii")
        
    
        sample_string_bytes = base64.b64decode(base64_bytes)
        sample_string = sample_string_bytes.decode("ascii")
        return render_template('manager_page.html', info = sample_string)
    return redirect('/decode_file')


if __name__ == '__main__':
    app.run(debug=True,port = 5000)
