from flask import Flask, redirect, url_for, request,render_template,send_file
from flask_sqlalchemy import SQLAlchemy
#from flask_migrate import Migrate, migrate
 

import sqlite3
import base64
import binascii,os
import bcrypt



app = Flask(__name__,template_folder='templates')


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Ciphers.db'
app.config['SQLALCHEMY_BINDS'] = { 'user': 'sqlite:///User.db',
'role': 'sqlite:///Role.db'

}
    
db = SQLAlchemy(app)

# Settings for migrations
#migrate = Migrate(app, db)

app.app_context().push()


class User(db.Model):
    # Model for saving new user details
    # This shall be saved into database in encrypted format too.
    id = db.Column(db.Integer,primary_key = True)
    name = db.Column(db.VARCHAR(50),nullable = False)
    username = db.Column(db.VARCHAR(50), nullable = False)
    password = db.Column(db.VARCHAR(50), nullable = False)
    
 
    # repr method represents how one object of this datatable
    # will look like
    def __repr__(self):
        return f"New USER created with name "
class Role(db.Model):
    # creating the role for each new user added
    id = db.Column(db.Integer,primary_key= True)
    username = db.Column(db.VARCHAR(50), nullable = False)
    role = db.Column(db.VARCHAR(50), nullable = False)

    def __repr__(self):
        return f"New User Role created"

class ciphers(db.Model):
    # saving the encrypted texts
    id = db.Column(db.Integer,primary_key = True)
    cipher = db.Column(db.VARCHAR(50),nullable = False)
    
 
    # repr method represents how one object of this datatable
    # will look like
    def __repr__(self):
        return f"New entry created "


@app.route('/')  #decorator for route(argument) function
def first_page():# renders the first page   
    return render_template('form.html') 


@app.route('/towards_homepage', methods= ['POST', 'GET'])
def towards_homepage():
    return render_template('homepage.html')

@app.route('/registration_form')
def registration_form():
    return render_template('registration_form.html')

global var
var = 0
@app.route('/register_new_user', methods = ['POST', 'GET'])
def register_new_user():
    #code for redirecting user to the login page after the user succesfully registers
    global var  
    print("first one")
    if request.method == 'POST':
        print("success underway")
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        access = request.form['access']
        if password =='' or username == '' or name =='' :
            return render_template('registration_form.html', info = 'Please fill all the fields')
        print("print this")
        print(type(username))
        print(type(access))
        #here we put the new user data into database
        p = User(name = name, username = username, password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(14)))
        db.session.add(p)
        print(var)
        var = Role.query.count()
        q = Role(id = var, username = username, role = access)
        
        db.session.add(q)
        db.session.commit()
        return render_template('registration_form.html',info = 'You have sucessfully registered!')
    else :
        return "new user registration was failed"
#returns encoded text given any plaintext file
def encrypt_plaintext(text):

    modified_plaintext = text.encode('utf-8')
    encoded_text = base64.b64encode(modified_plaintext)	
    return encoded_text
#returns the decrypted ciphertext
def decrypt_plaintext(text):

    sample_string_bytes = base64.b64decode(text)
    sample_string = sample_string_bytes.decode("ascii")
    return sample_string	


@app.route('/admin_login')
def admin_login():
    return render_template('admin_login.html')
    #return "this is the admin login page and here redirection to the login page for admin shall happen"

@app.route('/client_login')
def client_login():
    return render_template('client_login.html')
    #return "this is the client login page and here redirection to the client login page shall happen"

@app.route('/delete/<string:id>')
def erase(id):
     
    # deletes the data on the basis of unique id and
    # directs to home page
    data = ciphers.query.get(id)
    db.session.delete(data)
    db.session.commit()
    return redirect('/')


@app.route('/delete_user/<string:id>')
def erase_user(id):
    data = User.query.get(id)
    db.session.delete(data)
    db.session.commit()
    return redirect('/displayall_user')

@app.route('/delete_role/<string:id>')
def erase_role(id):
    data = Role.query.get(id)
    db.session.delete(data)
    db.session.commit()
    return redirect('/displayall_roles')

@app.route('/success')
def success():
    return render_template('homepage.html')
    

# DATABASE RENDERING ROUTES
@app.route('/displayall',methods = ['POST','GET'])
def displayall():
    cipher = ciphers.query.all()
    return render_template('index.html', cipher = cipher)


@app.route('/displayall_user',methods = ['POST','GET'])
def displayall_user():
    user = User.query.all()
    return render_template('index_user.html', user = user )
    
@app.route('/displayall_roles', methods = ['POST','GET'])
def displayall_roles():
    role = Role.query.all()
    return render_template('index_role.html', role = role )

@app.route('/to_client_page')
def to_client_page():
    return render_template('client_page.html', info = 'You are logged in!')

@app.route('/to_manager_page')
def to_manager_page():
    return render_template('manager_page.html', info = 'You are logged in!')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        raw_username = non_encrypted_username = username

        password = request.form['password']     
        raw_password = password
        
        
        #print(query) 
        #check if password matches or not and also check that if role based on username 
        #if the username is related to manager then redirect to manager_page and if client then redirect to manager_page

        
        
        

        print(db.session.query(User.id).filter_by(username = username))
        db.session.query(User.id).filter_by()
        matching_roles = db.session.query(Role.id).filter_by(username = non_encrypted_username)
        matching_users = db.session.query(Role.role).filter_by(username = non_encrypted_username)
        matching_password = User.query.filter_by(username = username)
        val = ""
        print("imp")
        print(username)
        pass_to_check = ""
        for user in matching_users :
            val = user.role
        print(val)
        cnt = 0
        pass_to_check = ""
        for value in matching_password:
            pass_to_check  = value.password
            print(cnt)
        print(password)
        print(pass_to_check)
        if raw_username == '' or raw_password == '':
            return render_template('form.html', info = 'Username and Password cannot be empty')

        if  bcrypt.checkpw(password.encode('utf-8'), pass_to_check):
            if val == "client":
                return redirect('/to_client_page')
            elif val == "manager":
                return redirect('/to_manager_page')

        else :
            return render_template('form.html', info = 'Invalid credentials!')

    else:
        return render_template('form.html')
        """Version= request.args.get('Version')
        SystemSerialNumber = request.args.get('SystemSerialNumber')
        Licenses = request.args.get('Licenses')
        return redirect(url_for('success',Version=Version,SystemSerialNumber=SystemSerialNumber,Licenses=Licenses))"""



@app.route('/encipher/<Version> /n <SystemNumber> /n <License>/n')
def encipher(Version, SystemNumber, License):
    plaintext = "NonStop ESS License \nVersion : 1 \n SystemNumber : "+SystemNumber+"\nLicense:1"
    print("here i am printing" + plaintext)
    modified_plaintext = plaintext.encode('utf-8')
    encoded_text = base64.b64encode(modified_plaintext)	
    with open('./saved_files/base64_encoded_file','wb') as binary_file:
        binary_file.write(encoded_text)
    
   
    if encoded_text != '':
        p = ciphers(cipher = encoded_text)
        db.session.add(p)
        db.session.commit()
        return redirect(url_for("to_client_page")+ "#myid")
    else :
        return redirect('/')
    return encoded_text 

@app.route('/download', methods = ['POST','GET'])
def download_file():
    print("into this function")
    if request.method == 'POST':
        print("in this request")
        SystemNumber =  request.form['SystemNumber']
        License = request.form.get('license')
        filename = request.form['filename']
        if SystemNumber == '':
            return render_template('client_page.html', info = 'SystemNumber cannot be empty!')

        if filename == '':
            return render_template('client_page.html', info = 'Filename cannot be empty!')
        print("the below value is of license")
        print(type(License))
        if License == "on":
            License_pass_value = '1'
        else : 
            License_pass_value = '0'
        
        ciphertext ={
            'Version'  : 1, 
            'SystemNumber' : SystemNumber,
            'License' : 1
        }

        plaintext = "NonStop ESS License \nVersion : 1 \n SystemNumber : "+SystemNumber+"\nLicense:"+License_pass_value;
        print("here i am printing" + plaintext)
        modified_plaintext = plaintext.encode('utf-8')
        encoded_text = base64.b64encode(modified_plaintext)	
        with open(filename,'wb') as binary_file:
            binary_file.write(encoded_text)

        p = "base64_encoded_file.txt"
        return send_file(filename,as_attachment = True)
    else:
        return "hello gys"

@app.route('/encode', methods = ['POST','GET'])
def encode():
    print("this is encode function")
    if request.method == 'POST':

        SystemNumber =  request.form['SystemNumber']    
        License = request.form.get('License')
        print("the below value is of license")
        print(type(License))
        if License == "on":
            License_pass_value = 1
        else : 
            License_pass_value = 0
        
        ciphertext ={
            'Version'  : 1, 
            'SystemNumber' : SystemNumber,
            'License' : 1
        }

        
        return redirect(url_for('encipher',Version = 1, SystemNumber =  SystemNumber, License = License_pass_value))
    return render_template('login.html') 

    

@app.route('/decipher/<cipher>')
def decipher(cipher):
    #converts the cipher into plaintext
    #base64_string =" R2Vla3NGb3JHZWVrcyBpcyB0aGUgYmVzdA =="
    base64_bytes = cipher.encode("ascii")
    
    sample_string_bytes = base64.b64decode(base64_bytes)
    sample_string = sample_string_bytes.decode("ascii")
    print("printing sample string " + sample_string)
    return sample_string	
    
# take input from user and first encipher the input and then save the encrypted part into the DB.
# when the user 


@app.route('/decode_file', methods = ['POST','GET'])
def decode_file():
    if request.method == 'POST':
        text_to_be_encoded = request.form['Choose File']
        file1 = open(text_to_be_encoded, "r+")
        print(file1.read())
        
        

        with open(text_to_be_encoded,'r') as file:
            to_print = file.read()
        base64_bytes = to_print.encode("ascii")
        print("this is to_print" + to_print)
    
        sample_string_bytes = base64.b64decode(base64_bytes)
        sample_string = sample_string_bytes.decode("ascii")
        return render_template('manager_page.html', info = sample_string)
        #print(text_to_be_encoded + "she")
    return redirect('/decode_file')



@app.route('/decode', methods = ['POST', 'GET'])
def decode():
    #return "successfully executed decode function"
    if request.method == 'POST':
        cipher = request.form['Choose File']
        cipher += "=" * ((4 - len(cipher) % 4) % 4)
        print(cipher,base64.b64encode(base64.b64decode(cipher)),"she")
        c = 0
        if base64.b64encode(base64.b64decode(cipher)) == bytes(cipher, 'utf-8') :
            return redirect(url_for('decipher', cipher = cipher))
        
        else :
            return "The string you entered is not base64 encoded"
    else:
        return "hello_world"



if __name__ == '__main__':
    app.run(debug=True,port = 5000)
