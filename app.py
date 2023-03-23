from flask import Flask, redirect, url_for, request,render_template
from flask_sqlalchemy import SQLAlchemy
#from flask_migrate import Migrate, migrate
 

import sqlite3
import base64
import binascii



app = Flask(__name__,template_folder='templates')


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ciphers.db'
    
db = SQLAlchemy(app)

# Settings for migrations
#migrate = Migrate(app, db)

app.app_context().push()



class ciphers(db.Model):
    # just save the encrypted texts
    id = db.Column(db.Integer,primary_key = True)
    cipher = db.Column(db.VARCHAR(50),nullable = False)
    
 
    # repr method represents how one object of this datatable
    # will look like
    def __repr__(self):
        return f"New entry created "


@app.route('/')  #decorator for route(argument) function
def hello_user():     #binding to hello_user call
    return render_template('form.html') 

#set of employee ids to verify from
valid_emp_id_client = ['234432','345543','567765']
valid_emp_id_admin = ['246642','357753','579975']


@app.route('/towards_homepage', methods= ['POST', 'GET'])
def towards_homepage():
    return render_template('homepage.html')


@app.route('/check_credentials_client', methods = ['POST','GET'])
def check_credentials_client():
    print("sdfs")
    if request.method == 'POST':
        emp_id = request.form['emp_id']
        print(type(emp_id))
        print(type(valid_emp_id_client[0]))
        if emp_id in valid_emp_id_client:
           print("hye man")
           return redirect(url_for('towards_homepage'))
        else :
           print("hell you")
           return redirect('')
    else :
        return "the client function did not execute properly"



@app.route('/check_credentials_admin', methods = ['POST','GET'])
def check_credentials_admin():
    if request.method == 'POST':
        emp_id = request.form['emp_id']
        print('sdfasdf')
        if emp_id in valid_emp_id_admin:
          return redirect(url_for('towards_homepage'))
        else :
          return "hello world"
    else :  
        return "the admin function did not execute properly"



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

@app.route('/success')
def success():
    
    return render_template('homepage.html')
    




@app.route('/displayall',methods = ['POST','GET'])
def displayall():
    cipher = ciphers.query.all()
    return render_template('index.html', cipher = cipher)


@app.route('/login', methods=['POST', 'GET'])
def login():
    
    if request.method == 'POST':
        """emp_id = request.form['emp_id']
        radio = checked['']

        if radio in valid_user:
            
        elif credentials in valid_adnub :
            return "Credentials you provided are not valid"""
        return redirect(url_for('success'))
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
    with open('./saved_files/file_with_encoded_text','wb') as binary_file:
        binary_file.write(encoded_text)
    
    return "The file was succesfully saved "
    
    """if encoded_text != '':
        p = ciphers(cipher = encoded_text)
        db.session.add(p)
        db.session.commit()
        return redirect('/displayall')
    else :
        return redirect('/')"""
    return encoded_text 


@app.route('/encode', methods = ['POST','GET'])
def encode():
    print("WHAT THE HECK")
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
        return sample_string	
        #print(text_to_be_encoded + "she")
    return redirect('/')



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
    app.run(debug=True)
