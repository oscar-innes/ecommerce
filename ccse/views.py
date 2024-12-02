from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
import secrets
import os
import datetime
from pymongo import MongoClient
import hashlib
import pyotp
from django.views import View
import re
from base64 import b64encode
import random
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
import base64
from django.template.response import TemplateResponse
import binascii
from bson import Binary
import logging
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout 
from urllib.parse import quote
import requests
import json
import time 
import qrcode 
from io import BytesIO
import atexit
import sendgrid
from sendgrid.helpers.mail import Content, Email, Mail
from sendgrid.helpers.mail import Mail, Email, Content, To, From

def fix_email(email):
    email = re.sub(r'@(\w+)(com)', r'@\1.\2', email) 
    return email


logger = logging.getLogger(__name__)

def is_otp_valid(username, secret, user_otp):
  thebigone = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureCart")
  totp = pyotp.parse_uri(thebigone)
  return totp.verify(user_otp)

def get_b64encoded_qr_image(data):
    print(data)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buffered = BytesIO()
    img.save(buffered)
    return b64encode(buffered.getvalue()).decode("utf-8")


def forgot_pass(request):
    db = get_db()
    hi = request.POST
    username = hi.get('user2')
    email = hi.get('email')
    k = db.Logins.find_one({"username": username})
    try:
        if k:
            email_to_decrypt = k.get("email")
            vector = k.get("vector")
            actualemail = decrypt_customers(username, email_to_decrypt, vector) 
            generated_code = random.randint(100000000000, 999999999999)
            actualemail = fix_email(actualemail)
            if actualemail == email:
                sg = sendgrid.SendGridAPIClient(os.environ.get("SENDGRID_API_KEY")
                )
                from_email = From("innesoscar@gmail.com")
                to_email = To(actualemail)
                subject = f"Code for account {username}"
                content = Content(
                "text/plain", f"Code for your account {generated_code}"
                )
                mail = Mail(from_email, to_email, subject, content)
                response = sg.client.mail.send.post(request_body=mail.get())
                context = {"code": generated_code, "username": username, "email": email}
                logger.info(f"{username} logged in and accessed admin panel.")
                return render(request, "verifyemail.html", context)
            else:
                context = {"login_message": "Error occured, That is not the users email."}
                return render(request, "custlogin.html", context)
        else:
            context = {"login_message": "Error occured, No such user exists."}
            return render(request, "custlogin.html", context)

    except Exception as e:
        context = {"login_message": "Error occured, ensure you have inputted valid email."}
        return render(request, "custlogin.html", context)
                



def verify_change(request):
    db = get_db()
    hi = request.POST
    code = hi.get('code')
    code2 = hi.get('code2')
    user3 = hi.get('user3')
    email = hi.get('email')
    try:
        if user3 != None:
            if code == code2:
                context = {"username": user3}
                request.session['codeaccepted'] = True
                request.session['username'] = user3
                return render(request, "changepass.html", context)
            else:
                context = {"code": code, "username": user3, "email": email}
                return render(request, "verifyemail.html", context)
        else:
            context = {"code": code, "username": user3, "email": email}
            return render(request, "verifyemail.html", context)
    except Exception as e:
        context = {"code": code, "username": user3, "email": email}
        return render(request, "verifyemail.html", context)


def order_status(request):
    pass

def verify2fa(request, username):
    db = get_db()
    hi = request.POST
    otp = hi.get('otp')
    k = db.Logins.find_one({"username": username})
    try:
        if k:
            sec = k.get("secret_token")
            if is_otp_valid(username, sec, otp):
                print("2FA verification successful!!")
                request.session['username'] = username
                basket = request.session['baskets'][username]
                equation = 0
                for usbskt2 in basket:
                    equation += usbskt2['qnt']
                context3 = {'username': username, 'user_basket_count': equation}
                if role_check(username):
                    userquery = list(db.Logins.find({}))
                    userproducts = list(db.Products.find({}))
                    context= {'users': userquery}
                    context2 = {'products': userproducts}
                    username = request.session['username']
                    context4 = {'productquery': context2, 'userquery': context, 'username': username, 'user_basket_count': equation}
                    logger.info(f"{username} logged in and accessed admin panel.")
                    return render(request, "adminpanel.html", context4)

                else:  
                    username = request.session['username']
                    logger.info(f"{username} logged in.")
                    return render(request, "home.html", context3)
            else:
                print("Invalid OTP. Please try again.")
                return render(request, "verify2fa.html", {'error_message': 'Invalid OTP Please retry.'})
        else:
            print("Invalid OTP. Please try again.")
            return render(request, "verify2fa.html", {'error_message': 'Invalid OTP. Please retry.'})
    except Exception as e:
        return render(request, "verify2fa.html", {'error_message': 'Invalid OTP Please retry.'})

def role_check(username):
    user_rolecheck = db.Logins.find_one({"username": username}, {"role": 1})
    if user_rolecheck:
        if user_rolecheck.get("role") in ["admin", "moderator"]:
            return True
        else:
            return False
    else:
        return False
    
def role_check2(username):
    user_rolecheck = db.Logins.find_one({"username": username}, {"role": 1})
    if user_rolecheck:
        if user_rolecheck.get("role") in ["admin"]:
            return True
        else:
            return False
    else:
        return False
    
def card_check(sort_code, account_no, cvv):
    acc2 = int(account_no)
    reggie = r'^[1-9]{2}\s?\-?[1-9]{2}\s?\-?[1-9]{2}$'
    if acc2 >= 100000000000 and acc2 <= 999999999999:
        if len(cvv) == 3:
            if re.match(reggie, sort_code):
                return True
            else:
                return False
        else:
            return False
    else: 
        return False
                
def sanitise_no(input):
  try:
    no = float(input)
    return float("%.2f" % no)
  except ValueError:
    new = re.sub('[^\d.]', '', no) 
    try:
      new = float(new) 
      return new
    except ValueError:
      return None

def update_keys(username):
    if username not in login_attempts:
        login_attempts[username] = 0

    

def password_check(password):
    if not re.search(r'[A-Z]', password):
        return False, "No capital letter"
    if not re.search(r'[a-z]', password):
        return False, "No lowecase letter"
    if not re.search(r'\d', password):
        return False, "No digit"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password): #usedw3resource here
        return False, "No special chara"
    return True, "All clear"

def generate_salt(length=16):
    return secrets.token_hex(length)

def create_basket(request, session):
    session_id = session.session_key
    username = request.session['username']
    if 'basket' not in session:
        request.session['baskets'] = {}
    if 'username' not in session['baskets']:
        request.session['baskets'][username] = []

def encrypt_salt(username, input):
    vector = secrets.token_bytes(16)  # create a random vector
    usernamer = hashlib.sha256(username.encode()).digest()
    aes = AES.new(usernamer, AES.MODE_GCM, nonce=vector) #create a new aes element with the key vector and gcm
    encryptedsalt = aes.encrypt(input.encode('utf-8'))
    return encryptedsalt.hex(), vector.hex()  # Return both encrypted salt and vector as hex values cause theyre nicer than bytes

def unencrypt_salt(username, salt, vector):
    salty = bytes.fromhex(salt)
    vector1 = bytes.fromhex(vector)  #convert back to bytes
    usernames = hashlib.sha256(username.encode()).digest() ##we derive a key from the enocding of the username
    aes = AES.new(usernames, AES.MODE_GCM, nonce=vector1)
    plainsalt = aes.decrypt(salty) #decrypt the salt
    return plainsalt.decode('utf-8') #decode from bytes to a plaintext salt

def encrypt_customers(username, input, vector):
    nonce = bytes.fromhex(vector)
    encrypt = hashlib.sha256(username.encode()).digest()
    aes = AES.new(encrypt, AES.MODE_GCM, nonce=nonce)
    salty = aes.encrypt(input.encode('utf-8'))
    ex2_element = salty.hex()
    return ex2_element

def decrypt_customers(username, input, vector):
    salty = bytes.fromhex(input)
    nonce = bytes.fromhex(vector)
    encrypt = hashlib.sha256(username.encode()).digest()
    aes = AES.new(encrypt, AES.MODE_GCM, nonce=nonce)
    plaintext = aes.decrypt(salty)
    return plaintext.decode('utf-8') 

def create_hash(password, salt):
    sha = hashlib.sha512()
    hashedp = bytes(password + str(salt), 'utf-8')
    sha.update(hashedp)
    final = base64.urlsafe_b64encode(sha.digest())
    base64.b64encode(final).decode('utf-8')
    return final

def sanitise_input(string):
    return re.sub('[../+\\n+\\r"\\\']*', '', string)

def check_details(username, email, number):
    db = get_db()
    try:
        if db.Logins.find_one({"username": username}) or db.Logins.find_one({"email": email}):
            return False
        else:
            return True
    except Exception as e:
        return True

def generate_code():
    return random.choice(range(100000, 999999))

def check_password(password):
    if len(password) > 10:
        return True
    else:
        return False

def get_db():
    reciever = MongoClient("mongodb+srv://mongouser:BigBallsBouncing@cluster0.nfi83.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0") 
    return reciever['WashDB']

def home(request): 
    try:
        username = request.session['username']
        basket = request.session['baskets'][username]
        equation = 0
        for basket in basket:
            equation += basket['qnt']
        context3 = {"user_basket_count": equation,  'username': username }
        return render(request, "home.html", context3)
    except Exception as e:
        return render(request, "home.html")
  
def contact(request): 
    try:
        username = request.session['username']
        basket = request.session['baskets'][username]
        equation = 0
        for bakset in basket:
            equation += bakset['qnt']
        context3 = {"user_basket_count": equation,  'username': username }
        return render(request, "contact.html", context3)
    except Exception as e:
        return render(request, "contact.html")

def products(request): 
    db = get_db()
    try:
        username = request.session['username']
    except Exception as e:
        username = None
        return render(request, "custlogin.html")
    try:
        username = request.session['username']
        basket = request.session['baskets'][username]
        userproducts = list(db.Products.find({}))
        context2 = {'products': userproducts}
        equation = 0
        for usbskt2 in basket:
                equation += usbskt2['qnt']
        context3 = {'productquery': context2, 'Update_Message': None,  "user_basket_count": equation,  'username': username }
        ##I think this is involving pulling the products
        return render(request, "products.html", context3)
    except Exception as e:
        return render(request, "products.html")
        
def cust_login(request): 
    try:
        if request.session['username'] is None:
            return render(request, "custlogin.html")
        else:
            username = request.session['username']
            return render(request, "custlogin.html", {"username": f"{username}"})
    except Exception as e:
        return render(request, "custlogin.html")
    
def delete_file(request): 
    username = request.session['username']
    if role_check(username):
        db = get_db()
        data = request.POST
        userindex = sanitise_input(data.get('delproductname'))
        role = sanitise_input(data.get('sommat'))
        if role == "Products":
            db.Products.delete_one({"productName": userindex})
            userquery = list(db.Logins.find({}))
            userproducts = list(db.Products.find({}))
            context= {'users': userquery}
            context2 = {'products': userproducts}
            logger.info(f"Product {userindex} deleted.")
            context3 = {'productquery': context2, 'userquery': context, 'username': username, 'Update_Message': f"Product deleted."}
            return render(request, "adminpanel.html", context3)
        elif role == "Logins":
            db.Logins.delete_one({"username": userindex})
            userquery = list(db.Logins.find({}))
            userproducts = list(db.Products.find({}))
            context= {'users': userquery}
            context2 = {'products': userproducts}
            logger.info(f"User {userindex} deleted.")
            context3 = {'productquery': context2, 'userquery': context, 'username': username, 'Update_Message': f"User deleted."}
            return render(request, "adminpanel.html", context3)
        else:
            userquery = list(db.Logins.find({}))
            userproducts = list(db.Products.find({}))
            context= {'users': userquery}
            context2 = {'products': userproducts}
            context3 = {'productquery': context2, 'userquery': context, 'username': username, 'Update_Message': f"Element not found in the database."}
            return render(request, "adminpanel.html", context3)

def postlogin(request): 
    data = request.POST
    db = get_db()
    username = sanitise_input(data.get('username'))
    password = sanitise_input(data.get('password'))
    exists = db.Logins.find_one({"username": f"{username}"})
    if exists:
        if username in login_attempts and login_attempts[username] <= 10:
            passy = exists.get("password")
            salty = exists.get("salt")
            vector = exists.get("vector")
            facheck = exists.get("secret_token")
            salt2 = unencrypt_salt(username, salty, vector) 
            check = create_hash(password, salt2)
            string_value = check.decode('utf-8')
            wham2 = str(string_value)
            if wham2 == passy:
                request.session['username'] = username
                create_basket(request, request.session)
                if facheck != "no":
                    login_attempts[username] == 0
                    equation = 0
                    basket = request.session['baskets'][username]
                    for usbskt2 in basket:
                        equation += usbskt2['qnt']
                    context3 = {'username': username, 'user_basket_count': equation}
                    return render(request, "verify2fa.html", context3)
                else:
                    if role_check(username):
                        basket = request.session['baskets'][username]
                        login_attempts[username] == 0
                        userquery = list(db.Logins.find({}))
                        userproducts = list(db.Products.find({}))
                        context= {'users': userquery}
                        context2 = {'products': userproducts}
                        equation = 0
                        for usbskt2 in basket:
                            equation += usbskt2['qnt']
                        context3 = {'productquery': context2, 'userquery': context, 'username': username, 'user_basket_count': equation}
                        logger.info(f"{username} successfully logged in")
                        return render(request, "adminpanel.html", context3)
                    else:
                        basket = request.session['baskets'][username]
                        login_attempts[username] == 0
                        equation = 0
                        for usbskt2 in basket:
                            equation += usbskt2['qnt']
                        logger.info(f"{username} logged in.")
                        context3 = {'username': username, 'user_basket_count': equation}
                        return render(request, "home.html", context3)
            else:
                logger.error(f"Incorrect login attempt for {username} ")
                return render(request, "custlogin.html", {'login_message': 'Passwords do not match'})
        
        else:
            login_attempts[username] += 1
            return render(request, "custlogin.html", {'login_message': 'user cannot be indexed'})

    else:
        return render(request, "custlogin.html", {'login_message': 'user does not exist'})

def admin(request):
    try:
        username2 = request.session['username']
        falsehood = role_check(username2)
        if falsehood:
            db = get_db()
            userquery = list(db.Logins.find({}))
            userproducts = list(db.Products.find({}))
            context= {'users': userquery}
            context2 = {'products': userproducts}
            context3 = {'productquery': context2, 'userquery': context, 'username': username2}
            return render(request, "adminpanel.html", context3)
        else:
            logger.critical(f"{username2} attempted to access admin page and was forbidden.")
            return HttpResponse(status=403)
    except Exception as e:
        logger.critical(f"{username2} attempted to access admin page and was forbidden.")
        return HttpResponse(status=403)

def postregis(request): 
    data = request.POST
    db = get_db()
    username = sanitise_input(data.get('username'))
    password = sanitise_input(data.get('password'))
    repeatpassword = sanitise_input(data.get('repeatpassword'))
    address = sanitise_input(data.get('address'))
    phone_number = sanitise_input(data.get('phonenumber'))
    email = sanitise_input(data.get('email'))
    fa_enabled = data.get('2fa_enabled')
    correct_length = check_password(password)
    if correct_length:
        if fa_enabled:
            if repeatpassword == password:
                passw, strengthmessage = password_check(password)
                if passw != False:
                    salt = generate_salt()
                    hashed = create_hash(password, salt)
                    clean_hash = hashed.decode('utf-8')
                    secret_token = pyotp.random_base32()
                    encsalt, vector = encrypt_salt(username, salt)
                    encemail = encrypt_customers(username, email, vector)
                    encnumber = encrypt_customers(username, phone_number, vector)
                    encaddress = encrypt_customers(username, address, vector)
                    file = {
                        "username": f"{username}",
                        "password": f"{clean_hash}",
                        "email": f"{encemail}",
                        "address": f"{encaddress}",
                        "phone_number": f"{encnumber}",
                        "salt": f"{encsalt}",
                        "vector": f"{vector}",
                        "secret_token": f"{secret_token}",
                        "role": "customer"
                    }
                    try:
                            message = "Login information inserted successfully."
                            check = check_details(username, encemail, encnumber)
                            if check == True:
                                    try:
                                        insert = db.Logins.insert_one(file)
                                        if insert:
                                            update_keys(username)
                                            k = db.Logins.find_one({"username": username})
                                            if k:
                                                token = k.get("secret_token")
                                                totp_auth = pyotp.totp.TOTP( 
                                                token).provisioning_uri( 
                                                name=username, 
                                                issuer_name='SecureCart') 
                                                base64_qr_image = get_b64encoded_qr_image(totp_auth)
                                                request.session['username'] = username
                                                context = {"secret": token, 'qr': base64_qr_image, 'username': username, 'username2': username}
                                                logger.info(f"Account {username} created with 2fa enabled.")
                                                return render(request, "setup2fa.html", context)
                                            else:
                                                return render(request, "custlogin.html")
                                        else:
                                            logger.error(f"Unexpected database error occured when registering a new user.")
                                            return render(request, "registration.html", {'register_message': 'Server Side database error. Please retry.'})


                                    except Exception as e:
                                        return render(request, "registration.html", {'register_message': f'{e}'})
                            else:
                                return render(request, "registration.html", {'register_message': f'Field in submission already in database'})
                    except Exception as e:
                        return render(request, "registration.html", {'register_message': f'{e}'})
                else:
                    return render(request, "registration.html", {'register_message': f'Password strength not correct you are missing: {strengthmessage}'})

            else:
                return render(request, "registration.html", {'register_message': 'passwords dont match'})
        else:
            if repeatpassword == password:
                passw, strengthmessage = password_check(password)
                if passw:
                    salt = generate_salt()
                    hashed = create_hash(password, salt)
                    clean_hash = hashed.decode('utf-8')
                    encsalt, vector = encrypt_salt(username, salt)
                    encemail = encrypt_customers(username, email, vector)
                    encnumber = encrypt_customers(username, phone_number, vector)
                    encaddress = encrypt_customers(username, address, vector)
                    secret_token = "no"
                    file = {
                        "username": f"{username}",
                        "password": f"{clean_hash}",
                        "email": f"{encemail}",
                        "address": f"{encnumber}",
                        "phone_number": f"{encaddress}",
                        "salt": f"{encsalt}",
                        "vector": f"{vector}",
                        "secret_token": f"{secret_token}",
                        "role": "customer"
                    }
                    try:
                        check = check_details(username, encemail, encnumber)
                        if check == True:
                            insert = db.Logins.insert_one(file)
                            update_keys(username)
                            if insert:
                                message = "Login information inserted successfully."
                                context = {'username': username}
                                logger.info(f"Account {username} created.")
                                return render(request, "custlogin.html", context)
                            else:
                                message = "Failed to insert login information."
                                return render(request, "custlogin.html", {'login_message': message})
                        else: 
                            return render(request, "registration.html", {'register_message': f'Field in submission already in database'})
                    except Exception as e:
                        return render(request, "registration.html", {'register_message': f'Server error occured on channel, please retry or contact support'})
                else:
                    return render(request, "registration.html", {'register_message': f'Password strength not correct you are missing: {strengthmessage}'})
            else:
                return render(request, "registration.html", {'register_message': 'Passwords dont match'})    
    else:
        return render(request, "registration.html", {'register_message': 'error, passwords not correct length'})
     
def registration(request): 
    return render(request, "registration.html")
        
def add1item(request, product_name):
    try: 
        username = request.session['username']
        basket = request.session['baskets'][username]
        if (usbskt['name'] == product_name in basket for usbskt in basket):
            for usbskt in basket:
                db = get_db()
                check = db.Products.find_one({"productName": usbskt['name']})
                grab = check.get("productStock")
                if usbskt['name'] == product_name:
                    if usbskt['qnt'] < grab:
                        usbskt['qnt'] += 1
                        request.session['baskets'][username] = basket
                        request.session.modified = True
                        context2 = {'products': basket}
                        finalprice = 0
                        equation = 0
                        for usbskt2 in basket:
                            wanyama = int(float((usbskt2['price'])))
                            price_prod  = usbskt2['qnt'] * wanyama
                            finalprice += price_prod  
                        for usbskt2 in basket:
                            equation += usbskt2['qnt']
                        context3 = {'productquery': context2, "user_basket_count": equation,  'username': username, 'total_price': finalprice}
                        return render(request, "basket.html", context3)
                    elif usbskt['qnt'] >= grab:
                        context2 = {'products': basket}
                        finalprice = 0
                        equation = 0
                        for usbskt2 in basket:
                            wanyama = int(float((usbskt2['price'])))
                            price_prod  = usbskt2['qnt'] * wanyama
                            finalprice += price_prod  
                        for usbskt2 in basket:
                            equation += usbskt2['qnt']
                        context3 = {'productquery': context2, "user_basket_count": equation,  'username': username, 'total_price': finalprice}
                        return render(request, "basket.html", context3)



    except Exception as e:
        equation = 0
        for usbskt2 in basket:
                equation += usbskt2['qnt']
        context3 = {"user_basket_count": equation}
        return render(request, "custlogin.html", context3)

def remove1item(request, product_name):
    try:
        username = request.session['username']
        basket = request.session['baskets'][username]
        if (usbskt['name'] == product_name in basket for usbskt in basket):
            for usbskt in basket:
                if usbskt['name'] == product_name:
                    usbskt['qnt'] -= 1
                    if usbskt['qnt'] == 0:
                        basket.remove(usbskt)
                        request.session['baskets'][username] = basket
                        request.session.modified = True
                        context2 = {'products': basket}
                        finalprice = 0
                        equation = 0
                        for usbskt2 in basket:
                            wanyama = int(float((usbskt2['price'])))
                            price_prod  = usbskt2['qnt'] * wanyama
                            finalprice += price_prod  
                        for usbskt2 in basket:
                            equation += usbskt2['qnt']
                        context3 = {'productquery': context2, "user_basket_count": equation,  'username': username, 'total_price': finalprice}
                        return render(request, "basket.html", context3)
                    else:
                        context2 = {'products': basket}
                        finalprice = 0
                        equation = 0
                        for usbskt2 in basket:
                            wanyama = int(float((usbskt2['price'])))
                            price_prod  = usbskt2['qnt'] * wanyama
                            finalprice += price_prod  
                        for usbskt2 in basket:
                            equation += usbskt2['qnt']
                        context3 = {'productquery': context2, "user_basket_count": equation,  'username': username, 'total_price': finalprice}
                        return render(request, "basket.html", context3)  
                else:
                    pass         
        else:
            equation = 0
            for usbskt2 in basket:
                    equation += usbskt2['qnt']
            return render(request, "basket.html", context3)
    except Exception as e:
        equation = 0
        for usbskt2 in basket:
                equation += usbskt2['qnt']
        context3 = {"user_basket_count": equation}
        return render(request, "custlogin.html", context3)

def clearbasket(request):
    equation = 0
    username = request.session['username']
    del request.session['baskets'][username]
    request.session.modified = True
    create_basket(request, request.session)
    context3 = {"user_basket_count": equation, 'username': username}
    return render(request, "basket.html", context3)

def basket(request): 
    try:
        username = request.session['username']
        basket = request.session['baskets'][username]
        context2 = {'products': basket}
        finalprice = 0
        equation = 0
        for usbskt2 in basket:
            wanyama = int(float((usbskt2['price'])))
            price_prod  = usbskt2['qnt'] * wanyama
            finalprice += price_prod  
        for usbskt2 in basket:
            equation += usbskt2['qnt']
        context3 = {'productquery': context2, "user_basket_count": equation,  'username': username, 'total_price': finalprice}
        return render(request, "basket.html", context3) 
    except Exception as e:
        equation = 0
        username = request.session['username']
        context3 = {"user_basket_count": equation, 'username': username}
        return render(request, "custlogin.html", context3)    

    ###youtube tutorial tommorow

def add_to_cart(request): 
    try:
        if request.session['username'] != None:
            username = request.session['username']
            basket = request.session['baskets'][username]
            print(basket)
            db = get_db()
            name = request.POST.get('product_name')
            image = request.POST.get('product_image')
            price = request.POST.get('product_price')
            product = {"name": name,
            "price": price,
            "image": image,
            "qnt": 1}
            in_basket = False
            for usrbskt in basket:
                check = db.Products.find_one({"productName": product['name']})
                grab = check.get("productStock")
                if product['name'] == usrbskt['name']:
                    in_basket = True
                    if usrbskt['qnt'] < grab:
                        usrbskt['qnt'] += 1
                    elif usrbskt['qnt'] >= grab:
                        equation = 0
                        for usbskt2 in basket:
                            equation += usbskt2['qnt']  
                        request.session['baskets'][username] = basket
                        request.session.modified = True
                        userproducts = list(db.Products.find({}))
                        context2 = {'products': userproducts}
                        context3 = {'productquery': context2, 'Update_Message': 'Cannot add anymore stock of this product', "user_basket_count": equation , "username": username}
                        return render(request, "products.html", context3)  
            if not in_basket:   
                basket.append(product)
            request.session['baskets'][username] = basket
            request.session.modified = True
            equation = 0
            for usbskt2 in basket:
                equation += usbskt2['qnt']  
            userproducts = list(db.Products.find({}))
            context2 = {'products': userproducts}
            context3 = {'productquery': context2, 'Update_Message': None, "user_basket_count": equation , "username": username}
            return render(request, "products.html", context3)
        else:
            db = get_db()
            userproducts = list(db.Products.find({}))
            context2 = {'products': userproducts}
            context3 = {'productquery': context2, 'Update_Message': "No user logged in", "username": username}
            return render(request, "products.html", context3)
    except Exception as e:
            db = get_db()
            userproducts = list(db.Products.find({}))
            context2 = {'products': userproducts}
            context3 = {'productquery': context2, 'Update_Message': "No user logged in", "username": username}
            return render(request, "products.html")

def payment(request): #were gonna do login logic here
    try:
        username = request.session['username']
        basket = request.session['baskets'][username]
        context2 = {'products': basket}
        finalprice = 0
        equation = 0
        for usbskt2 in basket:
            wanyama = int(float((usbskt2['price'])))
            price_prod  = usbskt2['qnt'] * wanyama
            finalprice += price_prod  
        for usbskt2 in basket:
            equation += usbskt2['qnt']
        if basket != []:
            context3 = {"user_basket_count": equation,  'username': username, 'total_price': finalprice}
            return render(request, "purchase.html", context3) 
        else:
            userproducts = list(db.Products.find({}))
            context2 = {'products': userproducts}
            context3 = {'productquery': context2, "user_basket_count": equation,  'username': username, 'total_price': finalprice}
            return render(request, "products.html", context3) 
    except Exception as e:
        equation = 0
        context3 = {"user_basket_count": equation}
        return render(request, "purchase.html", context3)  

def paynow(request):
    db = get_db()
    data = request.POST
    accno = sanitise_input(data.get('accountno'))
    srtcode = sanitise_input(data.get('sortcode'))
    cvv = sanitise_input(data.get('cvv2'))
    shipping_address = sanitise_input(data.get('address'))
    cityortown = sanitise_input(data.get('citytown'))
    houseno = sanitise_input(data.get('houseno'))
    postcode = sanitise_input(data.get('postcode'))
    country = sanitise_input(data.get('country'))
    username = request.session['username']
    basket = request.session['baskets'][username]
    try:
        exists = db.Logins.find_one({ "username": f"{username}"})
        if exists and card_check(srtcode, accno, cvv):
            vector = exists.get("vector")
            email = exists.get("email")
            enccvv = encrypt_customers(username, cvv, vector)
            encaccountno = encrypt_customers(username, accno, vector)
            encsortcode = encrypt_customers(username, srtcode, vector)
            current_datetime = datetime.datetime.now()
            prodstring = ""
            for item in basket:
                prodstring += 'Product:' + item['name'] + " " + 'x' + " " + str(item['qnt']) + " " #list of products inside an orders file.
            file = {
                    "username": f"{username}",
                    "products": f"{prodstring}",
                    "encaccnumber": f"{encaccountno}",
                    "enccvv": f"{enccvv}",
                    "encsortcode": f"{encsortcode}",
                    "status": 'Order confirmed',
                    "timestamp": f"{current_datetime}",
                    "house number": f"{houseno}",
                    "address": f"{shipping_address}",
                    "citytown": f"{cityortown}",
                    "postcode": f"{postcode}",
                    "country": f"{country}",
                    "email": f"{email}"
                }
            insert = db.Orders.insert_one(file) #if we were doing the realisitic card transfer it would involve the api to subtract money from a card, but this is fake for purposes of cw so we cant use stripe or something like that.
            if insert:  
                for item in basket:
                    check = db.Products.find_one({"productName": item['name']})
                    grab = check.get("productStock")
                    db.Products.update_one(
                        {"productName": item['name']},  
                        {"$inc": {"productStock": -item['qnt']}})
                basket.clear()
                request.session['baskets'][username] = basket
                request.session.modified = True
                orders = list(db.Orders.find({"username": username}))
                context2 = {'orderquery': orders}
                logger.info(f"Payment from {username} approved for {prodstring}.")
                context3 = {'orderquery': context2, 'username': request.session['username']}
                return render(request, "account.html", context3)
            else:
                context2 = {'products': basket}
                finalprice = 0
                equation = 0
                for usbskt2 in basket:
                    wanyama = int(float((usbskt2['price'])))
                    price_prod  = usbskt2['qnt'] * wanyama
                    finalprice += price_prod  
                for usbskt2 in basket:
                    equation += usbskt2['qnt']
                logger.error(f"Payment from {username} failed for {prodstring}.")
                context3 = {"user_basket_count": equation,  'username': username, 'total_price': finalprice, 'purchase_message': "Insertion error into database, contact support."}
                return render(request, "purchase.html", context3) 
        else:
            context2 = {'products': basket}
            finalprice = 0
            equation = 0
            for usbskt2 in basket:
                wanyama = int(float((usbskt2['price'])))
                price_prod  = usbskt2['qnt'] * wanyama
                finalprice += price_prod  
            for usbskt2 in basket:
                equation += usbskt2['qnt']
            context3 = {"user_basket_count": equation,  'username': username, 'total_price': finalprice, 'purchase_message': "Card Information invalid"}    
    except Exception as e:
        context2 = {'products': basket}
        finalprice = 0
        equation = 0
        print(e)
        for usbskt2 in basket:
            wanyama = int(float((usbskt2['price'])))
            price_prod  = usbskt2['qnt'] * wanyama
            finalprice += price_prod  
            for usbskt2 in basket:
                equation += usbskt2['qnt']
            context3 = {"user_basket_count": equation,  'username': username, 'total_price': finalprice, 'purchase_message': "Error on server side, please retry."}
            return render(request, "purchase.html", context3)

def add_product(request):
    username = request.session['username']  
    if role_check(username):
        data = request.POST
        db = get_db()
        name = sanitise_input(data.get('productname'))
        image = sanitise_input(data.get('imagefilename'))
        stock = sanitise_no(data.get('productstock'))
        price = sanitise_no(data.get('productprice'))
        desc = sanitise_input(data.get('productdesc'))
        price2 = float(price)
        stock2 = int(stock)
        file = {
                    "productName": f"{name}",
                    "productImage": f"{image}",
                    "productStock": int(f"{stock2}"),
                    "productPrice": float(f"{price2}"),
                    "productDesc": f"{desc}"
                }
        insert = db.Products.insert_one(file)
        if insert:
            
            userquery = list(db.Logins.find({}))
            userproducts = list(db.Products.find({}))
            context= {'users': userquery}
            context2 = {'products': userproducts}
            logger.info(f"New product {name} added to avaliable products.")
            context3 = {'productquery': context2, 'userquery': context, 'username': username, 'Update_Message': f"Successfully added {name} to Products!"}
            return render(request, "adminpanel.html", context3)
    else:
        return HttpResponse(status=403)

def cancelorder(request):
    post = request.POST
    prodlist = post.get('prodlist')
    try:
        if request.session['username'] is None:
            return render(request, "custlogin.html")
        else:
            db = get_db()
            username = request.session['username']
            basket = request.session['baskets'][username]
            equation = 0
            for usbskt2 in basket:
                equation += usbskt2['qnt']
            delete = list(db.Orders.delete_one({"prodlist": prodlist}))
            orders = list(db.Orders.find({"username": username}))
            logger.info(f"Order from {username} cancelled for {prodlist}.")
            context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation}
            return render(request, "account.html", context3)
    except Exception as e:
        username = request.session['username']
        equation = 0
        print(e)
        for usbskt2 in basket:
            equation += usbskt2['qnt']
        orders = list(db.Orders.find({"username": username}))
        context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation}
        return render(request, "account.html", context3)

def logout(request):
    try:
        username = request.session['username']
        logger.info(f"{username} has logged out of the site.")
        request.session.flush()
        return render(request, "home.html")
    except Exception as e:
         return render(request, "home.html")           

def account(request):
    try:
        if request.session['username'] is None:
            return HttpResponse(status=403)
        else:
            username = request.session['username']
            basket = request.session['baskets'][username]
            equation = 0
            for usbskt2 in basket:
                equation += usbskt2['qnt']
            orders = list(db.Orders.find({"username": username}))
            context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation}
            return render(request, "account.html", context3)
    except Exception as e:
        return render(request, "custlogin.html")
    
def change_pass(request):
    try:
        username = request.session['username']
        if request.session['username']:
            db = get_db()
            data = request.POST
            username = sanitise_input(data.get('username'))
            if data.get('password'):
                passwordog = sanitise_input(data.get('password'))
                newpass = sanitise_input(data.get('newpassword'))
                repeatnew = sanitise_input(data.get('repeatnew'))
                userfind = db.Logins.find_one({"username": username})
                basket = request.session['baskets'][username]
                if username == request.session['username']:
                    if userfind:
                        correct_length = check_password(newpass) 
                        passw, strengthmessage = password_check(newpass)
                        if correct_length and passw != False:
                                passy = userfind.get("password")
                                salty = userfind.get("salt")
                                vector = userfind.get("vector")
                                salt2 = unencrypt_salt(username, salty, vector)
                                check = create_hash(passwordog, salt2)
                                string_value = check.decode('utf-8')
                                wham2 = str(string_value)
                                if wham2 == passy:
                                    if newpass == repeatnew:
                                        salt = generate_salt()
                                        hashed = create_hash(newpass, salt)
                                        clean_hash = hashed.decode('utf-8')
                                        encsalt, victor = encrypt_salt(username, salt)
                                        update = {
                                        "salt": encsalt,
                                        "vector": victor,
                                        "password": clean_hash,

                                        }
                                        update = db.Logins.update_one(
                                        {"username": username}, 
                                        {"$set": update}       
                                        )
                                        if update:
                                            username = request.session['username']
                                            equation = 0
                                            for usbskt2 in basket:
                                                equation += usbskt2['qnt']
                                            orders = list(db.Orders.find({"username": username}))
                                            logger.info(f"{username}'s password has been updated to a new value.")
                                            context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation, "account_message": "Password updated!"}
                                            return render(request, "account.html", context3)
                                    else:
                                        equation = 0
                                
                                        orders = list(db.Orders.find({"username": username}))
                                        logger.error(f"Failed password change for {username}.")
                                        context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation, "account_message": "Passwords do not match, retry"}
                                        return render(request, "account.html", context3)
                                    
                                else:
                                    equation = 0
                                    orders = list(db.Orders.find({"username": username}))
                                    logger.error(f"Failed password change for {username}.")
                                    context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation, "account_message": "Passwords do not match, retry"}
                                    return render(request, "account.html", context3)
                        else:
                            equation = 0
                            orders = list(db.Orders.find({"username": username}))
                            logger.error(f"Failed password change for {username}.")
                            context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation, "account_message": "Passwords do not match or are not strong enough."}
                            return render(request, "account.html", context3)
                    else:
                        equation = 0
                        for usbskt2 in basket:
                            equation += usbskt2['qnt']
                        orders = list(db.Orders.find({"username": username}))
                        logger.error(f"User {request.session['username']} attempted to change account password that wasn't them.")
                        context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation, "account_message": "User attempted to change password for not their account."}
                        return render(request, "custlogin.html", context3)   
                else:
                    basket = request.session['baskets'][username]
                    equation = 0
                    for usbskt2 in basket:
                        equation += usbskt2['qnt']
                    orders = list(db.Orders.find({"username": username}))
                    context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation, "account_message": "New password isn't strong enough."}
                    return render(request, "account.html", context3)
            else:
                try:
                    newpass = sanitise_input(data.get('newpassword'))
                    repeatnew = sanitise_input(data.get('repeatnew'))
                    userfind = db.Logins.find_one({"username": username})
                    username = request.session['username']
                    if username == request.session['username']:
                        if userfind:
                            correct_length = check_password(newpass)
                            passw, strengthmessage = password_check(newpass)
                            if correct_length and passw != False:
                                if newpass == repeatnew and request.session['codeaccepted'] == True:
                                    salt = generate_salt()
                                    hashed = create_hash(newpass, salt)
                                    clean_hash = hashed.decode('utf-8')
                                    encsalt, victor = encrypt_salt(username, salt)
                                    update = {
                                    "salt": encsalt,
                                    "vector": victor,
                                    "password": clean_hash,

                                    }
                                    update = db.Logins.update_one(
                                    {"username": username}, 
                                    {"$set": update}       
                                    )
                                    if update:
                                        request.session['username'] = None
                                        logger.info(f"{username}'s password has been updated to a new value.")
                                        context3 = {"login_message": "Password updated!"}
                                        return render(request, "custlogin.html", context3)
                except Exception as e:
                    username = request.session['username']
                    equation = 0
                    orders = list(db.Orders.find({"username": username}))
                    context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation, "account_message": "Server error occured, please retry."}
                    return render(request, "changepass.html", context3)    

        else:
            equation = 0
            orders = list(db.Orders.find({"username": username}))
            context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation, "account_message": "Account cannot be found."}
            return render(request, "account.html", context3)
            
    except Exception as e:
        username = request.session['username']
        equation = 0
        orders = list(db.Orders.find({"username": username}))
        context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation, "account_message": "Server error occured, please retry."}
        return render(request, "account.html", context3)

def add_stock(request): 
    username2 = request.session['username']
    falsehood = role_check(username2)
    if falsehood:
        data = request.POST
        db = get_db()
        name = sanitise_input(data.get('productname'))
        no = sanitise_input(data.get('stocknumber'))
        if db.Products.find_one({"productName": name}):
            result = db.Products.update_one({'productName': name},  
            {'$inc': {'productStock': no}})
            userquery = list(db.Logins.find({}))
            userproducts = list(db.Products.find({}))
            context= {'users': userquery}
            context2 = {'products': userproducts}
            logger.info(f"Product {name} has had its stock increased by {no}.")
            context3 = {'productquery': context2, 'userquery': context, 'username': name, 'Update_Message': f"Successfully added {no} to {name}!"}
            return render(request, "adminpanel.html", context3)
        else:
            userquery = list(db.Logins.find({}))
            userproducts = list(db.Products.find({}))
            context= {'users': userquery}
            context2 = {'products': userproducts}
            context3 = {'productquery': context2, 'userquery': context, 'username': name, 'Update_Message': f"Product {name} not found!"}
            return render(request, "adminpanel.html", context3)
    else:
        return HttpResponse(status=403)

def change_role(request):
    username = request.session['username']
    if role_check(username):
        if role_check2(username):
            db = get_db()
            data = request.POST
            userindex = sanitise_input(data.get('changeuser'))
            role = sanitise_input(data.get('something'))
            if db.Logins.find_one({"username": userindex}):
                result = db.Logins.update_one({'username': userindex},  
                {"$set": {"role": role}})
                userquery = list(db.Logins.find({}))
                userproducts = list(db.Products.find({}))
                context= {'users': userquery}
                context2 = {'products': userproducts}
                logger.critical(f"{username} has had his role changed to {role}")
                context3 = {'productquery': context2, 'userquery': context, 'username': username, 'Update_Message': f"Successfully updated {userindex} to {role}"}
                return render(request, "adminpanel.html", context3)
            else:
                userquery = list(db.Logins.find({}))
                userproducts = list(db.Products.find({}))
                context= {'users': userquery}
                context2 = {'products': userproducts}
                context3 = {'productquery': context2, 'userquery': context, 'username': username, 'Update_Message': f"Username not found in the database."}
                return render(request, "adminpanel.html", context3)
        else:
            db = get_db()
            userquery = list(db.Logins.find({}))
            userproducts = list(db.Products.find({}))
            context= {'users': userquery}
            context2 = {'products': userproducts}
            logger.critical(f"{username} attempted to use moderator powers to make someone an admin. This is not allowed.")
            context3 = {'productquery': context2, 'userquery': context, 'username': username, 'Update_Message': f"Moderators cannot change roles."}
            return render(request, "adminpanel.html", context3)
    else:
        logger.critical(f"{username} attempted to perform an action they were not authorised to do.")
        return HttpResponse(status=403)

db = get_db()
usr_list = db.Logins.find({}, {"username": 1, '_id': 0})
global login_attempts
usernames = [user['username'] for user in usr_list]
login_attempts = dict.fromkeys(
    usernames, 0)  #intialise login attempts
