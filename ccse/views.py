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
import stripe
from django.http.response import JsonResponse # new
from django.views.decorators.csrf import csrf_exempt # new
from django.views.generic.base import TemplateView
from django.conf import settings
import traceback





def card_check(sort_code, account_no, cvv, date):
    acc2 = int(account_no)
    reggie = r'^[1-9]{2}\s?\-?[1-9]{2}\s?\-?[1-9]{2}$' #regex pattern checks that the sort code is of the appropriate length with '-' between every two numbers.
    if acc2 >= 100000000000 and acc2 <= 999999999999:  #is an account number a valid integer within a range.
        if len(cvv) == 3:
            if re.match(reggie, sort_code):
                month = date[:4]  #slice the selected date to obtain the input that matters to us
                year = date[5:7]
                if int(year) > datetime.datetime.now().year and int(month) > datetime.datetime.now().month:  #does the card expire yet check, is the entered month and year earlier than this month of this year.
                    return False
                else:
                    return True
            else:
                return False
        else:
            return False
    else:
        return False


def create_stripe_order(amount, prodlist, username):
    try:
        stripe.api_key = settings.STRIPE_SECRET_KEY  #obtain the key to interact with the stripe system
        checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],  #we default to a card payment here, nothing fancy
                mode='payment',
                client_reference_id=username,
                success_url="http://127.0.0.1:8000/",  
                cancel_url="http://127.0.0.1:8000/contact/", #lead to the contact page incase theres a technical error with a user trying to perform a payment
                line_items =[{
                    'price_data': {
                        'currency': "usd",
                        'product_data': {
                            'name': f'{username} ordered {prodlist}',  #JSON data to create a charge on the stripe dashboard based on the items ordered
                        },
                        'unit_amount': amount, 
                    },
                    'quantity': 1,  
                }],
        )

        stripe.PaymentIntent.create(   #creates a charge object that defines the amount paid based on the users basket
            amount=amount,
            currency="usd",
            automatic_payment_methods={"enabled": True, "allow_redirects": "never"},
            description=f"{username} ordered {prodlist}"
        )
        return True

    except Exception as e:
            return False

def create_stripe_product(name, price, desc):
    try:
        cents = int(price * 100)  #price is handled in cents so we need to convert to dollars to make our pricing accurate
        stripe.api_key = settings.STRIPE_SECRET_KEY
        product = stripe.Product.create(
                name=name, 
                description=desc   #create a product on the stripe dashboard
        )
        prodprice = stripe.Price.create(  #associate a price to a product using the price object
            product=product['id'],
            unit_amount=cents,
            currency="usd"  
        )
    except stripe.error.StripeError as e:
        return False

def fix_email(email):
    email = re.sub(r'@(\w+)(com)', r'@\1.\2', email) #regex pattern that adds a '.' back into the email as this gets removed during sanitiszation of inputs.
    return email

logger = logging.getLogger(__name__)

def is_otp_valid(username, secret, user_otp):
  thebigone = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureCart")   #create a new totp for a specific user with the secret, so this user is now linked to a google authenticator object
  totp = pyotp.parse_uri(thebigone)
  return totp.verify(user_otp)  #verify the entered code by a user against the code on the google authenticator instance

def get_b64encoded_qr_image(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)  #create a new QR code
    qr.add_data(data)  #add the link to the google authenticator totp for the specific user here
    img = qr.make_image(fill_color='black', back_color='white')
    buffered = BytesIO()
    img.save(buffered)
    return b64encode(buffered.getvalue()).decode("utf-8")

def forgot_pass(request):
    db = get_db()
    hi = request.POST
    username = sanitise_input(hi.get('user2'))
    email = sanitise_input(hi.get('email'))
    k = db.Logins.find_one({"username": username})
    try:
        if k:
            email_to_decrypt = k.get("email")
            vector = k.get("vector")
            generated_code = random.randint(100000000000, 999999999999)   #create a random code
            if email == email_to_decrypt:
                sg = sendgrid.SendGridAPIClient(os.getenv("SENDGRID_API_KEY")  #fetch the api key to communicate with the api to actually send the email.
                )                
                from_email = From("innesoscar@gmail.com")
                to_email = To(fix_email(email))
                subject = f"Code for account {username}"  # build the components of an email message that allows the code to be sent to the users email.
                content = Content(
                "text/plain", f"Code for your account {generated_code}"
                )
                mail = Mail(from_email, to_email, subject, content)
                response = sg.client.mail.send.post(request_body=mail.get())  #use the sendgrid module to actually send the email with all the content specified.
                request.session['generated_code'] = generated_code  #assign the code to the session so the user can verify against the code theyve been sent.
                context = {"username": username, "email": email, 'code': generated_code}
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
    hi = request.POST
    code = sanitise_input(hi.get('code'))
    user3 = sanitise_input(hi.get('user3'))
    try:
        if user3 != None:
            code2 = request.session['generated_code'] #does the code being entered matched the code that has been generated and stored in the session object
            if int(code) == int(code2):
                context = {"username": user3}  #if the values are the same, clear the code and confirm that the user has verified themselves
                del request.session['generated_code']
                request.session['codeaccepted'] = True
                request.session['username'] = user3
                return render(request, "changepass.html", context)
            else:
                context = {"code": code, "username": user3}
                return render(request, "verifyemail.html", context)
        else:
            context = {"code": code, "username": user3}
            return render(request, "verifyemail.html", context)
    except Exception as e:
        return render(request, "custlogin.html", {'login_message': 'Did not match code'})

def order_status(request):
    try:
        db = get_db()
        username = request.session['username']
        post = request.POST
        if role_check(username):
            status = sanitise_input(post.get('status'))
            ordering = sanitise_input(post.get('ordering'))
            ordered = ordering.split(" -- ") #lot of information specified for each order, divide and conquer this information
            timestamp = ordered[1]
            better_timestamp = f"{timestamp[:2]}/{timestamp[2:4]}/{timestamp[4:]}"  #slice the timestamp to extract a more defined time, day and month than datetime.now()
            cond1 = {
                "username": ordered[2],  #using the ordered variable as a array object grab the values at each index from the original string associated with an order
                "timestamp": better_timestamp,
                "products": ordered[0]
            }
            k = db.Orders.find_one(cond1)  # find a value in orders that has all of these fields present and true
            if k:
                update = {
                    "$set": {
                        "status": f"{status}"
                    }  #change the value at the json object to the status inputted
                }
                update = db.Orders.update_one(cond1, update)
                if update:
                    basket = request.session['baskets'][username]
                    equation = 0
                    for usbskt2 in basket:
                        equation += usbskt2['qnt']  #recalculate basket and page outputs stuff
                    userquery = list(db.Logins.find({}))
                    userproducts = list(db.Products.find({}))
                    orders = list(db.Orders.find({}))
                    context= {'users': userquery}
                    context2 = {'products': userproducts}
                    username = request.session['username']
                    context4 = {'productquery': context2, 'userquery': context, 'username': username, 'user_basket_count': equation,'orderquery':orders, 'Update_message': 'Successfully updated order!'}
                    logger.info(f"Order for {username} updated to {status}.")
                    return render(request, "adminpanel.html", context4)
                else:   
                    basket = request.session['baskets'][username]
                    equation = 0  #for if order information cannot be found
                    for usbskt2 in basket:
                        equation += usbskt2['qnt']
                    userquery = list(db.Logins.find({}))
                    userproducts = list(db.Products.find({}))
                    orders = list(db.Orders.find({}))
                    context= {'users': userquery}
                    context2 = {'products': userproducts}
                    username = request.session['username']
                    context4 = {'productquery': context2, 'userquery': context, 'username': username, 'user_basket_count': equation,'orderquery':orders, 'Update_message': 'Failed to update order!'}
                    return render(request, "adminpanel.html", context4)     
            else:
                basket = request.session['baskets'][username]
                equation = 0 #for if order information cannot be found
                for usbskt2 in basket:
                    equation += usbskt2['qnt']
                userquery = list(db.Logins.find({}))
                userproducts = list(db.Products.find({}))
                orders = list(db.Orders.find({}))
                context= {'users': userquery}
                context2 = {'products': userproducts}
                username = request.session['username']
                context4 = {'productquery': context2, 'userquery': context, 'username': username, 'user_basket_count': equation,'orderquery':orders, 'Update_message': 'Failed to update order!'}
                return render(request, "adminpanel.html", context4)
        else:
            basket = request.session['baskets'][username]
            equation = 0
            for usbskt2 in basket:  #for if order information cannot be found
                equation += usbskt2['qnt']
            userquery = list(db.Logins.find({}))
            userproducts = list(db.Products.find({}))
            orders = list(db.Orders.find({}))
            context= {'users': userquery}
            context2 = {'products': userproducts}
            username = request.session['username']
            context4 = {'productquery': context2, 'userquery': context, 'username': username, 'user_basket_count': equation,'orderquery':orders, 'Update_message': 'Failed to update order!'}
            return render(request, "adminpanel.html", context4)
    except Exception as e:
        return render(request, "custlogin.html", {'login_message': 'Login before you try and execute admin actions'})

def verify2fa(request, username):
    db = get_db()
    hi = request.POST
    k = db.Logins.find_one({"username": username})
    otp = sanitise_input(hi.get('otp'))  
    try:
        if k:
            sec = k.get('secret_token') 
            if is_otp_valid(username, sec, otp): #check whether otp alligns with the secret token assigned to a user in the database/
                request.session['username'] = username
                basket = request.session['baskets'][username]
                equation = 0
                for usbskt2 in basket:
                    equation += usbskt2['qnt']
                context3 = {'username': username, 'user_basket_count': equation}
                if role_check(username):  #access control of pages based on the role of the username logging in.
                    userquery = list(db.Logins.find({}))
                    userproducts = list(db.Products.find({}))
                    orders = list(db.Orders.find({}))
                    context= {'users': userquery}
                    context2 = {'products': userproducts}
                    username = request.session['username']
                    context4 = {'productquery': context2, 'userquery': context, 'username': username, 'user_basket_count': equation,'orderquery':orders}
                    logger.info(f"{username} logged in and accessed admin panel.")
                    return render(request, "adminpanel.html", context4)
                else:  
                    username = request.session['username']
                    logger.info(f"{username} logged in.")
                    return render(request, "home.html", context3)  #normal user logging in
            else:
                return render(request, "verify2fa.html", {'username': username, 'error_message': 'Invalid OTP Please retry.'})
        else: #for if otp cannot be resolved to a correct value
            return render(request, "verify2fa.html", {'username': username, 'error_message': 'Invalid OTP. Please retry.'})
    except Exception as e:
        return render(request, "verify2fa.html", {'error_message': 'Invalid OTP Please retry.'})

def role_check(username):
    user_rolecheck = db.Logins.find_one({"username": username}, {"role": 1})  #search and find a user and grab the role associated with their entry in the database
    if user_rolecheck:
        if user_rolecheck.get("role") in ["admin", "moderator"]:  #if the role is senior, the check is true otherwise false
            return True
        else:
            return False
    else:
        return False
    
def role_check2(username):
    user_rolecheck = db.Logins.find_one({"username": username}, {"role": 1})
    if user_rolecheck:
        if user_rolecheck.get("role") in ["admin"]:  #admin only check.
            return True
        else:
            return False
    else:
        return False
    
def sanitise_no(input):
  try:
    no = float(input)  #take a numeric input and make it a float and then return a decimal output that is encoded for sanitisation
    return float("%.2f" % no)
  except ValueError:
    new = re.sub('[^\d.]', '', no)   #if it cant be converted remove values to strip sensitive characters from a float.
    try:
      new = float(new) 
      return new
    except ValueError:
      return None

def update_keys(username):
    if username not in login_attempts:
        login_attempts[username] = 0  #set login attempts to zero when a login is confirmed

def password_check(password):
    if not re.search(r'[A-Z]', password):
        return False, "No capital letter"
    if not re.search(r'[a-z]', password):
        return False, "No lowecase letter"
    if not re.search(r'\d', password):
        return False, "No digit"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password): #usedw3resource here for regex patterns to verify a password is suitably strong
        return False, "No special chara"
    return True, "All clear"

def generate_salt(length=16):
    return secrets.token_hex(length)  #create a new custom salt to strengthen passwords

def create_basket(request, session, username):
    session_id = session.session_key
    if 'basket' not in session:
        request.session['baskets'] = {}  #create a basket if one doesnt exist
    if 'username' not in session['baskets']:
        request.session['baskets'][username] = [] #create a basket for a unique user, so that baskets dont clash with each other

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


def create_hash(password, salt):
    sha = hashlib.sha512()
    hashedp = bytes(password + str(salt), 'utf-8') #combine entered password with the salt
    sha.update(hashedp) #hash using sha
    final = base64.urlsafe_b64encode(sha.digest()) # convert back from a bytes object and make it a base64 hash that is a bit nicer to look at.
    base64.b64encode(final).decode('utf-8')
    return final

def sanitise_input(string):
    return re.sub('[../+\\n+\\r"\\\']*', '', string)  #remove dangerous characters from a string that is inputted.

def check_details(username, email):
    db = get_db()
    try:
        if db.Logins.find_one({"username": username}) or db.Logins.find_one({"email": email}):  #check whether details already exist in the database before proceeding
            return False
        else:
            return True
    except Exception as e:
        return True

def generate_code():
    return random.choice(range(100000, 999999))  #create a random code

def check_password(password):
    if len(password) > 10:
        return True  #password length check for strength
    else:
        return False

def get_db():
    reciever = MongoClient(os.getenv("MONGO_SECURECART"), tls=True) 
    return reciever['WashDB']  #create a reciever object that communicates with the database in a secure TLS channel.

def home(request): 
    try:
        username = request.session['username']
        basket = request.session['baskets'][username]  #request to the homepage and calculate things like current items in basket and store the current user logged in.
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
        equation = 0  #request to the contact page and calculate things like current items in basket and store the current user logged in.
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
        username = request.session['username']  #request to the products page and calculate things like current items in basket and store the current user logged in.
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
        if request.session['username'] is None:   #request to the customer login page 
            return render(request, "custlogin.html")
        else:
            username = request.session['username']
            return render(request, "custlogin.html", {"username": f"{username}"})
    except Exception as e:
        return render(request, "custlogin.html")
    
def delete_file(request): 
    try:
        stripe.api_key = settings.STRIPE_SECRET_KEY
        username = request.session['username']
        if role_check(username):
            db = get_db()
            data = request.POST
            userindex = sanitise_input(data.get('delproductname'))  
            role = sanitise_input(data.get('sommat'))
            if role == "Products":  #input is a dropdown box, so there is a choice of paths for the code
                db.Products.delete_one({"productName": userindex})
                userquery = list(db.Logins.find({}))
                userproducts = list(db.Products.find({}))
                orders = list(db.Orders.find({}))
                context= {'users': userquery}
                context2 = {'products': userproducts}
                danjuma = stripe.Product.search(query=f"active:'true' AND name:'{userindex}'")  #search for a product that is active and shares a name with what was inputted
                wooh = stripe.Price.search(query=f"product:'{userindex}'") #find the price object associated with the product object
                if danjuma.data:
                    identifier = danjuma.data[0].id  #if the product is found store the id of that product
                    for p in wooh.data:
                        stripe.Price.modify(p.id, active=False)  #deactivate the price for the object, so that the product can be deleted
                    stripe.Product.delete(identifier) #delete the product found
                    logger.info(f"Product {userindex} deleted.")
                    context3 = {'productquery': context2, 'userquery': context, 'username': username, 'Update_Message': f"Product deleted.", 'orderquery':orders}
                    return render(request, "adminpanel.html", context3)
                else:
                    logger.info(f"Deletion attempted by {username} but did not succeed.")
                    context3 = {'productquery': context2, 'userquery': context, 'username': username, 'Update_Message': f"Product not found.", 'orderquery':orders}
                    return render(request, "adminpanel.html", context3)
                
            elif role == "Logins":
                db.Logins.delete_one({"username": userindex})  #index database to delete a specific requested username and perform delete operation
                userquery = list(db.Logins.find({}))
                userproducts = list(db.Products.find({}))
                orders = list(db.Orders.find({}))
                context= {'users': userquery}
                context2 = {'products': userproducts}
                logger.info(f"User {userindex} deleted.")
                context3 = {'productquery': context2, 'userquery': context, 'username': username, 'Update_Message': f"User deleted.", 'orderquery':orders}
                return render(request, "adminpanel.html", context3)
            else:
                userquery = list(db.Logins.find({}))
                userproducts = list(db.Products.find({}))
                orders = list(db.Orders.find({}))
                context= {'users': userquery}
                context2 = {'products': userproducts}
                logger.info(f"Deletion attempted by {username} but did not succeed.")
                context3 = {'productquery': context2, 'userquery': context, 'username': username, 'Update_Message': f"Element not found in the database.", 'orderquery':orders}
                return render(request, "adminpanel.html", context3)
        else:
            logger.critical(f"{username} Attempted access admin page and was forbidden.")
            return HttpResponse(status=403)
    except Exception as e:
        logger.critical(f"User Attempted access admin page and was forbidden.")
        return HttpResponse(status=403)  #access control checks of the session being used by a user

def postlogin(request):
    try: 
        data = request.POST
        db = get_db()
        username = sanitise_input(data.get('username'))
        password = sanitise_input(data.get('password'))
        exists = db.Logins.find_one({"username": f"{username}"})
        if exists:
            if username in login_attempts and login_attempts[username] <= 10: #check that the account has not been spammed into oblivion
                passy = exists.get("password")
                salty = exists.get("salt")
                vector = exists.get("vector")
                facheck = exists.get("secret_token")
                salt2 = unencrypt_salt(username, salty, vector) #decode the encrypted salt and create a hash with the salt for authentication
                check = create_hash(password, salt2)   
                string_value = check.decode('utf-8')
                wham2 = str(string_value)
                if wham2 == passy: #does the hash match the hash stored in the database
                    create_basket(request, request.session, username)
                    if facheck != "no":  #is 2fa present for this user, if so this path gets executed.
                        login_attempts[username] == 0
                        equation = 0
                        basket = request.session['baskets'][username]
                        for usbskt2 in basket:
                            equation += usbskt2['qnt']
                        context3 = {'username': username, 'user_basket_count': equation}
                        return render(request, "verify2fa.html", context3)
                    else:
                        if role_check(username): #for if an admin has tried to log in and does not use 2fa to do so
                            basket = request.session['baskets'][username]
                            login_attempts[username] == 0
                            request.session['username'] = username
                            userquery = list(db.Logins.find({}))
                            userproducts = list(db.Products.find({}))
                            orders = list(db.Orders.find({}))
                            context= {'users': userquery}
                            context2 = {'products': userproducts}
                            equation = 0
                            for usbskt2 in basket:
                                equation += usbskt2['qnt']
                            context3 = {'productquery': context2, 'userquery': context, 'username': username, 'user_basket_count': equation, 'orderquery':orders}
                            logger.info(f"{username} successfully logged in")
                            return render(request, "adminpanel.html", context3)
                        else:  #regular user login logic
                            basket = request.session['baskets'][username]
                            request.session['username'] = username
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
                login_attempts[username] += 1  #if a login fails add one to the count of failed login attempts, rate limiting.
                return render(request, "custlogin.html", {'login_message': 'user cannot be indexed'})

        else:
            return render(request, "custlogin.html", {'login_message': 'user does not exist'})
    except Exception as e:
        return render(request, "custlogin.html", {'login_message': 'Server error, contact support'})
    
def admin(request):
    try:
        username2 = request.session['username']
        falsehood = role_check(username2)  #request to the admin page that checks the role of the user trying to access it. 
        if falsehood:
            db = get_db()
            userquery = list(db.Logins.find({}))
            userproducts = list(db.Products.find({}))
            orders = list(db.Orders.find({}))
            context= {'users': userquery}
            context2 = {'products': userproducts}
            context3 = {'productquery': context2, 'userquery': context, 'username': username2, 'orderquery':orders}
            return render(request, "adminpanel.html", context3)
        else:
            logger.critical(f"{username2} attempted to access admin page and was forbidden.")
            return HttpResponse(status=403)  #what happens if you try to access the page without the role in your session.
    except Exception as e:
        logger.critical(f"Attempted access admin page and was forbidden.")
        return HttpResponse(status=403)

def postregis(request): 
    data = request.POST
    db = get_db()
    username = sanitise_input(data.get('username'))
    password = sanitise_input(data.get('password'))
    repeatpassword = sanitise_input(data.get('repeatpassword'))
    address = sanitise_input(data.get('address'))
    phone_number = sanitise_input(data.get('phonenumber'))
    email = sanitise_input(data.get('email'))  #grab the values and sanitize what is to be entered into a field for data storage
    fa_enabled = data.get('2fa_enabled')  #is 2fa ticked for enabling?
    correct_length = check_password(password) 
    if correct_length:
        if fa_enabled:  #path for if 2fa is enabled
            if repeatpassword == password:
                passw, strengthmessage = password_check(password)
                if passw != False:  #ensure password is of suitable strength and length
                    salt = generate_salt()
                    hashed = create_hash(password, salt)
                    clean_hash = hashed.decode('utf-8')
                    secret_token = pyotp.random_base32()  #token for 2fa totp
                    encsalt, vector = encrypt_salt(username, salt)
                    encnumber = encrypt_customers(username, phone_number, vector)
                    encaddress = encrypt_customers(username, address, vector)  #encrypt sensitive data
                    file = {
                        "username": f"{username}",
                        "password": f"{clean_hash}",
                        "email": f"{email}",
                        "address": f"{encaddress}",
                        "phone_number": f"{encnumber}",
                        "salt": f"{encsalt}",
                        "vector": f"{vector}",
                        "secret_token": f"{secret_token}",
                        "role": "customer"  #create a JSON object that takes the sanitised and encrypted inputs and stores them in the database
                    }
                    try:
                            message = "Login information inserted successfully."
                            check = check_details(username, email)
                            if check == True:
                                    try:
                                        insert = db.Logins.insert_one(file)  #insert the JSON file into the database
                                        if insert:
                                            update_keys(username) #add this username to the list of login attempts that could occur
                                            k = db.Logins.find_one({"username": username})
                                            if k:
                                                token = k.get("secret_token")
                                                totp_auth = pyotp.totp.TOTP( 
                                                token).provisioning_uri( 
                                                name=username, 
                                                issuer_name='SecureCart')   #generate a new TOTP for 2fa authentication being used for this user
                                                base64_qr_image = get_b64encoded_qr_image(totp_auth) #get the qr code used to link the user to a 2fa secret via google authenticator
                                                request.session['username'] = username
                                                token = request.session[username]['otptoken']  #create a new token to get verified with and confirm that you have set up 2fa.
                                                context = {'qr': base64_qr_image, 'username': username, 'username2': username}
                                                logger.info(f"Account {username} created with 2fa enabled.")
                                                return render(request, "setup2fa.html", context)
                                            else:
                                                return render(request, "custlogin.html")
                                        else:
                                            logger.error(f"Unexpected database error occured when registering a new user.")
                                            return render(request, "registration.html", {'register_message': 'Server Side database error. Please retry.'})


                                    except Exception as e:
                                        return render(request, "registration.html", {'register_message': 'Unexpected error occured, please retry'})
                            else:
                                return render(request, "registration.html", {'register_message': f'Field in submission already in database'})
                    except Exception as e:
                        return render(request, "registration.html", {'register_message': f'{e}'})
                else:
                    return render(request, "registration.html", {'register_message': f'Password strength not correct you are missing: {strengthmessage}'})

            else:
                return render(request, "registration.html", {'register_message': 'passwords dont match'})
        else:  #similar but without the need for 2fa
            if repeatpassword == password:
                passw, strengthmessage = password_check(password)
                if passw:
                    salt = generate_salt()
                    hashed = create_hash(password, salt)
                    clean_hash = hashed.decode('utf-8')
                    encsalt, vector = encrypt_salt(username, salt)
                    encnumber = encrypt_customers(username, phone_number, vector)
                    encaddress = encrypt_customers(username, address, vector)
                    secret_token = "no"
                    file = {
                        "username": f"{username}",
                        "password": f"{clean_hash}",
                        "email": f"{email}",
                        "address": f"{encnumber}",
                        "phone_number": f"{encaddress}",
                        "salt": f"{encsalt}",
                        "vector": f"{vector}",
                        "secret_token": f"{secret_token}",
                        "role": "customer"
                    }
                    try:
                        check = check_details(username, email)
                        if check == True:
                            insert = db.Logins.insert_one(file)
                            update_keys(username)  #update the login attempts
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
                return render(request, "registration.html", {'register_message': 'Passwords dont match'})     #exception handling here.
    else:
        return render(request, "registration.html", {'register_message': 'error, passwords not correct length'})
     
def registration(request): 
    try:
        username2 = request.session['username']
        basket = request.session['baskets'][username2]
        equation = 0
        for usbskt2 in basket:  #request to the register page and calculate things like current items in basket and store the current user logged in.
            equation += usbskt2['qnt']
        context = {'username': username2, 'user_basket_count': equation}
        return render(request, "registration.html", context)
    except Exception as e:
        return render(request, "registration.html")

        
def add1item(request, product_name):
    try: 
        username = request.session['username']
        basket = request.session['baskets'][username]
        if (usbskt['name'] == product_name in basket for usbskt in basket):  #if the product to be increased is within the basket for that specific user..
            for usbskt in basket:
                db = get_db()
                check = db.Products.find_one({"productName": usbskt['name']})  #does this product exist under the database with that name being passed into the method.
                grab = check.get("productStock")  #grab the stock to check whether more of that product should be able to be added to the basket
                if usbskt['name'] == product_name:
                    if usbskt['qnt'] < grab:
                        usbskt['qnt'] += 1  #increment the quantity of the product in the basket session object.
                        request.session['baskets'][username] = basket
                        request.session.modified = True  #update the session object to adjust for this.
                        context2 = {'products': basket}
                        finalprice = 0
                        equation = 0
                        for usbskt2 in basket:
                            wanyama = float((usbskt2['price']))
                            price_prod  = usbskt2['qnt'] * wanyama
                            finalprice += price_prod  #calculate the total price of all the products and quantities that determines a final price after this change.
                        for usbskt2 in basket:
                            equation += usbskt2['qnt']
                        context3 = {'productquery': context2, "user_basket_count": equation,  'username': username, 'total_price': finalprice}
                        return render(request, "basket.html", context3)
                    elif usbskt['qnt'] >= grab:  #if you cannot add anymore, ignore this input and just return the page without an incremenet.
                        context2 = {'products': basket}
                        finalprice = 0
                        equation = 0
                        for usbskt2 in basket:
                            wanyama = float((usbskt2['price']))
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
        if (usbskt['name'] == product_name in basket for usbskt in basket):  #does this product exist under the database with that name being passed into the method.
            for usbskt in basket:
                if usbskt['name'] == product_name:
                    usbskt['qnt'] -= 1  #decrement the quantity being selected by a user for that product in the basket session object
                    if usbskt['qnt'] == 0:
                        basket.remove(usbskt)  #if this quantity hits zero remove it, user doesnt want the product anymore
                        request.session['baskets'][username] = basket
                        request.session.modified = True
                        context2 = {'products': basket}
                        finalprice = 0
                        equation = 0
                        for usbskt2 in basket:
                            wanyama = float((usbskt2['price']))
                            price_prod  = usbskt2['qnt'] * wanyama
                            finalprice += price_prod  #calculate total price based on quantity and price of each product in the session
                        for usbskt2 in basket:
                            equation += usbskt2['qnt']
                        context3 = {'productquery': context2, "user_basket_count": equation,  'username': username, 'total_price': finalprice}
                        return render(request, "basket.html", context3)
                    else:
                        context2 = {'products': basket}
                        finalprice = 0
                        equation = 0
                        for usbskt2 in basket:
                            wanyama = float((usbskt2['price']))
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
    del request.session['baskets'][username]  #delete the basket session for the user, remove all products that were stored
    request.session.modified = True
    create_basket(request, request.session)  #create a new basket, in case a user wants to start shopping again.
    context3 = {"user_basket_count": equation, 'username': username}
    return render(request, "basket.html", context3)

def basket(request): 
    try:
        username = request.session['username']
        basket = request.session['baskets'][username]
        context2 = {'products': basket}  #request to the basket page and calculate things like current items in basket and store the current user logged in.
        finalprice = 0
        equation = 0
        for usbskt2 in basket:
            wanyama = float((usbskt2['price']))
            price_prod  = usbskt2['qnt'] * wanyama
            finalprice += price_prod    #calculate total price based on quantity and price of each product in the session
        for usbskt2 in basket:
            equation += usbskt2['qnt']
        context3 = {'productquery': context2, "user_basket_count": equation,  'username': username, 'total_price': finalprice}
        return render(request, "basket.html", context3) 
    except Exception as e:
        equation = 0
        context3 = {"user_basket_count": equation}
        return render(request, "custlogin.html", context3)    

    #

def add_to_cart(request): 
    try:
        if request.session['username'] != None:
            username = request.session['username']
            basket = request.session['baskets'][username]
            db = get_db()
            name = sanitise_input(request.POST.get('product_name'))
            image = sanitise_input(request.POST.get('product_image'))
            price = sanitise_no(request.POST.get('product_price'))  #take in inputs for the product to add
            product = {"name": name,
            "price": price,
            "image": image,
            "qnt": 1}
            in_basket = False
            for usrbskt in basket:  #calculate total price based on quantity and price of each product in the session
                check = db.Products.find_one({"productName": product['name']})  #does the product that has been selected exist for the values given in the database?
                grab = check.get("productStock")
                if product['name'] == usrbskt['name']:
                    in_basket = True
                    if usrbskt['qnt'] < grab:  #provided there is still stock of this product avaliable..
                        usrbskt['qnt'] += 1  #increment the quantity in the basket session of this object
                    elif usrbskt['qnt'] >= grab:
                        equation = 0
                        for usbskt2 in basket:
                            equation += usbskt2['qnt']    #recalculate basket quantity now that a product has been added to the cart.
                        request.session['baskets'][username] = basket
                        request.session.modified = True
                        userproducts = list(db.Products.find({}))
                        context2 = {'products': userproducts}
                        context3 = {'productquery': context2, 'Update_Message': 'Cannot add anymore stock of this product', "user_basket_count": equation , "username": username}
                        return render(request, "products.html", context3)  
            if not in_basket:
                basket.append(product)  #if when adding its not already in the basket yet, create a new value that encompasses the values needed for tracking of price and quantity
            request.session['baskets'][username] = basket
            request.session.modified = True
            equation = 0
            for usbskt2 in basket:
                equation += usbskt2['qnt']  
            userproducts = list(db.Products.find({}))
            context2 = {'products': userproducts}
            context3 = {'productquery': context2, 'Update_Message': None, "user_basket_count": equation , "username": username}
            return render(request, "products.html", context3)
        else:  #exception handling
            db = get_db()
            userproducts = list(db.Products.find({}))
            context2 = {'products': userproducts}
            context3 = {'productquery': context2, 'Update_Message': "No user logged in", "username": username}
            return render(request, "products.html", context3)
    except Exception as e:
        db = get_db()
        userproducts = list(db.Products.find({}))
        context2 = {'products': userproducts}
        context3 = {'productquery': context2, 'Update_Message': "No user logged in"}
        return render(request, "products.html")

def payment(request): 
    try:
        username = request.session['username']
        basket = request.session['baskets'][username]
        context2 = {'products': basket}
        finalprice = 0
        equation = 0
        for usbskt2 in basket:
            wanyama = float((usbskt2['price']))
            price_prod  = usbskt2['qnt'] * wanyama
            finalprice += price_prod    #calculate the final price based on quantity and price of all the products from the basket session
        for usbskt2 in basket:
            equation += usbskt2['qnt']
        if basket != []:  #provided the basket is NOT empty
            context3 = {"user_basket_count": equation,  'username': username, 'total_price': finalprice}
            return render(request, "purchase.html", context3) 
        else:  #redirect user to actually buy something yknow
            userproducts = list(db.Products.find({}))
            context2 = {'products': userproducts}
            context3 = {'productquery': context2, "user_basket_count": equation,  'username': username, 'total_price': finalprice}
            return render(request, "products.html", context3) 
    except Exception as e:
        equation = 0
        context3 = {"user_basket_count": equation}
        return render(request, "purchase.html", context3)  

def paynow(request):
    try:
        db = get_db()
        data = request.POST
        accno = sanitise_input(data.get('accountno'))
        price = sanitise_input(data.get('pricey'))
        cvv = sanitise_input(data.get('cvv2'))
        expiry = sanitise_input(str(data.get('expiry')))
        shipping_address = sanitise_input(data.get('address'))
        cityortown = sanitise_input(data.get('citytown'))
        sortcode = sanitise_input(data.get('sortcode'))  #get all the details and sanitize them for insertion into the database
        houseno = sanitise_input(data.get('houseno'))
        postcode = sanitise_input(data.get('postcode'))
        country = sanitise_input(data.get('country'))
        username = request.session['username']
        basket = request.session['baskets'][username]
        exists = db.Logins.find_one({"username": f"{username}"})  #does the user making this payment exist
        if exists and card_check(sortcode, accno, cvv, expiry):  #are card details in a valid format for each submission field
            vector = exists.get("vector")
            email = exists.get("email")
            current_datetime = datetime.datetime.now()
            thedate = current_datetime.date().strftime(
            '%d/%m/%Y')  #grab and apply the date and time
            thetime = current_datetime.time().strftime('%H:%M:%S')
            thedatetime = f"{thedate} {thetime}"  #format the time to be more efficent for tracking orders for non repudation
            prodstring = ""
            for item in basket:  #create a string that lists the details of the order that is being created.
                prodstring += ' Product:' + " " + item['name'] + " " + 'x' + " " + str(item['qnt']) + " " #list of products inside an orders file.
            file = {
                    "username": f"{username}",
                    "products": f"{prodstring}",
                    "status": 'Order confirmed',
                    "timestamp": f"{thedatetime}",
                    "house_number": f"{houseno}",
                    "address": f"{shipping_address}",
                    "citytown": f"{cityortown}",
                    "postcode": f"{postcode}",
                    "country": f"{country}",
                    "email": f"{email}"
            }
            stripe.api_key = settings.STRIPE_SECRET_KEY
            insert = db.Orders.insert_one(file)  #insert the details that confirm a new order in the 
            expiry.split('/')
            stripeinsert = create_stripe_order(price, prodstring, username)
            if stripeinsert == True and insert:  
                for item in basket:
                    check = db.Products.find_one({"productName": item['name']})  #find the product and get its stock for every product in the basket
                    grab = check.get("productStock")
                    db.Products.update_one(
                        {"productName": item['name']},  
                        {"$inc": {"productStock": -item['qnt']}}  #reduce the product stock for each item that was purchased based on the quantity value from the basket session
                    )
                basket.clear()  #reset the basket for continued shopping without leftovers
                request.session['baskets'][username] = basket
                request.session.modified = True
                orders = list(db.Orders.find({"username": username}))
                context2 = {'orderquery': orders}
                logger.info(f"Payment from {username} approved for {prodstring}.")
                context3 = {'orderquery': context2, 'username': request.session['username']}
                return render(request, "home.html", context3)
            else:
                context2 = {'products': basket}
                finalprice = 0
                equation = 0
                for usbskt2 in basket:
                    wanyama = float((usbskt2['price']))
                    price_prod  = usbskt2['qnt'] * wanyama  #recalculate and dont reset the basket as an error has occured here.
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
                wanyama = float((usbskt2['price']))
                price_prod  = usbskt2['qnt'] * wanyama
                finalprice += price_prod  
            for usbskt2 in basket:
                equation += usbskt2['qnt']
            context3 = {"user_basket_count": equation,  'username': username, 'total_price': finalprice, 'purchase_message': "Card or user Information invalid"} 
            return render(request, "purchase.html", context3)    
    except Exception as e:  #exception handling.
        return render(request, "custlogin.html", {'login_message': 'Please login before you pay'})

def add_product(request):
    username = request.session['username']  
    if role_check(username): #check that the user executing this command is authorized to do so.
        data = request.POST
        db = get_db()
        name = sanitise_input(data.get('productname'))
        image = sanitise_input(data.get('imagefilename'))
        stock = sanitise_no(data.get('productstock'))
        price = sanitise_no(data.get('productprice'))
        desc = sanitise_input(data.get('productdesc'))  
        price2 = float(price)
        stock2 = int(stock)  #convert inputted values into the values needed for storage, change data types.
        file = {
                    "productName": f"{name}",
                    "productImage": f"{image}",
                    "productStock": int(f"{stock2}"),
                    "productPrice": float(f"{price2}"),
                    "productDesc": f"{desc}"
                }
        insert = db.Products.insert_one(file)
        if insert:
            create_stripe_product(name, price, desc)  #create a stripe product on the dashboard based on these inputs
            userquery = list(db.Logins.find({}))
            userproducts = list(db.Products.find({}))
            orders = list(db.Orders.find({}))
            context= {'users': userquery}
            context2 = {'products': userproducts}
            logger.info(f"New product {name} added to avaliable products.")  #logging to confirm an action has been completed
            context3 = {'productquery': context2, 'userquery': context, 'username': username, 'Update_Message': f"Successfully added {name} to Products!", 'orderquery': orders}
            return render(request, "adminpanel.html", context3)
    else:
        return HttpResponse(status=403)

def cancelorder(request):
    post = request.POST
    prodlist = post.get('prodlist')
    try:
        if request.session['username'] is None:  #checks a user is authenticated to cancel an order, prevent csrf. 
            return render(request, "custlogin.html", {'login_message': 'Please login before cancelling order'})
        else:
            db = get_db()
            username = request.session['username']
            basket = request.session['baskets'][username]
            equation = 0
            for usbskt2 in basket:
                equation += usbskt2['qnt']
            db.Orders.delete_one({"products": prodlist})  #search for the productlist string and delete the value that matches what order value was entered
            orders = list(db.Orders.find({"username": username}))
            statusorder = value_grab(orders)  
            logger.info(f"Order from {username} cancelled for {prodlist}.")
            context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation, 'account_message': f"Successfully deleted {prodlist} for {username}", "statuslist": statusorder}
            return render(request, "account.html", context3)
    except Exception as e:  #for if the prodlist cannot be found.
        username = request.session['username']
        equation = 0
        for usbskt2 in basket:
            equation += usbskt2['qnt']
        orders = list(db.Orders.find({"username": username}))
        statusorder = value_grab(orders)
        context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation, "account_message": "Error deleting this try again.", "statuslist": statusorder}
        return render(request, "account.html", context3)

def logout(request):
    try:
        username = request.session['username']
        logger.info(f"{username} has logged out of the site.")
        request.session.flush()  #remove all session objects and delete all details before returning to the home page.
        return render(request, "home.html")
    except Exception as e:
         return render(request, "home.html")           

def account(request):
    try:
        if request.session['username'] is None:
            return HttpResponse(status=403)   #ensures user is authenticated.
        else:
            username = request.session['username']
            basket = request.session['baskets'][username]  #request for an account page that finds all the information regarding the user that is currently logged in and the status of all that users orders
            equation = 0
            for usbskt2 in basket:
                equation += usbskt2['qnt']
            orders = list(db.Orders.find({"username": username}))
            statusorder = value_grab(orders)  #grab and assign numerical values for each order based on the status thats been assigned to each.
            context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation, "statuslist": statusorder }
            return render(request, "account.html", context3)
    except Exception as e:
        return render(request, "custlogin.html", {'login_message': 'Please login first'})
    
def change_pass(request):
    try:
        data = request.POST
        username = request.session['username']
        db = get_db()
        if username == sanitise_input(data.get('username')):
            data = request.POST
            username = sanitise_input(data.get('username'))
            if sanitise_input(data.get('newpass')):
                newpass = sanitise_input(data.get('newpass'))
                repeatnew = sanitise_input(data.get('repeatnew'))
                userfind = db.Logins.find_one({"username": username})
                if userfind:
                    correct_length = check_password(newpass) 
                    passw, strengthmessage = password_check(newpass)
                    if correct_length and passw != False: #is the new password suitably strong to be used as a new password?
                        if newpass == repeatnew:  #do the passwords match?
                            salt = generate_salt()
                            hashed = create_hash(newpass, salt)
                            clean_hash = hashed.decode('utf-8')
                            encsalt, victor = encrypt_salt(username, salt)  #create a new hash, salt and encrypt the salt to secure it from anyone being able to recreate a users password
                            update = {
                            "salt": encsalt,
                            "vector": victor,
                            "password": clean_hash,

                            }
                            update = db.Logins.update_one(
                            {"username": username}, 
                            {"$set": update}    #update the values in the database with the new vector (used in the enc algorithm), the new password and the new salt that is encrypted  
                            )
                            basket = create_basket(request, request.session, username)  #create a new basket for this user
                            if update:
                                username = request.session['username']
                                basket = request.session['baskets'][username]
                                equation = 0
                                for usbskt2 in basket:
                                    equation += usbskt2['qnt']
                                orders = list(db.Orders.find({"username": username}))
                                statusorder = value_grab(orders)
                                logger.info(f"{username}'s password has been updated to a new value.")
                                context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation, "account_message": "Password updated!", "statuslist": statusorder }
                                return render(request, "account.html", context3)  #send to the users account and alert that the password has been changed.
                            else:
                                equation = 0
                                basket = request.session['baskets'][username]
                                orders = list(db.Orders.find({"username": username}))
                                statusorder = value_grab(orders)
                                context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation, "account_message": "Passwords do not match, retry", "statuslist": statusorder }
                                return render(request, "changepass.html", context3)
                                  #exception handling for if this fails for some reason  
                        else:
                            equation = 0
                            orders = list(db.Orders.find({"username": username}))
                            logger.error(f"Failed password change for {username}.")
                            statusorder = value_grab(orders)
                            context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation, "change_error": "Passwords do not match, retry", "statuslist": statusorder }
                            return render(request, "changepass.html", context3)
                    else:
                        equation = 0
                        orders = list(db.Orders.find({"username": username}))
                        logger.error(f"Failed password change for {username}.")
                        statusorder = value_grab(orders)  #grab and assign numerical values for each order based on the status thats been assigned to each.
                        context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation, "change_error": "Passwords do not match or are not strong enough.", "statuslist": statusorder }
                        return render(request, "changepass.html", context3)
                else:
                    equation = 0
                    for usbskt2 in basket:
                        equation += usbskt2['qnt']
                    orders = list(db.Orders.find({"username": username}))
                    statusorder = value_grab(orders) #grab and assign numerical values for each order based on the status thats been assigned to each.
                    logger.error(f"User {request.session['username']} attempted to change account password that wasn't them.")
                    context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation, "account_message": "User attempted to change password for not their account.", "statuslist": statusorder }
                    return render(request, "custlogin.html", context3)   
            else:
                basket = request.session['baskets'][username]
                equation = 0
                for usbskt2 in basket:
                    equation += usbskt2['qnt']
                orders = list(db.Orders.find({"username": username}))
                statusorder = value_grab(orders)
                context3 = {'orderquery': orders, 'username': username, 'user_basket_count': equation, "account_message": "New password isn't strong enough.", "statuslist": statusorder }
                return render(request, "changepass.html", context3) 
        else:
            equation = 0
            context3 = {"login_message": "Please login before trying to change your pass"}
            return render(request, "custlogin.html", context3)    
           
    except Exception as e:
        equation = 0
        context3 = {"login_message": "Please login before trying to change your pass"}
        return render(request, "custlogin.html", context3)

def add_stock(request): 
    username2 = request.session['username']
    falsehood = role_check(username2)  #role check to ensure only admins can add stock to the product 
    if falsehood:
        data = request.POST
        db = get_db()
        name = sanitise_input(data.get('productname'))
        no = sanitise_input(data.get('stocknumber'))  
        if db.Products.find_one({"productName": name}):  #ensure the product is valid before inserting, make sure that it exists
            result = db.Products.update_one({'productName': name},  
            {'$inc': {'productStock': int(no)}})  #increment that products stock with the numerical input to update the quantity
            userquery = list(db.Logins.find({}))
            userproducts = list(db.Products.find({}))
            orderquery = list(db.Orders.find({}))
            context= {'users': userquery}
            context2 = {'products': userproducts}
            logger.info(f"Product {name} has had its stock increased by {no}.")  #confirm and output that the stock was updated successfully
            context3 = {'productquery': context2, 'userquery': context, 'orderquery': orderquery, 'username': username2, 'Update_Message': f"Successfully added {no} to {name}!"}
            return render(request, "adminpanel.html", context3)
        else:  #handle not being able to find a product that can be updated
            userquery = list(db.Logins.find({}))
            userproducts = list(db.Products.find({}))
            orderquery = list(db.Orders.find({}))
            context= {'users': userquery}
            context2 = {'products': userproducts}
            context3 = {'productquery': context2, 'userquery': context, 'orderquery': orderquery, 'username': name, 'Update_Message': f"Product {name} not found!"}
            return render(request, "adminpanel.html", context3)
    else:
        return HttpResponse(status=403)  #return restriction if user is not an admin

def change_role(request):
    username = request.session['username']
    if role_check(username):
        if role_check2(username):  #ensure an ADMIN ONLY can change a role in the database.
            db = get_db()
            data = request.POST
            userindex = sanitise_input(data.get('changeuser'))
            role = sanitise_input(data.get('something'))
            if db.Logins.find_one({"username": userindex}):
                result = db.Logins.update_one({'username': userindex},  
                {"$set": {"role": role}})  #change the role value associated with the user to the role that has been inputted
                userquery = list(db.Logins.find({}))
                userproducts = list(db.Products.find({}))
                context= {'users': userquery}
                context2 = {'products': userproducts}
                orders = list(db.Orders.find({}))
                logger.critical(f"{username} has had his role changed to {role}")  #alert that the user has been changed in their role.
                context3 = {'productquery': context2, 'orderquery': orders, 'userquery': context, 'username': username, 'Update_Message': f"Successfully updated {userindex} to {role}"}
                return render(request, "adminpanel.html", context3)
            else:  #handle the incident where the user cannot be updated or found
                userquery = list(db.Logins.find({}))
                userproducts = list(db.Products.find({}))
                context= {'users': userquery}
                context2 = {'products': userproducts}
                orders = list(db.Orders.find({}))
                context3 = {'productquery': context2, 'orderquery': orders, 'userquery': context, 'username': username, 'Update_Message': f"Username not found in the database."}
                return render(request, "adminpanel.html", context3)
        else:
            db = get_db()
            userquery = list(db.Logins.find({}))
            userproducts = list(db.Products.find({}))
            orders = list(db.Orders.find({}))
            context= {'users': userquery}
            context2 = {'products': userproducts}
            logger.critical(f"{username} attempted to use moderator powers to make someone an admin. This is not allowed.")  #rbac check invalidation if user doesnt have the required role.
            context3 = {'productquery': context2, 'userquery': context, 'orderquery': orders, 'username': username, 'Update_Message': f"Moderators cannot change roles."}
            return render(request, "adminpanel.html", context3)
    else:
        logger.critical(f"{username} attempted to perform an action they were not authorised to do.")
        return HttpResponse(status=403)  #return a restriction if the user is not admin or mod
    

def value_grab(orders):
    statuses = [order['status'] for order in orders]  #look at all the statuses in the database for every order thats listed
    statusorder = []
    for status in statuses:
        if status == "Order confirmed":
            value = 0
            statusorder.append({"value": value})
        if status == "Left the warehouse":  #these numerical values are used to assign value to a progress bar that indicates how complete orders are based on a database status enum
            value = 35
            statusorder.append({"value": value})
        if status == "Dispatched to courier":
            value = 65
            statusorder.append({"value": value})
        if status == "Out for delivery":
            value = 100
            statusorder.append({"value": value})
    return statusorder

db = get_db()
usr_list = db.Logins.find({}, {"username": 1, '_id': 0})  #find all usernames being used in the system
global login_attempts  #global variable to access these attempts from many places in the application
usernames = [user['username'] for user in usr_list]
login_attempts = dict.fromkeys(
    usernames, 0)  #create a dict object that has a key pair of the number of attempts done by a user
