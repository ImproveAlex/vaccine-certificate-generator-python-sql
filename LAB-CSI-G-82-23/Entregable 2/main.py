from datetime import datetime
import sqlite3
from typing import Optional
from fpdf import FPDF
import re
import datetime
from password_validator import PasswordValidator
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

class cryptography:
    def __init__(self)-> None:
        pass

    def generateKey(self, passw, random = None):
        if random == None:
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=320000,
                )
            key = base64.urlsafe_b64encode(kdf.derive(passw.encode('utf-8')))
            return (salt, key)
        else:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=random,
                iterations=320000,
                )
            key = base64.urlsafe_b64encode(kdf.derive(passw.encode('utf-8')))
            return (key)

        
    def encryption(self, key, msg):
        f = Fernet(key)
        e_msg = f.encrypt(msg.encode('utf-8'))
        return e_msg

    def decryption(self, key, e_msg):
        f = Fernet(key)
        msg = f.decrypt (e_msg)
        msg = msg.decode('utf-8')
        return msg


    def keyEncryptionMasterPassword(self, salt, user_key, password='zKGx#RB7wcRxZBAM'):
        key = self.generateKey (password, salt)
        encypted_key = self.encryption(key, user_key.decode('utf-8'))
        return(encypted_key)

    def keyDecryptionMasterPassword(self, salt, user_key, password='zKGx#RB7wcRxZBAM'):
        key = self.generateKey (password, salt)
        decrypted_key = self.decryption(key, user_key)
        return(decrypted_key.encode('utf-8'))

    def GenerateCSR(self):
        # Generate our key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # Write our key to disk for safe keeping
        with open(r"C:\Games\invento\key.pem", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
            ))
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"THE_COVID_CERTIFICATE_ORGANIZATION"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for 90 days
            datetime.datetime.utcnow() + datetime.timedelta(days=90)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        # Sign our certificate with our private key
        ).sign(key, hashes.SHA256())
        # Write our certificate out to disk.
        with open(r"C:\Games\invento\certificate.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
                    
                

class PdfGenerator:
    def __init__(self) -> None:
        self.pdf = FPDF()
        self.pdf.add_page()
        self.count = 15.0
    
    def add_title(self, title: str):
        self.add_line(title, 0.0, 18, 'B', 'C', 0)
    
    def add_subtitle(self, title: str):
        self.add_line(title, self.count, 14, 'B', 'L')
        self.count+=8
    
    def add_text(self, text: str):
        self.add_line(text, self.count, 12, '', 'L')
        self.count+=8

    def add_line(self, text: str, y: float, font_size: int, font_type: str, align: str, x = 10.0):
        self.pdf.set_xy(x, y)
        self.pdf.set_font('Times', font_type, font_size)
        self.pdf.set_text_color(0, 0, 0)
        self.pdf.cell(w=210.0, h=40.0, align=align, txt=text, border=0)

    def generate(self, id: str):
        self.pdf.output('{}.pdf'.format(id))

class App:
    def __init__(self) -> None:
        self.conn = sqlite3.connect("data.db")
        self.master_salt = self.conn.execute ("SELECT * FROM salt LIMIT 1").fetchone()[0] 
        self.crypt = cryptography()
        self.salt = None 
        self.key = None

    def login(self, dni: str, u_key):
        e_key = self.get_data('users',dni)[0][7]
        d_key = self.crypt.keyDecryptionMasterPassword(self.master_salt, e_key)
        if d_key == u_key:
            return True
        else:
            return False

    def create_user(self, dni: str, password, name: str, surname: str, date_of_birth: str, role: str, address: str):
        salt , key = self.crypt.generateKey(password)
        e_name = self.crypt.encryption(key, name)
        e_surname = self.crypt.encryption(key, surname)
        e_date_of_birth = self.crypt.encryption(key, date_of_birth)
        e_role = self.crypt.encryption(key, role)
        e_address = self.crypt.encryption(key, address)
        ekey = self.crypt.keyEncryptionMasterPassword(self.master_salt, key)
        self.conn.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (dni, salt, e_name, e_surname, e_date_of_birth, e_role, e_address, ekey))
        self.conn.commit()
    
    def add_covid_vaccine(self, dni: str, vaccine: str, date: str, password: str):
        e_u_key = self.get_data('users', dni)[0][7]
        user_key = self.crypt.keyDecryptionMasterPassword(self.master_salt, e_u_key, password)
        e_vaccine = self.crypt.encryption(user_key, vaccine)
        e_date = self.crypt.encryption(user_key, date)
        self.conn.execute("INSERT INTO covid_vaccines VALUES (?, ?, ?)",( dni, e_vaccine, e_date))
        self.conn.commit()

    def get_covid_certificate(self, dni: str):
        covid_vaccines = self.get_data('covid_vaccines', dni)[0]
        pdf = self.create_pdf_template('Covid Vaccines', dni)
        pdf.add_text('')
        pdf.add_subtitle('Covid-19 Vaccine:')
        fields = []
        for field in covid_vaccines:
            fields.append(field)
        for i in range(1, 3):
              fields[i] = self.crypt.decryption(self.key, fields[i])
        pdf.add_text('{} - {}'.format(fields[1], fields[2]))
        pdf.generate('covid_certificate_{}'.format(dni))

    def create_pdf_template(self, title: str, dni: str):
        user = self.get_data('users', dni)[0]
        fields = []
        for field in user:
            fields.append(field)
        for i in range(2, 7):
          fields[i] = self.crypt.decryption(self.key, fields[i])
        pdf = PdfGenerator()
        pdf.add_title('Covid-19 Vaccine Certificate')
        pdf.add_subtitle('Patient Info:')
        pdf.add_text('DNI: {}'.format(fields[0]))
        pdf.add_text('Name: {} {}'.format(fields[2], fields[3]))
        pdf.add_text('Date of Birth: {}'.format(fields[4]))
        pdf.add_text('Address: {}'.format(fields[6]))
        return pdf

    def check_covid_record(self, dni):
        try:
            data = self.get_data('covid_vaccines',dni)[0][0]
            if dni == data:
                print('Your Covid-19 information is in the data base')
                return
        except:
            print('No records found')
            return
        
        
    def get_data(self, table: str, dni: str):
        query = "SELECT * FROM {} WHERE dni =:dni".format(table)
        return self.conn.execute(query, { "dni": dni }).fetchmany()

    def check_option(self, option):
        if str.isdigit(option):
            return int(option)
        else:
            return option
    def get_key(self, dni, password):
        crpyt = cryptography()
        salt = self.get_data('users', dni)[0][1]
        key = crpyt.generateKey(password, salt)
        self.salt = salt
        self. key = key
        return key

def login(app: App):
    crypt = cryptography()
    while True:
        print('----------------------------------COVID CERTIFICATE GENERATOR----------------------------------\n')
        option = app.check_option(input('1. Login\n2. Register\n0. Exit\n\nEnter option: '))
        if option == 0:
            exit()
        elif option == 1:
            print('----------------------------------LOGIN----------------------------------\n')
            while True:
                dni = input('DNI: ')
                if len(dni)>8 and len(dni)<10:
                    break;
                print ('DNI must have 8 numbers and 1 letter')
            while True:  
                schema = PasswordValidator()
                schema.has().no().spaces()
                schema.has().symbols()
                password = input("Password: ")
                if len(password) < 8:
                    print("Make sure your password is at lest 8 letters")
                elif re.search('[0-9]',password) is None:
                    print("Make sure your password has a number in it")
                elif re.search('[a-z]',password) is None: 
                    print("Make sure your password has a lower case letter in it")    
                elif re.search('[A-Z]',password) is None: 
                    print("Make sure your password has a capital letter in it")
                elif schema.validate(password) is False:
                    print("Make sure your password has a symbol, no spaces allowed")
                else:
                    break
            key = app.get_key(dni, password)
            if app.login(dni, key):
                user = app.get_data('users', dni)
                user_t = user[0][5]
                user_t = crypt.decryption(key, user_t)
                return (user_t, dni)

            print('Incorrect login information')
        elif option == 2:
            create_user(app, 'patient')
        else :
            print('\nIncorrect option\n')

def patient_portal(app: App, dni: str):
    print('\n----------------------------PATIENT PORTAL----------------------------\n')
    while True:
        option = app.check_option(input('1. Generate covid certificate\n2. Check for covid records\n0. Exit\n\nEnter option: '))
        if option == 0:
            return
        elif option == 1:
            try: 
                app.get_covid_certificate(dni)
                print('\nCovid certificate generated\n')
            except:
                print('There is no Covid certificate for you')
        elif option == 2:
            app.check_covid_record(dni)
        else :
            print('\nIncorrect option\n')

def medic_portal(app: App):
    print('\n------------------------------MEDIC PORTAL------------------------------\n')
    while True:
        option = app.check_option(input('1. Create user\n2. Add vaccine to patient\n0. Exit\n\nEnter option: '))
        if option == 0:
            return
        elif option == 1:
            create_user(app, 'medic')
        elif option == 2:
            add_vaccine_to_patient(app)
        else:
            print('\nIncorrect option\n')

def create_user(app: App, user: str):
            if user == 'medic':
                print('\n------------------------------CREATE NEW USER------------------------------\n')
            elif user == 'patient':
                print('\n------------------------------REGISTER------------------------------\n')
            while True:
                dni = input('DNI: ')
                if len(dni)>8 and len(dni)<10:
                    break;
                print ('DNI must have 8 numbers and 1 letter')
            print('\n PLEASE MAKE SURE YOUR PASSWORD CONTAINS: \n\n - At least 8 characters—the more characters, the better.\n - A mixture of both uppercase and lowercase letters.\n - A mixture of letters and numbers. \n - Inclusion of at least one special character, e.g. , ! @ # ? )\n')    
            while True:  
                schema = PasswordValidator()
                schema.has().no().spaces()
                schema.has().symbols()
                password = input("Password: ")
                if len(password) < 8:
                    print("Make sure your password is at lest 8 letters")
                elif re.search('[0-9]',password) is None:
                    print("Make sure your password has a number in it")
                elif re.search('[a-z]',password) is None: 
                    print("Make sure your password has a lower case letter in it")    
                elif re.search('[A-Z]',password) is None: 
                    print("Make sure your password has a capital letter in it")
                elif schema.validate(password) is False:
                    print("Make sure your password has a symbol, no spaces allowed")
                else:
                    break
            while True:    
                name = input('Names: ')
                try:
                    name1, name2 = name.split(' ')
                    if str.isalpha(name1) and str.isalpha(name2):
                        break
                    print('Please enter a correct name, do dont include any number or symbols')
                except:
                    if str.isalpha(name):
                        break
                    print('Please enter a correct name, do dont include any number or symbols')
            while True:    
                surname = input('Surnames: ')
                try:
                    sur1, sur2 = surname.split(' ')
                    if str.isalpha(sur1) and str.isalpha(sur2):
                        break
                    print('Please enter a surname, do dont include any number or symbols')
                except:
                    if str.isalpha(surname):
                        break
                    print('Please enter a surname, do dont include any number or symbols')
            while True:   
                dob = input('Enter a date in DD/MM/YYYY format ')
                try:
                    day, month, year = dob.split('/')
                    datetime.datetime(int(year), int(month), int(day))
                    break
                except:
                    print("Invalid Date")

            if user == 'patient':
                role = 'patient'
            elif user == 'medic':
                while True:
                    role = input('Role: ')
                    if (role == "patient") or (role == "medic"):
                        break
                    print('Incorrect user the only valid users are patient or medic')
            address = input('Address: ')
            app.create_user(dni, password, name, surname, dob, role, address)
            print('\nUser created successfully\n')



def add_vaccine_to_patient(app: App):
    print('\n----------------------------ADD A VACCINE TO PATIENT--------------------------------\n')
    while True:
        dni = input('DNI: ')
        if len(dni)>8:
            break;
        print ('DNI must have at least 8 numbers and 1 letter')
    while True:     
                password = input("Itroduce the master password: ")
                if len(password) < 8:
                    print("Make sure your password is at lest 8 letters")
                elif re.search('[a-z]',password) is None: 
                    print("Make sure your password has a lower case letter in it")    
                elif re.search('[A-Z]',password) is None: 
                    print("Make sure your password has a capital letter in it")
                else:
                    break
        
    vaccines = [ "Other","Phizer","Modern", "Janssen", "AstraZenca"]
    while True:
        print ('\n Select a Vaccine:')
        option = app.check_option(input(' 1. Pfizer\n 2. Modern\n 3. Janssen\n 4. AstraZeneca\n 0. Other\n\nEnter option: '))
        try:
            vaccine = vaccines[option]
            break
        except:
            print('Invalid option')
    while True:
            date = input('Enter the date the patient got full vaccinated in DD/MM/YYYY format ')
            try:
                day, month, year = date.split('/')
                datetime.datetime(int(year), int(month), int(day))
                break
            except:
                print("Invalid Date")
    try:
        app.add_covid_vaccine(dni, vaccine, date, password)
        print('\nVaccine added successfully\n')
    except:
        print('\nCovid details already added or no patient in system\n')

def main():
    cryp = cryptography()
    cryp.GenerateCSR()
    app = App()
    [user_role, dni] = login(app)
    if user_role == 'medic':
        medic_portal(app)
    elif user_role == 'patient':
        patient_portal(app, dni)
    else:
        print('unknown user role')
main()