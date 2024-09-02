from datetime import datetime
import sqlite3
from fpdf import FPDF

class PdfGenerator:
    def __init__(self) -> None:
        self.pdf = FPDF()
        self.pdf.add_page()
        self.count = 15.0
    
    def add_title(self, title: str):
        self.add_line(title, 0.0, 18, 'B', 'C')
    
    def add_subtitle(self, title: str):
        self.add_line(title, self.count, 14, 'B', 'L')
        self.count+=8
    
    def add_text(self, text: str):
        self.add_line(text, self.count, 12, '', 'L')
        self.count+=8

    def add_line(self, text: str, y: float, font_size: int, font_type: str, align: str):
        self.pdf.set_xy(10.0, y)
        self.pdf.set_font('Times', font_type, font_size)
        self.pdf.set_text_color(0, 0, 0)
        self.pdf.cell(w=210.0, h=40.0, align=align, txt=text, border=0)

    def generate(self, id: str):
        self.pdf.output('{}_{}.pdf'.format(id, datetime.today().strftime('%Y_%m_%d')))

class App:
    def __init__(self) -> None:
        self.conn = sqlite3.connect("data.db")
    
    def login(self, dni: str, password: str) -> bool:
        user = self.conn.execute("SELECT COUNT(dni) FROM users WHERE dni =:dni AND password=:password LIMIT 1",
            {"dni": dni, "password": password }).fetchone()
        return user[0] == 1

    def create_user(self, dni: str, password: str, name: str, surname: str, date_of_birth: str, role: str, address: str):
        self.conn.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)",
            (dni, password, name, surname, date_of_birth, role, address))
        self.conn.commit()
    
    def add_register(self, table: str, dni: str, value1: str, value2: str = None, value3: str = None):
        user = self.conn.execute("SELECT COUNT(dni) FROM users WHERE dni =:dni",{"dni": dni }).fetchone()
        if user[0] == 1:
            query = "INSERT INTO {} values ('{}','{}')".format(table, dni, value1)
            if table == "covid_vaccines":
                query = "INSERT INTO {} values ('{}','{}','{}')".format(table, dni, value1, value2)
            elif table == "registers":
                query = "INSERT INTO {} values ('{}','{}','{}','{}')".format(table, dni, value1, value2, value3)
            self.conn.execute(query)
            self.conn.commit()
    
    def get_medical_history(self, dni: str):
        registers = self.get_data('registers', dni)
        allergies = self.get_data('allergies', dni)
        antecedents_inherited = self.get_data('antecedents_inherited', dni)
        diseases = self.get_data('diseases', dni)
        pdf = self.create_pdf_template('Medical History', dni)
        pdf.generate('medical_history_{}'.format(dni))

    def get_covid_certificate(self, dni: str):
        covid_vaccines = self.get_data('covid_vaccines', dni)
        pdf = self.create_pdf_template('Covid Vaccines', dni)
        pdf.add_subtitle('Covid Vaccines')
        for vaccine in covid_vaccines:
            pdf.add_text('{} - {}'.format(vaccine[1], vaccine[2]))
        pdf.generate('covid_certificate_{}'.format(dni))

    def create_pdf_template(self, title: str, dni: str):
        user = self.get_data('users', dni)[0]
        pdf = PdfGenerator()
        pdf.add_title('Covid Vaccines')
        pdf.add_subtitle('Patient Info:')
        pdf.add_text('DNI: {}'.format(user[0]))
        pdf.add_text('Name: {} {}'.format(user[2], user[3]))
        pdf.add_text('Date of Birth: {}'.format(user[4]))
        pdf.add_text('Address: {}'.format(user[6]))
        return pdf

    def get_data(self, table: str, dni: str):
        query = "SELECT * FROM {} WHERE dni =:dni".format(table)
        return self.conn.execute(query, { "dni": dni }).fetchmany()

def login(app: App):
    while True:
        dni = input('DNI: ')
        password = input('password: ')
        if app.login(dni, password):
            return (app.get_data('users', dni)[0][5], dni)
        print('Incorrect login information')

def patient_portal(app: App, dni: str):
    print('\nPatient portal')
    while True:
        option = int(input('1. Generate covid certificate\n0. Exit\n\nEnter option: '))
        if option == 0:
            return
        elif option == 1:
            app.get_covid_certificate(dni)
            print('\nCovid certificate generated\n')
        else:
            print('\nUnknown option\n')

def medic_portal(app: App):
    print('\nMedic portal')
    while True:
        option = int(input('1. Create user\n2. Add vaccine to patient\n0. Exit\n\nEnter option: '))
        if option == 0:
            return
        elif option == 1:
            create_user(app)
        elif option == 2:
            add_vaccine_to_patient(app)
        else:
            print('\nUnknown option\n')

def create_user(app: App):
    print('\nNew user\n')
    dni = input('DNI: ')
    password = input('password: ')
    name = input('name: ')
    surname = input('surname: ')
    dob = input('date of birth: ')
    role = input('role: ')
    address = input('address: ')
    app.create_user(dni, password, name, surname, dob, role, address)
    print('\nUser created successfully\n')

def add_vaccine_to_patient(app: App):
    print('\nAdd vaccine to patient\n')
    dni = input('DNI: ')
    vaccine = input('vaccine: ')
    date = input('date: ')
    app.add_register('covid_vaccines', dni, vaccine, date)
    print('\nVaccine added successfully\n')

def main():
    app = App()
    [user_role, dni] = login(app)
    if user_role == 'medic':
        medic_portal(app)
    elif user_role == 'patient':
        patient_portal(app, dni)
    else:
        print('unknown user role')

main()