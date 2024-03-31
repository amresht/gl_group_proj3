# Importing necessary modules and libraries
from flask import Flask, jsonify, render_template, request,redirect,url_for,session,flash
from flask_sqlalchemy import SQLAlchemy
import numpy as np
import sklearn
import pickle
import bcrypt
import jwt
import datetime

# Creating a Flask application instance
app = Flask(__name__)
app.secret_key = 'assignment-3'
jwt_secret_key = 'givig-token-to-each-user'

# Loading a pre-trained machine learning model using pickle
model = pickle.load(open('model.pkl','rb'))

# Configuring the database connection URI and tracking modifications
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Tigers08#@localhost/loanpredictiondb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

# Creating a SQLAlchemy database instance
db = SQLAlchemy(app)

#blacklist to store invalidated tokens
blacklist = set()

# Define User model
class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), unique = True)
    password = db.Column(db.String(255))

    def __init__(self, username, password):
        self.username = username
        self.password = password
        
# Create the users table in the database
with app.app_context():
    db.create_all()

# Rendering Home page
@app.route('/')
def home():
    return render_template('home.html')

## Register API
@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST':
        try:
            # Get form data
            username = request.form['username']
            password = request.form['password']

            # Check if the username already exists
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                 return '''
                    <h1>Username Already Exists!</h1>
                    <button onclick="location.href='/register'">Register</button>
                    <button onclick="location.href='/login'">Login</button>
                '''

            # Hash the password using bcrypt
            hashed_pass = bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())

            # Create a new User object with hashed password
            new_user = User(username=username, password=hashed_pass)

            # Add the new user to the database
            db.session.add(new_user)
            db.session.commit()

            # Generate JWT token
            token = jwt.encode({'username': username}, app.secret_key, algorithm='HS256')
            # Redirect to the login page with success token
            return redirect(url_for('login', token=token))
        
        except Exception as e:
            return jsonify({'message': f'Error: {str(e)}'}), 500
    return render_template('register.html')

## Login API
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            #Get form data
            username = request.form['username']
            password = request.form['password']

            # Find the user by username
            user = User.query.filter_by(username=username).first()

            if user:
                # Check if pass matches
                if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):

                    # Set token expiration time (e.g., 1 hour from now)
                    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)

                    # Generate JWT token
                    token = jwt.encode({'username': username, 'exp': expiration_time},app.secret_key, algorithm='HS256')

                    # Store token in session
                    session['token'] = token
                    # Store username in session
                    session['username'] = username

                    # Redirect user to another page with token as query parameter
                    return redirect(url_for('predict', token=token))
                else:
                   return '''
                        <h1>Invalid username or password! Please enter correct details</h1>
                        <button onclick="location.href='/login'">Login</button>
                    '''
            else:
                return jsonify({'message': 'User not found'}), 404

        except Exception as e:
            return jsonify({'message': f'Error: {str(e)}'}), 500

    return render_template('login.html')

## Predict API
@app.route('/predict', methods=['GET', 'POST'])
def predict():
    token = None  # Initialize token variable
    if request.method == 'POST':
        try:
            # Retrieve the entered details from the form
            gender = int(request.form['gender'])
            married = int(request.form['married'])
            dependents = float(request.form['dependents'])
            education = int(request.form['education'])
            self_employed = int(request.form['self_employed'])
            applicant_income = int(request.form['applicant_income'])
            coapplicant_income = float(request.form['coapplicant_income'])
            loan_amount = float(request.form['loan_amount'])
            loan_amount_term = float(request.form['loan_amount_term'])
            credit_history = int(request.form['credit_history'])
            property_area = int(request.form['property_area'])

            # Retrieve username from session
            username = session.get('username')

            # Prepare the input for prediction
            input_data = [[gender, married, dependents,education, self_employed,  applicant_income,
                           coapplicant_income, loan_amount, loan_amount_term, credit_history, property_area]]
            
            # Make the prediction
            prediction = model.predict(input_data)

            # Process the prediction result
            if prediction == 1:
                output = "Congrats!! You are eligible for the loan."
            else:
                output = "Sorry, you are not eligible for the loan."

            # Set token expiration time (e.g., 1 hour from now)
            expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)

            # Generate JWT token
            token = jwt.encode({'username': username, 'exp': expiration_time},app.secret_key, algorithm='HS256')

            # Render the template with the prediction result and form data
            return render_template('predict.html', prediction=output, token=token )
        
        except Exception as e:
            return jsonify({'message': f'Error: {str(e)}'}), 500
        
    return render_template('predict.html', token=token)

# Logout API
# @app.route('/logout')
# def logout():
#     try:
#         session.pop('id', None)
#         session.pop('username', None)
#         print('logged out succesfully ')
#     except Exception as e:
#         # Handle the exception here, for example, you can log it
#         print(f"Error occurred while logging out: {e}")
#     return redirect('/')

@app.route('/logout')
def logout():
    try:
        # Retrieve token from session
        token = session.get('token')
        
        print("Token:", token)  # Debugging print
        
        # Check if token exists
        if token:
            # Verify JWT token
            decoded_token = jwt.decode(token, app.secret_key, algorithms=['HS256'])
            print("Decoded token:", decoded_token)  # Debugging print
            
            # Proceed with logout logic (e.g., remove session data)
            session.pop('token', None)
            # Proceed with logout logic (e.g., remove session data)
            session.pop('id', None)
            session.pop('username', None)
            print('Logged out successfully')
            return redirect('/')
        else:
            # If token is missing
            return jsonify({'error': 'Invalid or missing JWT token in the URL'}), 401
            
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Expired JWT token'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid JWT token'}), 401
    except Exception as e:
        # Handle other exceptions
        return jsonify({'error': f'Error occurred: {e}'}), 500
    
with app.app_context():
    db.session.commit()

# Running the Flask application in debug mode
if __name__ == "__main__":
    app.run(debug=True)