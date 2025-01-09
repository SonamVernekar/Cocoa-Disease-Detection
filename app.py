from flask import Flask, render_template, request, redirect, url_for, flash, session,jsonify
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt

from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing import image
import numpy as np
from io import BytesIO
import os
import http.client
import json
import bcrypt  as bc
from googletrans import Translator 



app = Flask(__name__)
app.secret_key = 'zmdb'

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''  # Set your MySQL password here
app.config['MYSQL_DB'] = 'cocoa'

mysql = MySQL(app)
bcrypt = Bcrypt(app)


model = load_model('model.keras')


# Define the uploads folder
UPLOAD_FOLDER="static/uploads"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER




def send_admin_notification(farmer_id, image_path, predicted_class, confidence_level):
    try:
        # Create a cursor for executing queries
        cursor = mysql.connection.cursor()

        # Create message for notification
        message = (f"Low confidence level: {confidence_level:.2f}% for uploaded image. "
                   f"Predicted class: {predicted_class}.")

        # Insert notification into the database
        sql = ("INSERT INTO notifications (farmer_id, image, message, status) "
               "VALUES (%s, %s, %s, %s)")
        cursor.execute(sql, (farmer_id, image_path, message, 'new'))
        
        # Commit the transaction
        mysql.connection.commit()

        print(f"Notification logged in database for farmer ID: {farmer_id}, image: {image_path}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        cursor.close()  # Always close the cursor





@app.route('/')
def index():
    return render_template('index.html')  # Create an index.html file


# Route to handle translation requests
@app.route("/translate", methods=["POST"])
def translate():
    data = request.json
    target_language = data.get("language", "en")  # Default to English if not provided

    session['lang']=target_language
    print(session['lang'])

    # Read the content of the HTML file
    with open("templates/admin/dashboard.html", "r", encoding="utf-8") as file:
        html_content = file.read()

    # Translation API integration
    conn = http.client.HTTPSConnection("ai-translate.p.rapidapi.com")
    payload = json.dumps({
        "texts": [html_content],
        "tl": target_language,
        "sl": "auto"  # Auto-detect source language
    })
    headers = {
        'x-rapidapi-key': "e5e42c8c80mshdafd385694d5b95p137990jsnca39c5f8c7bb",
        'x-rapidapi-host': "ai-translate.p.rapidapi.com",
        'Content-Type': "application/json"
    }

    try:
        conn.request("POST", "/translateHtml", payload, headers)
        res = conn.getresponse()
        translated_data = json.loads(res.read().decode("utf-8"))

        # Extract the translated HTML
        translated_html = translated_data.get("data", [[]])[0][0]  # Get first item safely
        if not translated_html:
            return jsonify({"error": "Translation failed: no content received"}), 500

        return jsonify({"translated_html": translated_html})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        
        # Validation
        if not name or not email or not password:
            flash('All fields are required.', 'warning')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        cur = mysql.connection.cur()
        try:
            cur.execute("INSERT INTO farmers (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
            mysql.connection.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Email already exists or an error occurred.', 'danger')
            print(f"Error: {e}")  # Log the error for debugging
        finally:
            cur.close()
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Validation
        if not email or not password:
            flash('Email and password are required.', 'warning')
            return redirect(url_for('login'))

        cur = mysql.connection.cursor()
        try:
            # Check the admin table
            cur.execute("SELECT a_id, name, password FROM admin WHERE email = %s", (email,))
            admin = cur.fetchone()
            
            if admin and bc.checkpw(password.encode('utf-8'), admin[2].encode('utf-8')):
                session['admin_id'] = admin[0]
                session['username'] = admin[1]
                session['role'] = 'admin'
                flash('Admin login successful!', 'success')
                return redirect(url_for('admin_panel'))  # Ensure this return is included
            
            # Check the farmers table
            cur.execute("SELECT f_id, email, password, name FROM farmers WHERE email = %s", (email,))
            user = cur.fetchone()
            
            if user and bcrypt.check_password_hash(user[2], password):  # user[2] is the hashed password field
                session['loggedin'] = True
                session['id'] = user[0]  # Farmer ID
                session['name'] = user[3]  # Farmer name
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            
            flash('Invalid email or password. Please try again.', 'danger')
        except Exception as e:
            flash('An error occurred during login. Please try again later.', 'danger')
            print(f"Error: {e}")
        finally:
            cur.close()
    return render_template('login.html')



@app.route('/admin_panel')
def admin_panel():
    if 'admin_id' in session:
        cur = mysql.connection.cursor()
        try:
            # Get the total count of farmers
            cur.execute("SELECT COUNT(*) FROM farmers")
            total_farmers = cur.fetchone()[0]

            # Get the count of new notifications
            cur.execute("SELECT COUNT(*) FROM notifications WHERE status='new'")
            new_notifications_count = cur.fetchone()[0]

            return render_template('admin/home.html', name=session['username'], 
                                   total_farmers=total_farmers, 
                                   new_notifications_count=new_notifications_count)
        except Exception as e:
            flash(f'Error fetching data: {str(e)}', 'danger')
            return redirect(url_for('login'))
        finally:
            cur.close()
    
    flash('You must log in first.', 'warning')
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if 'loggedin' in session:
        return render_template('admin/dashboard.html', name=session['name'])
    flash('You must log in first.', 'warning')
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))



# Prediction function
def predict_image(file):
    img = image.load_img(file, target_size=(250, 250))  # Ensure the target size matches your model's input
    img = image.img_to_array(img)
    img = np.expand_dims(img, axis=0)
    img = img / 255.0
    prediction = model.predict(img)
    predicted_class_index = np.argmax(prediction)
    predicted_probability = np.max(prediction)
    
    return predicted_class_index, predicted_probability
@app.route('/predict', methods=['POST'])
def predict():
    # Check if a file is uploaded
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    try:
        # Save the file temporarily
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # Predict the class and probability
        predicted_class_index, predicted_probability = predict_image(file_path)

        # Convert probability to percentage
        confidence_percentage = predicted_probability * 100

        # Get farmer ID from the request form
        farmer_id = session['id']

        # Mapping the predicted class index to disease and recommendations
        recommendations = {
    0: {
        "disease": {
            "en": "Black Pod Rot",
            "kn": "ಕಪ್ಪು ಶೋಥ",
            "hi": "काला पॉड रॉट",
            "ml": "ബ്ലാക്ക് പോഡ് റോട്ട്",
            "te": "బ్లాక్ పాడ్ రాట్",
            "ta": "கருப்பு பாக் அழுகல்"
        },
        "recommendation": {
            "en": [
                "Remove and destroy infected pods to prevent spread.",
                "Maintain proper drainage in plantations to reduce waterlogging.",
                "Apply fungicides like copper-based fungicides regularly.",
                "Prune trees to improve airflow and reduce humidity."
            ],
            "kn": [
                "ಪ್ರಸರಣವನ್ನು ತಡೆಯಲು ಸೋಂಕಿತ ಕೊಂಬುಗಳನ್ನು ತೆಗೆಯಿರಿ ಮತ್ತು ನಾಶಪಡಿಸಿ.",
                "ನೀರು ನಿಲ್ಲಿಸುವಿಕೆಯನ್ನು ತಡೆಯಲು ತೋಟಗಳಲ್ಲಿ ಸರಿಯಾದ ಹಾಸುಮಾರುಗಳನ್ನು ಉಳಿಸಿ.",
                "ತಾಮ್ರ ಆಧಾರಿತ ಫಂಗಿಸೈಡ್ ಗಳನ್ನು ನಿಯಮಿತವಾಗಿ ಅನ್ವಯಿಸಿ.",
                "ಗಾಳಿಯ ಹರಿವು ಹೆಚ್ಚಿಸಲು ಮತ್ತು ತೇವಾಂಶವನ್ನು ಕಡಿಮೆ ಮಾಡಲು ಮರಗಳನ್ನು ಕತ್ತರಿಸಿ."
            ],
            "hi": [
                "फैलाव को रोकने के लिए संक्रमित फली को हटा दें और नष्ट कर दें।",
                "जलभराव को कम करने के लिए बागानों में उचित जल निकासी बनाए रखें।",
                "तांबे आधारित कवकनाशकों का नियमित रूप से उपयोग करें।",
                "हवा के प्रवाह में सुधार के लिए पेड़ों की छंटाई करें और आर्द्रता कम करें।"
            ],
            "ml": [
                "വ്യാപനം തടയാൻ ബാധിച്ച പാക്കറ്റുകൾ നീക്കം ചെയ്ത് നശിപ്പിക്കുക.",
                "വാട്ടർലോഗിംഗ് കുറയ്ക്കാൻ തോട്ടങ്ങളിൽ ആവശ്യമായ ഡ്രെയിനേജ് ഉറപ്പാക്കുക.",
                "താമ്രം അടങ്ങിയ ഫംഗിസൈഡുകൾ സ്ഥിരമായി പ്രയോഗിക്കുക.",
                "വാതകത്തിനും തീവ്രമായ വരൾച്ചയും കുറയ്ക്കാൻ മരങ്ങൾ കഷ്‌ണം ചെയ്യുക."
            ],
            "te": [
                "వైరస్ సోకిన పాడ్‌లను తీసివేయండి మరియు నాశనం చేయండి.",
                "నీటి నిల్వను తగ్గించడానికి తోటల్లో సరైన డ్రైనేజ్‌ని నిర్వహించండి.",
                "తాంబ్రం ఆధారిత ఫంగిసైడ్‌లను క్రమం తప్పకుండా ఉపయోగించండి.",
                "గాలి ప్రవాహం మెరుగుపరచడానికి మరియు తేమను తగ్గించడానికి చెట్లను ఎండి చేయండి."
            ],
            "ta": [
                "அறுவடையை அகற்றவும், அழிக்கவும் பரவலைத் தடுக்கவும்.",
                "நீர் தேங்கலைத் தடுக்க தோட்டங்களில் தக்க வடிகால் பராமரிக்கவும்.",
                "பித்தளையை அடிப்படையாகக் கொண்ட பூஞ்சை நாசினிகளை பின் தொடர்ந்து பயன்படுத்தவும்.",
                "காற்றோட்டத்தை மேம்படுத்தவும் ஈரப்பதத்தை குறைக்கவும் மரங்களை வெட்டவும்."
            ]
        }
    },
    1: {
        "disease": {
            "en": "Healthy",
            "kn": "ಆರೋಗ್ಯಕರ",
            "hi": "स्वस्थ",
            "ml": "ആരോഗ്യമുള്ള",
            "te": "ఆరోగ్యకరమైనది",
            "ta": "ஆரோக்கியமான"
        },
        "recommendation": {
            "en": [
                "Continue regular maintenance and monitoring.",
                "Use organic fertilizers to promote growth.",
                "Ensure proper irrigation and sunlight exposure.",
                "Monitor for early signs of diseases or pests."
            ],
            "kn": [
                "ನಿಯಮಿತ ನಿರ್ವಹಣೆ ಮತ್ತು ನಿಯಂತ್ರಣವನ್ನು ಮುಂದುವರಿಸಿ.",
                "ವೃದ್ಧಿಯನ್ನು ಉತ್ತೇಜಿಸಲು ಜೈವಿಕ ರಸಗೊಬ್ಬರವನ್ನು ಬಳಸಿರಿ.",
                "ಸರಿಯಾದ ನೀರಾವರಿ ಮತ್ತು ಬೆಳಕಿನ ಹಿತದೋಷವನ್ನು ಖಚಿತಪಡಿಸಿ.",
                "ರೋಗ ಅಥವಾ ಕೀಟಗಳ ಪ್ರಾರಂಭಿಕ ಲಕ್ಷಣಗಳಿಗಾಗಿ ಮಿತವ್ಯಯ ಇರಿಸಿ."
            ],
            "hi": [
                "नियमित रखरखाव और निगरानी जारी रखें।",
                "विकास को बढ़ावा देने के लिए जैविक उर्वरकों का उपयोग करें।",
                "उचित सिंचाई और प्रकाश जोखिम सुनिश्चित करें।",
                "रोग या कीटों के प्रारंभिक लक्षणों की निगरानी करें।"
            ],
            "ml": [
                "സ്ഥിരമായ പരിപാലനവും നിരീക്ഷണവും തുടരുക.",
                "വളർച്ചയെ പ്രോത്സാഹിപ്പിക്കുന്നതിനായി ജൈവ വളങ്ങൾ ഉപയോഗിക്കുക.",
                "ശുദ്ധമായ ജലസേചനം, സൂര്യപ്രകാശം ഉറപ്പാക്കുക.",
                "രോഗലക്ഷണങ്ങൾക്കോ കീടപിടിച്ചിടലുകൾക്കോ നിരീക്ഷിക്കുക."
            ],
            "te": [
                "క్రమం తప్పకుండా నిర్వహణ మరియు గమనిక కొనసాగించండి.",
                "పెరుగుదల కోసం సేంద్రియ ఎరువులను ఉపయోగించండి.",
                "అన్నివిధ రకాల కాంతి మరియు నీటిని నిర్ధారించండి.",
                "కీటకాలు మరియు వ్యాధుల ప్రారంభ సూచనల కోసం జాగ్రత్తగా పరిశీలించండి."
            ],
            "ta": [
                "தொடர்ந்து பராமரிப்பைச் செய்யவும் கண்காணிக்கவும்.",
                "வளர்ச்சியை ஊக்குவிக்க ஓர் இயற்கை உரங்களை பயன்படுத்தவும்.",
                "சரியான சூரிய ஒளி மற்றும் நீரேற்றம் உறுதிசெய்க.",
                "உயிர்களை சீக்கிரம் பார்க்கலாம் கண்டு பிடியுங்கள்."
            ]
        }
    },
    2: {
        "disease": {
            "en": "Monilia",
            "kn": "ಮೊನೀಲಿಯಾ",
            "hi": "मोनिलिया",
            "ml": "മോണിലിയ",
            "te": "మోనిలియా",
            "ta": "மோனிலியா"
        },
        "recommendation": {
            "en": [
                "Remove and destroy infected fruit and debris.",
                "Ensure proper air circulation around plants.",
                "Apply fungicides that are effective against Monilia.",
                "Practice crop rotation to prevent recurrence."
            ],
            "kn": [
                "ಬಾಧಿತ ಹಣ್ಣುಗಳು ಮತ್ತು ಬಾಳ್ಕೂಟವನ್ನು ತೆಗೆದುಹಾಕಿ ಮತ್ತು ನಾಶಪಡಿಸಿ.",
                "ಬಂಡೆಗಳಲ್ಲಿ ಉತ್ತಮ ಗಾಳಿ ಹರಿವನ್ನು ಖಚಿತಪಡಿಸಿ.",
                "ಮೋನಿಲಿಯಾ ವಿರುದ್ಧ ಪರಿಣಾಮಕಾರಿಯಾಗಿದೆ ಎಂದು ಫಂಗಿಸೈಡ್ ಅನ್ನು ಅನ್ವಯಿಸಿ.",
                "ಮರುಕುಡಿಯಲು ವಿಳಂಬವನ್ನು ತಪ್ಪಿಸಲು ಬೆಳೆಪಂಪಾ ಅಭ್ಯಾಸ ಮಾಡಿ."
            ],
            "hi": [
                "संक्रमित फल और मलबे को हटा दें और नष्ट करें।",
                "पौधों के चारों ओर उचित वायु परिसंचरण सुनिश्चित करें।",
                "मोनिलिया के खिलाफ प्रभावी कवकनाशक लगाएं।",
                "पुनरावृत्ति को रोकने के लिए फसल चक्र का अभ्यास करें।"
            ],
            "ml": [
                "ബാധിത പഴങ്ങളും മണ്ണും നീക്കം ചെയ്ത് നശിപ്പിക്കുക.",
                "സസ്യങ്ങള kolem മികച്ച വായു പ്രവാഹം ഉറപ്പാക്കുക.",
                "മോണിലിയയ്‌ക്കെതിരായ ഫംഗിസൈഡുകൾ പ്രയോഗിക്കുക.",
                "പുനരാവൃത്തി തടയാൻ വിളയറ്റത്തിന്റെ ഉപയോഗം നടത്തുക."
            ],
            "te": [
                "సోకిన కాయలను మరియు ముక్కలను తీసివేయండి మరియు నాశనం చేయండి.",
                "చెట్ల చుట్టూ సరైన గాలి ప్రవాహాన్ని నిర్ధారించండి.",
                "మోనిలియా వ్యతిరేకంగా ప్రభావవంతమైన ఫంగిసైడ్లను వర్తించండి.",
                "మరల రాకను నివారించడానికి పంట మలచడం సాధన చేయండి."
            ],
            "ta": [
                "பாதிக்கப்பட்ட பழங்களை மற்றும் கழிவு பொருட்களை அகற்றவும் அழிக்கவும்.",
                "சேதங்களின் சுற்றுவட்டத்தில் காற்று சரியாக ஓட வேண்டும்.",
                "மோனிலியாவுக்கு எதிரான திறன் வாய்ந்த பூஞ்சை நாசினியை பயன்படுத்தவும்.",
                "மறு தோற்றத்தைத் தடுக்க பண்ணை முளைப்பதைக் கடைபிடிக்கவும்."
            ]
        }
    }
}

        
        # Fetch the selected language from the session (default to English)
        selected_language = session.get('lang', 'en')
        print(selected_language)

        # Fetch the disease and recommendations based on prediction
        disease_data = recommendations.get(predicted_class_index, {})
        result = disease_data.get("disease", {}).get(selected_language, "Unknown")
        recommendation = disease_data.get("recommendation", {}).get(selected_language, ["No recommendations available."])

        # Logic for low confidence
        if confidence_percentage < 75:
            send_admin_notification(farmer_id, file_path, result, confidence_percentage)
            # Response when the confidence is below 75%
            return jsonify({
                "message": "A notification has been sent to the admin due to low confidence.",
                "predicted_class": result,
                "confidence_level": confidence_percentage
            })

        # Response when the confidence is 75% or higher
        response = {
            "predicted_class": result,
            "recommendations": recommendation,
            "predicted_probability": float(predicted_probability),
            "confidence_level": confidence_percentage,
            "file": file_path  # Include the path to the uploaded file
        }

        # Clean up the temporary file
        os.remove(file_path)

        return jsonify(response)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route('/farmer-notification')
def farmernotify():
    return render_template('admin/notifications.html')


@app.route('/notifications', methods=['GET','POST'])
def get_notifications():

    if 'id' not in session:
        return jsonify({"error": "You must be logged in to view notifications."}), 401
    
    farmer_id = session['id']
    cur = mysql.connection.cursor()
    try:
        cur.execute(
            "SELECT n_id, image, message, status, date,reply,reply_date FROM notifications WHERE farmer_id = %s  and status='replied' ORDER BY date DESC",
            (farmer_id,)
        )
        notifications = cur.fetchall()
        return jsonify(notifications)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()

@app.route('/all-new-notifications', methods=['GET'])
def get_all_new_notifications():
    if 'admin_id' not in session:
        return jsonify({"error": "You must be logged in to view notifications."}), 401

    cur = mysql.connection.cursor()
    try:
        # Get count of new notifications
        cur.execute("SELECT COUNT(*) FROM notifications WHERE status='new'")
        count_result = cur.fetchone()
        new_notification_count = count_result[0] if count_result else 0
        
        # Get details of new notifications
        cur.execute(
            """
            SELECT n.n_id, n.image, n.message, n.status, n.date, f.name, f.email
            FROM notifications n
            INNER JOIN farmers f ON n.farmer_id = f.f_id WHERE n.status='new'
            ORDER BY n.date DESC
            """
        )
        notifications = cur.fetchall()

        # Prepare the response with count and notifications
        response = {
            "count": new_notification_count,
            "notifications": notifications
        }
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()



@app.route('/all-notifications', methods=['GET'])
def get_all_notifications():
    if 'admin_id' not in session:
        return jsonify({"error": "You must be logged in to view notifications."}), 401

    cur = mysql.connection.cursor()
    try:
        cur.execute(
            """
            SELECT n.n_id, n.image, n.message, n.status, n.date, f.name,f.email
            FROM notifications n
            INNER JOIN farmers f ON n.farmer_id = f.f_id
            ORDER BY n.date DESC
            """
        )
        notifications = cur.fetchall()
        return jsonify(notifications)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()

@app.route('/send-reply/<int:notification_id>', methods=['POST'])
def send_reply(notification_id):
    if 'admin_id' not in session:
        return jsonify({"error": "You must be logged in to send a reply."}), 401

    # Get the reply message from the request data
    data = request.get_json()
    reply_message = data.get('message', '').strip()

    if not reply_message:
        return jsonify({"error": "Reply message cannot be empty."}), 400

    cur = mysql.connection.cursor()
    try:
        # First, insert the reply into the replies table

        # Then, update the notifications table to include the reply and reply date
        cur.execute(
            "UPDATE notifications SET reply = %s,status='replied', reply_date = NOW() WHERE n_id = %s",
            (reply_message, notification_id)
        )
        
        # Commit the changes to the database
        mysql.connection.commit()

        return jsonify({"success": "Reply sent successfully."}), 200
    except Exception as e:
        mysql.connection.rollback()  # Rollback in case of error
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()



@app.route('/api/translate', methods=['POST'])
def translate_text():
    try:
        # Parse incoming JSON data
        data = request.json
        texts = data.get('texts', [])  # List of texts to translate
        target_lang = data.get('targetLang', 'en')  # Target language (default: English)

        # Validate input
        if not isinstance(texts, list) or not texts:
            return jsonify({"error": "Invalid input. 'texts' should be a non-empty list."}), 400

        # Initialize the translator
        translator = Translator()

        # Translate each text individually
        translations = [translator.translate(text, dest=target_lang).text for text in texts]

        return jsonify({"translations": translations})
    except Exception as e:
        # Handle errors gracefully
        return jsonify({"error": str(e)}), 500



if __name__ == '__main__':
    app.run(debug=True)
