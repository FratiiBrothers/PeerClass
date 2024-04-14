from flask import Flask, render_template, request, redirect, url_for, session, abort  # Importăm funcția abort
from pymongo import MongoClient
import bcrypt
from flask import jsonify
from bson.objectid import ObjectId
import json
import folium

app = Flask(__name__)
app.secret_key = 'cheie_secreta'

mongo_client = MongoClient("mongodb://localhost:27017/")
mongo = mongo_client["peerclass"]


@app.route('/')
def index():
    return render_template('index.html', username = session.get("username"))
@app.route('/save-pin', methods=['POST'])
def save_pin():
    data = request.get_json()
    latitude = data['latitude']
    longitude = data['longitude']
    numar_persoane = data['numar_persoane']

    mongo["pins"].insert_one({'latitude': latitude, 'longitude': longitude, 'numar_persoane': numar_persoane})

    return {'message': 'Pin salvat cu succes!'}

@app.route('/get-pins', methods=['GET'])
def get_pins():
    pins = list(mongo['pins'].find())
    for pin in pins: 
        del pin['_id']
        pin['latitude'] = float(pin['latitude'])
        pin['longitude'] = float(pin['longitude'])
        pin['numar_persoane'] = int(pin['numar_persoane'])


    return {'pins': pins}


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session: return redirect("/postari")

    if request.method == 'POST':
        users = mongo["users"]
        login_user = users.find_one({'username' : request.form['username']})

        if login_user:
            if bcrypt.checkpw(request.form['password'].encode('utf-8'), login_user['password']):
                session['username'] = request.form['username']
                return redirect(url_for('postari'))
        
        return 'Autentificare eșuată. Verifică username-ul și parola.'

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()

    return redirect("/")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session: return redirect("/postari")

    if request.method == 'POST':
        users = mongo["users"]
        existing_user = users.find_one({'username' : request.form['username']})

        if existing_user is None:
            hashed_password = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())
            users.insert_one({
                'username' : request.form['username'], 
                'password' : hashed_password,
                "full_name": "",
                "location": "",
                "description": "",
                "streak": 0,
                "followers": [],
                "following": []
            })
            session['username'] = request.form['username']
            return redirect(url_for('postari'))
        
        return 'Acest username există deja!'

    return render_template('register.html')


@app.route('/postari')
def postari():
    postari = mongo["postari"].find()
    return render_template('postari.html', username = session.get("username"), postari=postari)


@app.route('/postare/<_id>', methods=['GET', 'POST'])
def afisare_postare(_id):
    postare = mongo["postari"].find_one({'_id': ObjectId(_id)})
    if postare:
        comentarii = mongo["comentarii"].find({'postare_id': _id})

        if request.method == 'POST':
            text_comentariu = request.form['text_comentariu']
            
            mongo["comentarii"].insert_one({
                'postare_id': _id,
                'text': text_comentariu
            })
            
            return redirect(url_for('afisare_postare', _id=_id))

        return render_template('postare.html', username = session.get("username"), postare=postare, comentarii=comentarii)
    else:
        abort(404)

@app.route('/like/<comentariu_id>')
def like_comentariu(comentariu_id):
    mongo["comentarii"].update_one({'_id': comentariu_id}, {'$inc': {'likes': 1}})
    return redirect(request.referrer)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        titlu = request.form['titlu']
        text = request.form['text']
        mongo["postari"].insert_one({'titlu': titlu, 'text': text})
        return redirect(url_for('postari'))
    
    return render_template('upload.html', username = session.get("username"))

@app.route('/users/<username>')
def user(username):
    if "username" not in session: return redirect("/login")

    user = mongo['users'].find_one({"username": username})

    if user == None: abort(404)

    print(session.items())
    print(session.get("username"))

    return render_template("user.html",
                            requested_username = username,
                            username = session.get("username"), 
                            full_name = user['full_name'],
                            location = user['location'],
                            description = user['description'],
                            streak = user['streak'],
                            followers = len(user['followers']),
                            following = len(user['following'])
                            )

@app.route('/harta')
def harta():
    
    pins = mongo["pins"].find()

    
    map = folium.Map(location=[45.14, 24.36], zoom_start=10)

    
    for pin in pins:
        
        folium.Marker([pin['latitude'], pin['longitude']], popup=f"Număr persoane: {pin['numar_persoane']}").add_to(map)

    
    map.save('templates/map.html')
    return render_template('harta.html', username = session.get("username"))

if __name__ == '__main__':
    app.run(debug=True)
