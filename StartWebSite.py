from flask import Flask, render_template, request, redirect, send_file, url_for, flash, session, jsonify
import psycopg2
from psycopg2.extras import DictCursor
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt
import datetime
import os
from dotenv import load_dotenv
from flask_mail import Mail, Message
from flask import make_response, send_from_directory
import json

# Charger les variables d'environnement depuis le fichier .env pour la configuration
load_dotenv()

# Initialiser l'application Flask
app = Flask(__name__)
# Charger la clé secrète pour la sécurité des sessions et JWT depuis le fichier .env
app.secret_key = os.getenv('SECRET_KEY')

# Configuration de Flask-Mail pour l'envoi des emails (serveur SMTP, utilisateur, mot de passe, etc.)
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
mail = Mail(app)

# Définir un chemin pour stocker temporairement les fichiers importés
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Extensions de fichiers autorisées pour l'importation
ALLOWED_EXTENSIONS = {'json'}

# Fonction pour vérifier l'extension de fichier lors de l'importation
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Route pour exporter les données de la base de données au format JSON
@app.route('/export_bdd', methods=['GET'])
def export_bdd():
    # Vérifier si l'utilisateur connecté est un administrateur
    if 'admin' not in session:
        return redirect(url_for('login'))

    try:
        # Connexion à la base de données
        conn = get_db_connection()
        cur = conn.cursor()

        # Récupérer les données des différentes tables (à adapter selon les tables à exporter)
        cur.execute("SELECT * FROM Utilisateur")
        utilisateurs = cur.fetchall()

        cur.execute("SELECT * FROM Cave")
        caves = cur.fetchall()

        cur.execute("SELECT * FROM Etagere")
        etageres = cur.fetchall()

        cur.execute("SELECT * FROM Bouteille")
        bouteilles = cur.fetchall()

        # Structurer les données dans un dictionnaire pour les convertir en JSON
        data = {
            "utilisateurs": utilisateurs,
            "caves": caves,
            "etageres": etageres,
            "bouteilles": bouteilles
        }

        # Spécifier le chemin du fichier de sauvegarde JSON
        filename = "bdd_export.json"
        filepath = os.path.join('static', filename)

        # Écrire les données au format JSON dans le fichier
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)

        # Fermer la connexion à la base de données
        cur.close()
        conn.close()

        flash('Base de données exportée avec succès.', 'success')
        # Envoyer le fichier JSON en tant que téléchargement
        return send_from_directory(directory='static', path=filename, as_attachment=True)

    except Exception as e:
        flash("Erreur lors de l'exportation de la base de données.", 'error')
        print(f"Erreur lors de l'exportation : {e}")
        return redirect(url_for('admin_dashboard'))
    

# Configuration de la connexion à la base de données PostgreSQL
def get_db_connection():
    try:
        conn = psycopg2.connect(
            host="localhost",
            database="postgres",
            user="postgres",
            password="lakomya",
            port=5432,
            options='-c client_encoding=UTF8',
            cursor_factory=DictCursor  # Utilisation de DictCursor pour accéder aux colonnes par nom
        )
        return conn
    except Exception as e:
        print(f"Erreur lors de la connexion à la base de données : {e}")
        return None

# Fonction pour vérifier si l'email ou le login existe déjà dans la base
def user_exists(email=None, login=None):
    conn = get_db_connection()
    if conn is None:
        return False
    cur = conn.cursor()
    if email:
        cur.execute("SELECT * FROM Utilisateur WHERE Email = %s", (email,))
    elif login:
        cur.execute("SELECT * FROM Utilisateur WHERE Login = %s", (login,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user

# Fonction pour générer un token JWT de réinitialisation de mot de passe avec expiration
def generate_reset_token(email):
    token = jwt.encode(
        {
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        },
        app.secret_key,  # Utilisation de la clé secrète pour signer le token
        algorithm='HS256'
    )
    return token

# Fonction pour envoyer un email de réinitialisation de mot de passe
def send_reset_email(email, token):
    reset_link = url_for('reset_password', token=token, _external=True)
    msg = Message('Réinitialisation de votre mot de passe', recipients=[email])
    msg.body = f'Cliquez sur le lien suivant pour réinitialiser votre mot de passe : {reset_link}'
    mail.send(msg)

# Fonction pour vérifier et décoder le token JWT de réinitialisation
def verify_reset_token(token):
    try:
        decoded_token = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        return decoded_token['email']
    except jwt.ExpiredSignatureError:
        return None  # Token expiré
    except jwt.InvalidTokenError:
        return None  # Token invalide

# Route pour afficher le formulaire d'inscription
@app.route('/inscription', methods=['GET'])
def inscription():
    return render_template('Inscription.html')

# Route pour traiter le formulaire d'inscription
@app.route('/inscription', methods=['POST'])
def inscription_post():
    nom = request.form['nom']
    prenom = request.form['prenom']
    email = request.form['email']
    telephone = request.form['telephone']
    login = request.form['login']
    mot_de_passe = request.form['mot_de_passe']

    # Vérifier si l'email ou le login est déjà pris
    email_exists = user_exists(email=email)
    login_exists = user_exists(login=login)

    errors = []
    
    if email_exists or login_exists:
        flash("Erreur dans les informations fournies. L'adresse email ou le login peuvent déjà être utilisés.", 'error')
        errors.append('email_error')
        errors.append('login_error')
    
    if errors:
        return render_template('Inscription.html', errors=errors)

    # Hachage du mot de passe pour sécuriser le stockage
    hashed_password = generate_password_hash(mot_de_passe)

    # Connexion à la base de données pour insérer les informations de l'utilisateur
    conn = get_db_connection()
    if conn is None:
        flash("Une erreur s'est produite, veuillez réessayer.", 'error')
        return redirect(url_for('inscription'))

    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO Utilisateur (Nom, Prenom, Email, Telephone, Login, MotDePasse) 
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (nom, prenom, email, telephone, login, hashed_password)
        )
        conn.commit()
        flash("Votre inscription a bien été prise en compte. Vous pouvez désormais vous connecter.", 'success')
    except Exception as e:
        print(f"Erreur lors de l'insertion : {e}")
        flash("Une erreur s'est produite, veuillez réessayer.", 'error')
    finally:
        cur.close()
        conn.close()

    # Redirection vers la page de connexion après une inscription réussie
    return redirect(url_for('login'))

# Route pour afficher le formulaire de connexion
@app.route('/login', methods=['GET'])
def login():
    return render_template('Login.html')

# Route pour traiter le formulaire de connexion
@app.route('/login', methods=['POST'])
def login_post():
    login = request.form['login']
    mot_de_passe = request.form['mot_de_passe']


    # Vérifier si l'utilisateur est l'administrateur
    if login == 'admin' and mot_de_passe == 'admin':
        session['admin'] = True
        return redirect(url_for('admin_dashboard'))  # Rediriger vers la page d'administration

    # Connexion à la base de données
    conn = get_db_connection()
    if conn is None:
        flash("Erreur de connexion à la base de données.", 'error')
        return redirect(url_for('login'))
    cur = conn.cursor()

    # Vérifier les informations de connexion
    cur.execute("SELECT * FROM Utilisateur WHERE Login = %s", (login,))
    user = cur.fetchone()

    cur.close()
    conn.close()

    # Vérifier si l'utilisateur existe et si le mot de passe est correct
    if user and check_password_hash(user['motdepasse'], mot_de_passe):
        # Stocker le login de l'utilisateur dans la session
        session['user'] = login
        return redirect(url_for('dashboard'))  # Rediriger vers la page d'accueil après connexion
    else:
        # Si le login ou le mot de passe est incorrect, afficher un message d'erreur
        flash("Le login et/ou le mot de passe semblent incorrect.", 'error')
        return redirect(url_for('login'))

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin' not in session:
        return redirect(url_for('login'))
    
    # Logique pour afficher les informations administratives
    return render_template('administration.html')

# Route pour afficher la page après connexion
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn is None:
        flash("Erreur de connexion à la base de données.", 'error')
        return redirect(url_for('login'))

    cur = conn.cursor()

    # Récupérer l'utilisateur connecté
    cur.execute("SELECT ID_Utilisateur FROM Utilisateur WHERE Login = %s", (session['user'],))
    utilisateur = cur.fetchone()

    # Récupérer les caves de cet utilisateur
    cur.execute("SELECT * FROM Cave WHERE Proprietaire_ID = %s", (utilisateur['id_utilisateur'],))
    caves = cur.fetchall()

    # Ajouter la logique pour le nombre d'étagères et de bouteilles
    caves_with_info = []
    for cave in caves:
        # Création d'un dictionnaire pour chaque cave
        cave_info = {
            'id_cave': cave['id_cave'],
            'nom_cave': cave['nom_cave'],
            'nb_etageres': 0,
            'nb_bouteilles': 0
        }

        # Nombre d'étagères dans chaque cave
        cur.execute("SELECT COUNT(*) FROM Etagere WHERE Cave_ID = %s", (cave['id_cave'],))
        nb_etageres = cur.fetchone()[0]
        cave_info['nb_etageres'] = nb_etageres if nb_etageres else 0

        # Nombre de bouteilles dans chaque cave
        cur.execute("""
            SELECT COUNT(*)
            FROM Bouteille
            WHERE Etagere_ID IN (SELECT ID_Etagere FROM Etagere WHERE Cave_ID = %s)
        """, (cave['id_cave'],))
        nb_bouteilles = cur.fetchone()[0]
        cave_info['nb_bouteilles'] = nb_bouteilles if nb_bouteilles else 0

        caves_with_info.append(cave_info)

    cur.close()
    conn.close()

    # Rendre la page avec les informations récupérées
    response = make_response(render_template('dashboard.html', login=session['user'], caves=caves_with_info))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/delete_caves', methods=['POST'])
def delete_caves():
    if 'user' not in session:
        return redirect(url_for('login'))

    # Récupérer les IDs des caves sélectionnées pour la suppression
    cave_ids = request.form.getlist('cave_ids')
    print(f"IDs des caves à supprimer : {cave_ids}")

    if cave_ids:
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            for cave_id in cave_ids:
                # Supprimer les bouteilles associées aux étagères de la cave
                cur.execute("""
                    DELETE FROM Bouteille
                    WHERE etagere_id IN (SELECT id_etagere FROM Etagere WHERE cave_id = %s)
                """, (cave_id,))
                
                # Supprimer les étagères de la cave
                cur.execute("DELETE FROM Etagere WHERE cave_id = %s", (cave_id,))
                
                # Supprimer la cave elle-même
                cur.execute("DELETE FROM Cave WHERE id_cave = %s", (cave_id,))
            
            conn.commit()
            flash('Caves supprimées avec succès.', 'success')
        except Exception as e:
            flash('Erreur lors de la suppression des caves.', 'error')
            print(f"Erreur de suppression : {e}")
        finally:
            cur.close()
            conn.close()

    return redirect(url_for('dashboard'))


# Route pour afficher le formulaire de réinitialisation du mot de passe
@app.route('/mdp_oublie', methods=['GET'])
def mdp_oublie():
    return render_template('MdpOublier.html')

# Route pour traiter la demande de réinitialisation du mot de passe
@app.route('/mdp_oublie', methods=['POST'])
def mdp_oublie_post():
    email = request.form['email']

    # Vérifier si l'utilisateur existe dans la base de données
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM Utilisateur WHERE Email = %s", (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user:
        # Générer un token unique pour la réinitialisation du mot de passe
        reset_token = generate_reset_token(user['email'])

        # Simuler l'envoi de l'email avec le lien de réinitialisation
        send_reset_email(user['email'], reset_token)

        flash("Un email de réinitialisation du mot de passe a été envoyé.", 'info')
        return redirect(url_for('login'))
    else:
        flash("Aucun compte associé à cet email.", 'error')
        return redirect(url_for('mdp_oublie'))

# Route pour la réinitialisation du mot de passe (à ajouter plus tard avec le token)
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Vérification et décodage du token
    email = verify_reset_token(token)
    if not email:
        flash('Le lien de réinitialisation a expiré ou est invalide.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Récupérer le nouveau mot de passe
        new_password = request.form['new_password']
        hashed_password = generate_password_hash(new_password)

        # Mise à jour du mot de passe dans la base de données
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE Utilisateur SET MotDePasse = %s WHERE Email = %s", (hashed_password, email))
        conn.commit()
        cur.close()
        conn.close()

        flash('Votre mot de passe a été réinitialisé avec succès.', 'success')
        return redirect(url_for('login'))

    return render_template('ResetPassword.html')

# Page d'accueil avant connexion
@app.route('/')
def accueil():
    return render_template('index.html')

# Route pour déconnexion qui efface toute la session
@app.route('/logout')
def logout():
    session.clear()  # Supprime toutes les informations de session
    flash('Vous avez été déconnecté avec succès.', 'info')
    return redirect(url_for('login'))  # Redirige vers la page de connexion

# Route pour afficher le formulaire de création de cave
@app.route('/creer_cave', methods=['GET', 'POST'])
def creer_cave():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Récupérer les données du formulaire
        nom_cave = request.form['nom_cave']

        # Connexion à la base de données pour ajouter la cave
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            # Insertion de la cave avec l'ID du propriétaire (utilisateur connecté)
            cur.execute(
                """
                INSERT INTO Cave (Nom_Cave, Proprietaire_ID)
                VALUES (%s, (SELECT ID_Utilisateur FROM Utilisateur WHERE Login = %s))
                """,
                (nom_cave, session['user'])
            )
            conn.commit()
            flash('Cave ajoutée avec succès !', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash('Une erreur est survenue lors de la création de la cave.', 'error')
            print(e)
        finally:
            cur.close()
            conn.close()

    return render_template('creer_cave.html')

@app.route('/creer_etagere', methods=['GET', 'POST'])
def creer_etagere():
    cave_id = request.args.get('cave_id')
    
    if not cave_id:
        flash("Aucun ID de cave spécifié.", "error")
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cur = conn.cursor()

    # Récupérer les informations de la cave pour afficher le nom de la cave dans le template
    cur.execute("SELECT Nom_Cave FROM Cave WHERE ID_Cave = %s", (cave_id,))
    cave = cur.fetchone()

    if not cave:
        flash("Cave non trouvée.", "error")
        return redirect(url_for('dashboard'))

    error_message = session.pop('error_message', None)  # Récupérer et effacer l'erreur de la session

    if request.method == 'POST':
        numero_etagere = request.form['numero_etagere']
        nb_places = request.form['nb_places']

        # Vérifier si le numéro d'étagère existe déjà dans cette cave
        cur.execute("""
            SELECT * FROM Etagere WHERE Numero = %s AND Cave_ID = %s
        """, (numero_etagere, cave_id))
        existing_etagere = cur.fetchone()

        if existing_etagere:
            session['error_message'] = "Un numéro d'étagère similaire existe déjà dans cette cave."
            return redirect(url_for('creer_etagere', cave_id=cave_id))

        # Insérer la nouvelle étagère pour la cave spécifiée
        cur.execute("""
            INSERT INTO Etagere (Numero, Nb_place, Cave_ID)
            VALUES (%s, %s, %s)
        """, (numero_etagere, nb_places, cave_id))

        conn.commit()
        flash("L'étagère a été ajoutée avec succès.", 'success')
        return redirect(url_for('view_etageres', cave_id=cave_id))

    cur.close()
    conn.close()
    
    return render_template('creer_etagere.html', cave=cave, cave_id=cave_id, error_message=error_message)

@app.route('/delete_etageres/<int:cave_id>', methods=['POST'])
def delete_etageres(cave_id):
    etagere_ids = request.form.getlist('etagere_ids')
    if etagere_ids:
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            for etagere_id in etagere_ids:
                # Supprimer les bouteilles associées à chaque étagère
                cur.execute("DELETE FROM Bouteille WHERE etagere_id = %s", (etagere_id,))
                # Supprimer l'étagère elle-même
                cur.execute("DELETE FROM Etagere WHERE id_etagere = %s", (etagere_id,))
            conn.commit()
            flash('Étagères supprimées avec succès.', 'success')
        except Exception as e:
            flash('Erreur lors de la suppression des étagères.', 'error')
            print(e)
        finally:
            cur.close()
            conn.close()
    return redirect(url_for('view_etageres', cave_id=cave_id))


@app.route('/ajouter_bouteille/<int:etagere_id>', methods=['GET', 'POST'])
def ajouter_bouteille(etagere_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    # Récupération des IDs des templates sélectionnés
    template_ids = request.form.getlist('template_id[]')
    conn = get_db_connection()
    cur = conn.cursor()

    # Récupérer la capacité totale de l'étagère et le nombre actuel de bouteilles
    cur.execute("SELECT nb_place FROM Etagere WHERE id_etagere = %s", (etagere_id,))
    nb_place = cur.fetchone()[0]

    cur.execute("SELECT SUM(nb_bouteille) FROM Bouteille WHERE etagere_id = %s", (etagere_id,))
    nb_bouteilles = cur.fetchone()[0]
    print(f"Nombre total de bouteilles dans l'étagère après insertion : {nb_bouteilles}")


    # Calculer le nombre de places restantes
    places_restantes = nb_place - nb_bouteilles

    total_quantity = 0
    # Calculer la quantité totale demandée par l'utilisateur
    for template_id in template_ids:
        quantity = int(request.form.get(f'quantity_{template_id}', 0))
        total_quantity += quantity

    if total_quantity > places_restantes:
        flash(f"Impossible d'ajouter {total_quantity} bouteilles. Il ne vous reste que {places_restantes} places dans l'étagère.", 'error')
        return redirect(url_for('view_templates', etagere_id=etagere_id))
        

    # Si l'ajout est possible, insérer les bouteilles
    for template_id in template_ids:
        quantity = int(request.form.get(f'quantity_{template_id}', 0))
        if quantity > 0:
            cur.execute("""
                INSERT INTO Bouteille (Note_perso, Etagere_ID, Template_ID, Nb_bouteille)
                VALUES (%s, %s, %s, %s)
            """, (None, etagere_id, template_id, quantity))

    conn.commit()
    cur.close()
    conn.close()

    flash('Bouteilles ajoutées avec succès.', 'success')
    return redirect(url_for('view_bouteilles', etagere_id=etagere_id))

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/templates_bouteille/<int:etagere_id>', methods=['GET'])
def view_templates(etagere_id):
    conn = get_db_connection()
    cur = conn.cursor()

    # Requête pour récupérer les templates, les notes moyennes et les commentaires
    cur.execute("""
        SELECT 
            t.id_template, t.nom, t.prix, t.domaine, t.type_bouteille, t.annee, t.region, t.image_path, 
            COALESCE(ROUND(AVG(b.note_perso)::numeric, 1), 0) AS note_moyenne,
            STRING_AGG(b.commentaire, ', ' ORDER BY b.id_bouteille) AS commentaires
        FROM TemplateBouteille t
        LEFT JOIN Bouteille b ON t.id_template = b.template_id
        LEFT JOIN Utilisateur u ON b.utilisateur_id = u.id_utilisateur
        GROUP BY t.id_template, t.nom, t.prix, t.domaine, t.type_bouteille, t.annee, t.region, t.image_path;

    """)
    rows = cur.fetchall()

    # Transformez les données en dictionnaire avec des clés correspondant aux noms utilisés dans le template HTML
    templates = [
        {
            'id': row[0],
            'nom': row[1],
            'prix': row[2],
            'domaine': row[3],
            'type_bouteille': row[4],
            'annee': row[5],
            'region': row[6],
            'image_path': row[7],
            'note_moyenne': row[8],  # Note moyenne calculée
            'commentaires': row[9]   # Commentaires des utilisateurs
        }
        for row in rows
    ]

    # Récupérer les informations sur l'étagère
    cur.execute("SELECT nb_place FROM Etagere WHERE id_etagere = %s", (etagere_id,))
    nb_place = cur.fetchone()[0]
    cur.execute("SELECT SUM(nb_bouteille) FROM Bouteille WHERE etagere_id = %s", (etagere_id,))
    nb_bouteille = cur.fetchone()[0] or 0

    cur.close()
    conn.close()

    return render_template('templates_bouteille.html', templates=templates, etagere_id=etagere_id, nb_place=nb_place, nb_bouteille=nb_bouteille)


@app.route('/etagere/<int:cave_id>', methods=['GET'])
def view_etageres(cave_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()

    # Récupérer les informations de la cave sélectionnée
    cur.execute("""
        SELECT * FROM Cave WHERE ID_Cave = %s AND Proprietaire_ID = (
            SELECT ID_Utilisateur FROM Utilisateur WHERE Login = %s
        )
    """, (cave_id, session['user']))
    cave = cur.fetchone()

    # Récupérer les étagères associées à cette cave et compter les bouteilles
    cur.execute("""
        SELECT Etagere.ID_Etagere, Etagere.Numero, Etagere.Nb_place AS nb_places, 
            COALESCE(SUM(Bouteille.nb_bouteille), 0) AS nb_bouteilles,
            Etagere.Nb_place - COALESCE(SUM(Bouteille.nb_bouteille), 0) AS places_restantes
        FROM Etagere
        LEFT JOIN Bouteille ON Etagere.ID_Etagere = Bouteille.Etagere_ID
        WHERE Etagere.Cave_ID = %s
        GROUP BY Etagere.ID_Etagere, Etagere.Numero, Etagere.Nb_place
    """, (cave_id,))
    etageres = cur.fetchall()

    cur.close()
    conn.close()

    if cave is None:
        flash("Cave non trouvée ou vous n'y avez pas accès.", "error")
        return redirect(url_for('dashboard'))

    return render_template('view_etageres.html', cave=cave, etageres=etageres)



@app.route('/bouteilles/<int:etagere_id>', methods=['GET'])
def view_bouteilles(etagere_id):
    archivee = request.args.get('archivee', 'false').lower() == 'true'

    conn = get_db_connection()
    cur = conn.cursor()

    # Requête pour récupérer les informations des bouteilles, en fonction de l'état archivé ou non
    if archivee:
        cur.execute("""
            SELECT 
                MIN(b.id_bouteille) AS id_bouteille, t.id_template, t.nom, t.type_bouteille, t.annee, t.region, t.prix,
                SUM(b.nb_bouteille_archivee) AS total_nb_bouteille,
                ROUND(AVG(b.note_perso)::numeric, 1) AS note_perso,
                STRING_AGG(b.commentaire, ', ' ORDER BY b.id_bouteille) AS commentaires
            FROM Bouteille b
            JOIN TemplateBouteille t ON b.template_id = t.id_template
            WHERE b.etagere_id = %s AND b.nb_bouteille_archivee > 0
            GROUP BY t.id_template, t.nom, t.type_bouteille, t.annee, t.region, t.prix
        """, (etagere_id,))
        template = 'bouteille_archiver.html'
    else:
        cur.execute("""
            SELECT 
                MIN(b.id_bouteille) AS id_bouteille, t.id_template, t.nom, t.type_bouteille, t.annee, t.region, t.prix,
                SUM(b.nb_bouteille) AS total_nb_bouteille,
                ROUND(AVG(b.note_perso)::numeric, 1) AS note_perso,
                STRING_AGG(b.commentaire, ', ' ORDER BY b.id_bouteille) AS commentaires
            FROM Bouteille b
            JOIN TemplateBouteille t ON b.template_id = t.id_template
            WHERE b.etagere_id = %s AND b.nb_bouteille > 0
            GROUP BY t.id_template, t.nom, t.type_bouteille, t.annee, t.region, t.prix
        """, (etagere_id,))
        template = 'bouteille.html'

    bouteilles = cur.fetchall()

    # Récupérer le numéro de l'étagère et le cave_id pour l'affichage
    cur.execute("SELECT Numero, Cave_ID FROM Etagere WHERE ID_Etagere = %s", (etagere_id,))
    etagere = cur.fetchone()
    numero_etagere = etagere['numero'] if etagere else None
    cave_id = etagere['cave_id'] if etagere else None

    cur.close()
    conn.close()

    return render_template(template, bouteilles=bouteilles, etagere_id=etagere_id, numero_etagere=numero_etagere, cave_id=cave_id)


@app.route('/add_bottle_from_template/<int:etagere_id>', methods=['POST'])
def add_bottle_from_template(etagere_id):
    template_id = request.form.get('template_id')
    quantity = request.form.get('quantity', 0)

    print(f"Template ID: {template_id}, Quantity: {quantity}")

    if not template_id or int(quantity) <= 0:
        flash('Template ID or quantity is missing or invalid', 'error')
        return redirect(url_for('view_templates', etagere_id=etagere_id))

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO Bouteille (template_id, etagere_id, nb_bouteille)
            VALUES (%s, %s, %s)
            ON CONFLICT (template_id, etagere_id) DO UPDATE
            SET nb_bouteille = Bouteille.nb_bouteille + %s
            """,
            (template_id, etagere_id, quantity, quantity)
        )

        conn.commit()
        print(f"Bouteille ajoutée avec template_id: {template_id} et quantité: {quantity}")
        flash('Bouteille ajoutée avec succès.', 'success')
    except Exception as e:
        flash('Erreur lors de l\'ajout de la bouteille.', 'error')
        print(f"Erreur lors de l'insertion de la bouteille : {e}")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('view_bouteilles', etagere_id=etagere_id))




@app.route('/bouteille/<int:etagere_id>/trier', methods=['GET'])
def trier_bouteilles(etagere_id):
    critere = request.args.get('critere', 'nom')
    # Définir le critère de tri et vérifier les colonnes associées
    if critere in ['nom', 'type_bouteille', 'annee', 'region', 'prix']:
        order_by_column = f"t.{critere}"
    elif critere == 'nb_bouteille':
        order_by_column = "total_nb_bouteille"
    elif critere == 'note_perso':
        order_by_column = "note_perso"
    else:
        order_by_column = "t.nom"

    conn = get_db_connection()
    cur = conn.cursor()

    # Requête pour regrouper et trier les bouteilles, en excluant celles dont la quantité est 0
    cur.execute(f"""
        SELECT 
            MIN(b.id_bouteille) AS id_bouteille, t.id_template, t.nom, t.type_bouteille, t.annee, t.region, t.prix,
            SUM(b.nb_bouteille) AS total_nb_bouteille, 
            ROUND(AVG(b.note_perso)::numeric, 1) AS note_perso,
            STRING_AGG(b.commentaire, ', ' ORDER BY b.id_bouteille) AS commentaires,
            t.domaine, t.image_path
        FROM Bouteille b
        JOIN TemplateBouteille t ON b.template_id = t.id_template
        WHERE b.etagere_id = %s
        GROUP BY t.id_template, t.nom, t.type_bouteille, t.annee, t.region, t.prix, t.domaine, t.image_path
        ORDER BY {order_by_column}
    """, (etagere_id,))

    bouteilles = cur.fetchall()

    # Récupérer le numéro et le cave_id associé à l'étagère pour le titre et le bouton de retour
    cur.execute("SELECT Numero, Cave_ID FROM Etagere WHERE ID_Etagere = %s", (etagere_id,))
    etagere = cur.fetchone()
    numero_etagere = etagere['numero'] if etagere else None
    cave_id = etagere['cave_id'] if etagere else None

    cur.close()
    conn.close()

    return render_template('bouteille.html', bouteilles=bouteilles, etagere_id=etagere_id, numero_etagere=numero_etagere, cave_id=cave_id)



# Route pour archiver une bouteille, accessible via une méthode POST et prenant l'ID de la bouteille en paramètre.
@app.route('/archiver_bouteille/<int:bouteille_id>', methods=['POST'])
def archiver_bouteille(bouteille_id):
    # Récupérer la quantité à archiver depuis le formulaire. Par défaut, c'est 1 si aucune quantité n'est spécifiée.
    quantity_to_archive = int(request.form.get('quantity', 1))
    # Vérifier si l'utilisateur est connecté. Si non, le rediriger vers la page de connexion.
    if 'user' not in session:
        return redirect(url_for('login'))

    # Établir une connexion à la base de données.
    conn = get_db_connection()
    cur = conn.cursor()

    # Récupérer les informations de la bouteille actuelle, incluant la quantité disponible, la quantité archivée, et l'ID de l'étagère associée.
    cur.execute("SELECT nb_bouteille, nb_bouteille_archivee, etagere_id FROM Bouteille WHERE id_bouteille = %s", (bouteille_id,))
    bouteille = cur.fetchone()

    # Si la bouteille existe (les informations sont récupérées correctement).
    if bouteille:
        # Stocker la quantité actuelle et la quantité déjà archivée.
        current_quantity = bouteille['nb_bouteille']
        archived_quantity = bouteille['nb_bouteille_archivee']
        etagere_id = bouteille['etagere_id']

        # Vérifier si la quantité à archiver est supérieure à la quantité disponible.
        if quantity_to_archive > current_quantity:
            # Afficher un message d'erreur si l'utilisateur essaie d'archiver plus que la quantité disponible.
            flash(f"Vous ne pouvez pas archiver plus de {current_quantity} bouteilles.", 'error')
        else:
            # Calculer la nouvelle quantité restante et la nouvelle quantité archivée.
            new_quantity = current_quantity - quantity_to_archive
            new_archived_quantity = archived_quantity + quantity_to_archive
            # Mettre à jour la base de données avec les nouvelles quantités.
            cur.execute("""
                UPDATE Bouteille 
                SET nb_bouteille = %s, nb_bouteille_archivee = %s 
                WHERE id_bouteille = %s
            """, (new_quantity, new_archived_quantity, bouteille_id))

            # Valider les changements dans la base de données.
            conn.commit()
            # Afficher un message de succès indiquant le nombre de bouteilles archivées.
            flash(f'{quantity_to_archive} bouteilles archivées avec succès.', 'success')

    # Fermer le curseur et la connexion à la base de données.
    cur.close()
    conn.close()

    # Rediriger l'utilisateur vers la vue des bouteilles de l'étagère concernée.
    return redirect(url_for('view_bouteilles', etagere_id=etagere_id))



@app.route('/creer_template_bouteille/<int:etagere_id>', methods=['GET', 'POST'])
def creer_template_bouteille(etagere_id):
    if request.method == 'POST':
        nom = request.form['nom']
        type_bouteille = request.form['type_bouteille']
        annee = request.form['annee']
        region = request.form['region']
        prix = request.form['prix']
        domaine = request.form['domaine']
        
        # Traiter l'image
        image = request.files.get('image', None)
        if image and image.filename != '':
            # Utiliser le nom sécurisé du fichier pour le chemin
            filename = secure_filename(image.filename)
            image_path = f'images/{filename}'  # Chemin relatif à partir de 'static/'
            image.save(f'static/{image_path}')  # Sauvegarder l'image dans le dossier 'static/images/'
            print(f"Image saved at: {image_path}")  # Debug : Afficher le chemin de l'image enregistrée
        else:
            # Utiliser une image par défaut si aucune image n'a été fournie
            image_path = 'images/default.png'
            print("No image uploaded, using default image.")  # Debug : Indiquer que l'image par défaut est utilisée

        # Sauvegarder le template dans la base de données
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO TemplateBouteille (nom, type_bouteille, annee, region, prix, domaine, image_path)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (nom, type_bouteille, annee, region, prix, domaine, image_path))

        conn.commit()
        cur.close()
        conn.close()
        
        return redirect(url_for('view_templates', etagere_id=etagere_id))

    return render_template('creer_template_bouteille.html', etagere_id=etagere_id)



@app.route('/noter_bouteille', methods=['POST'])
def noter_bouteille():
    id_bouteille = request.form.get('id_bouteille')
    note = request.form.get('note')
    
    print(f"ID Bouteille : {id_bouteille}, Note : {note}")

    if not id_bouteille or not note:
        return jsonify({'success': False, 'message': 'Données invalides'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("""
        UPDATE Bouteille 
        SET note_perso = %s
        WHERE id_bouteille = %s
    """, (note, id_bouteille))
    
    conn.commit()
    cur.close()
    conn.close()
    
    return jsonify({'success': True}), 200

@app.route('/ajouter_commentaire/<int:bouteille_id>', methods=['POST'])
def ajouter_commentaire(bouteille_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    commentaire = request.form.get('commentaire')

    conn = get_db_connection()
    cur = conn.cursor()

    # Récupérer l'étagère associée à la bouteille pour la redirection
    cur.execute("SELECT etagere_id FROM Bouteille WHERE id_bouteille = %s", (bouteille_id,))
    bouteille = cur.fetchone()

    if bouteille:
        etagere_id = bouteille['etagere_id']

        try:
            # Mise à jour ou insertion du commentaire pour la bouteille donnée
            cur.execute("""
                UPDATE Bouteille
                SET commentaire = %s
                WHERE id_bouteille = %s
            """, (commentaire, bouteille_id))
            conn.commit()
            flash('Commentaire ajouté avec succès.', 'success')
        except Exception as e:
            flash('Erreur lors de l\'ajout du commentaire.', 'error')
            print(e)
        finally:
            cur.close()
            conn.close()

        return redirect(url_for('view_bouteilles', etagere_id=etagere_id))
    else:
        flash('Bouteille non trouvée.', 'error')
        return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(debug=True)