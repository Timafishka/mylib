from flask import render_template, request, make_response, redirect, url_for, session
import random
import string
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
from PIL import Image
from PIL import ImageDraw
from flask import Flask
from flask_restful import Api, Resource
import sqlite3


app = Flask(__name__)
api = Api(app)
app.secret_key = 'your_secret_key_here'

app.config['UPLOAD_FOLDER'] = 'static/images/books/'
print(app.config['UPLOAD_FOLDER'])

DATABASE = 'sql/base.db'
IMAGE_FOLDER = 'images/'


# Соединение SQLite
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# Генерация кода пользователя
def generate_usercode():
    key = 'abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(random.choices(key, k=9))


# Генерация кода публикации
def generate_publicationcode():
    key = string.ascii_letters + string.digits
    return ''.join(random.choices(key, k=12))


# Функция шифрования
def encrypt_text(text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct


# Функция дешифрования
def decrypt_text(iv, ct, key):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')


# Ввод ключа шифрования администратором
SECRET_KEY = input("Введите секретный ключ: ").encode('utf-8')
# Хэширование ключа
hashed_secret_key = hashlib.sha256(SECRET_KEY).digest()


# Хэш пароля
def hash_password(password):
    iv, ct = encrypt_text(password, SECRET_KEY)
    return iv, ct


# Проверка хэша пароля
def check_password_hash(hashed_password, password):
    iv, ct = hashed_password
    decrypted_password = decrypt_text(iv, ct, SECRET_KEY)
    return decrypted_password == password


# Сохранение пользователя
def save_user(username, email, password):
    usercode = generate_usercode()
    iv, ct = hash_password(password)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, mail, password_iv, password_ct, usercode) VALUES (?, ?, ?, ?, ?)',
                   (username, email, iv, ct, usercode))
    conn.commit()
    conn.close()


# Аутентификация пользователя
def verify_login(email, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE mail = ?', (email,))
    user = cursor.fetchone()
    conn.close()

    if user:
        iv = user['password_iv']
        ct = user['password_ct']
        if check_password_hash((iv, ct), password):
            return user
    return None


# Главная страница
@app.route('/')
@app.route('/works')
def works():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM books')
    publications = cursor.fetchall()
    conn.close()

    assets_resources = ["static/engine_assets/images/lobbysite_logo_btn.png",
                        "static/engine_assets/images/upload_btn.png",
                        "static/engine_assets/images/profile_pic.png", "static/engine_assets/images/MyLib_logo.png"]
    return render_template('works.html', publications=reversed(publications), asts_rsc=assets_resources)


# Страница загрузки книги
@app.route('/upload')
def upload_page():
    assets_resources = ["static/engine_assets/images/profile_pic.png", "static/engine_assets/images/MyLib_logo.png"]
    return render_template('upload.html', asts_rsc=assets_resources)


def round_corners(image, radius):
    # Создаем маску для скругления углов
    mask = Image.new("L", image.size, 0)
    draw = ImageDraw.Draw(mask)
    draw.rectangle((0, 0, image.width, image.height), fill=255)
    draw.pieslice((0, 0, radius * 2, radius * 2), 180, 270, fill=0)
    draw.pieslice((image.width - radius * 2, 0, image.width, radius * 2), 270, 360, fill=0)
    draw.pieslice((0, image.height - radius * 2, radius * 2, image.height), 90, 180, fill=0)
    draw.pieslice((image.width - radius * 2, image.height - radius * 2, image.width, image.height), 0, 90, fill=0)

    # Скругляем углы изображения
    result = Image.new("RGBA", image.size)
    result.paste(image, mask=mask)
    return result


def process_image(book_pic):
    image = Image.open(book_pic)
    width, height = image.size
    # Применяем скругление углов с радиусом 5% от ширины изображения
    rounding_radius = int(width * 0.05)
    rounded_image = round_corners(image, rounding_radius)

    # Создаем квадратное изображение, заполняя недостающие области белым цветом
    max_size = max(width, height)
    square_image = Image.new('RGB', (max_size, max_size), color='white')
    offset = ((max_size - width) // 2, (max_size - height) // 2)
    square_image.paste(rounded_image, offset)
    square_image = square_image.resize((540, 540))
    return square_image


# Обработчик для загрузки книги
@app.route('/upload_book', methods=['POST'])
def upload_book():
    if request.method == 'POST':
        TextTitle = request.form['TextTitle']
        book_text = request.form['book_text']
        publicationcode = generate_publicationcode()
        # Загрузка изображения
        if 'book_pic' in request.files:
            book_pic = request.files['book_pic']
            filename = publicationcode + '.jpg'
            if book_pic.filename != '':
                if book_pic.filename.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp')):
                    processed_img = process_image(book_pic)
                    processed_img.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                else:
                    filename = 'bookpic_standart_layout.jpg'
            else:
                filename = 'bookpic_standart_layout.jpg'

        # Сохранение в базу данных
        conn = get_db_connection()
        cursor = conn.cursor()

        if 'user' in session:
            username = session['user']
            conn_usr_code = sqlite3.connect(DATABASE)
            cursor = conn_usr_code.cursor()
            cursor.execute("SELECT usercode FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            conn_usr_code.close()
            if result:
                usercode = result[0]
            else:
                return redirect(url_for('upload'))
        else:
            usercode = "anonymous"
            username = "Аноним"

        conn.close()
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        try:
            cursor.execute(
                'INSERT INTO books (title, text, author, usercode, publicationcode, path2pic, likedby) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (TextTitle, book_text, username, usercode, publicationcode,
                 os.path.join(app.config['UPLOAD_FOLDER'], filename), '000,'))
            conn.commit()
        except sqlite3.Error as e:
            print("ERROR WITH PUBLICATION:", e)
            conn.rollback()
        finally:
            conn.close()

        return redirect(url_for('works'))


# Шаблон книг
@app.route('/book-<publicationcode>')
@app.route('/book<publicationcode>')
def book(publicationcode):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM books WHERE publicationcode = ?', (publicationcode,))
    publication = cursor.fetchone()
    publication_list = list(publication)[2]
    paragraphs = publication_list.split('\r\n')
    book_text = [paragraph for paragraph in paragraphs]
    conn.close()
    assets_resources = ["static/engine_assets/images/lobbysite_logo_btn.png",
                        "static/engine_assets/images/profile_pic.png", "static/engine_assets/images/MyLib_logo.png",
                        "static/engine_assets/images/comment_btn.png", "static/engine_assets/images/upload_btn.png"]
    author_link = "/user-" + publication['usercode']

    if 'user' in session:
        username = session['user']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        readerid = list(user)[4]
    else:
        readerid = None
    conn_like_check = get_db_connection()
    cursor = conn_like_check.cursor()
    cursor.execute('SELECT likes, likedby FROM books WHERE publicationcode = ?', (publicationcode,))
    likeinfo = cursor.fetchone()
    conn_like_check.close()
    likes = likeinfo[0]
    likedby = likeinfo[1]
    if readerid and readerid in likedby:
        assets_resources.append("static/engine_assets/images/like_active.png")
    else:
        assets_resources.append("static/engine_assets/images/like_nonactive.png")

    return render_template('book.html', author_link=author_link, publication=publication,
                           book_text=book_text, asts_rsc = assets_resources, readerid=readerid)


# Шаблон комментариев пользователей
@app.route('/comments-<publicationcode>')
@app.route('/comments<publicationcode>')
def comments(publicationcode):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM comments WHERE publicationcode = ?', (publicationcode,))
    comments = cursor.fetchall()
    cursor.execute('SELECT * FROM books WHERE publicationcode = ?', (publicationcode,))
    booktitle = list(cursor.fetchone())[1]
    conn.close()

    logo_path = "static/engine_assets/images/MyLib_logo.png"
    assets_resources = ["static/engine_assets/images/bac2book_btn.png",
                        "static/engine_assets/images/upload_btn.png",
                        "static/engine_assets/images/profile_pic.png", "static/engine_assets/images/MyLib_logo.png"]
    return render_template('comments.html', publicationcode=publicationcode, booktitle=booktitle,
                           comments=reversed(comments), logo_path=logo_path, asts_rsc=assets_resources)


# Скрипт добавления комментария
@app.route('/add-comment', methods=['POST'])
def add_comment():
    if 'user' in session:
        if 'user' in session:
            username = session['user']
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            readerid = list(user)[4]
        else:
            readerid = None

        comment = request.json.get('comment')
        publicationcode = request.json.get('pbcode')
        conn2comm = get_db_connection()
        cursor = conn2comm.cursor()
        cursor.execute('INSERT INTO comments (publicationcode, comment, usercode, author) VALUES (?, ?, ?, ?)',
                       (publicationcode, comment, readerid, username))
        conn2comm.commit()
        conn2comm.close()
        return 'Комментарий успешно добавлен', 200


# Скрипт добавления лайка на публикацию
@app.route('/like', methods=['POST'])
def like():
    publicationcode = request.form['publicationcode']
    if 'user' in session:
        if 'user' in session:
            username = session['user']
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            readerid = list(user)[4]
        else:
            readerid = None

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT likes, likedby FROM books WHERE publicationcode = ?', (publicationcode,))
        publication = cursor.fetchone()
        likes = publication[0]
        likedby = publication[1]

        if readerid and readerid in likedby:
            # Убрать лайк
            likes -= 1
            likedby = likedby.replace(readerid + ",", "").replace("," + readerid, "")
        else:
            # Добавить лайк
            if readerid:
                likes += 1
                likedby += "," + readerid
            else:
                likedby = likedby

        cursor.execute('UPDATE books SET likes = ?, likedby = ? WHERE publicationcode = ?', (likes, likedby, publicationcode))
        conn.commit()
        conn.close()

    # Перенаправление обратно на страницу книги
    return redirect('/book-{}'.format(publicationcode))


# Шаблон профиля пользователя
@app.route('/user-<usercode>')
def user_profile(usercode):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE usercode = ?', (usercode,))
    userdata = cursor.fetchone()['username']
    cursor.execute('SELECT * FROM books WHERE usercode = ?', (usercode,))
    publications = cursor.fetchall()
    conn.close()

    assets_resources = ["static/engine_assets/images/lobbysite_logo_btn.png",
                        "static/engine_assets/images/upload_btn.png",
                        "static/engine_assets/images/profile_pic.png", "static/engine_assets/images/MyLib_logo.png"]
    return render_template('user.html', userdata=userdata, publications=reversed(publications), asts_rsc=assets_resources)


# Функциональная отладочная страница входа или регистрации
@app.route('/AddSession', methods=['GET', 'POST'])
def add_session():
    if request.method == 'POST':
        if request.form['action'] == 'login':
            return redirect(url_for('login'))
        elif request.form['action'] == 'signin':
            return redirect(url_for('signin'))
    return render_template('add_session.html')


# Страница регистрации
@app.route('/AddSession/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? OR mail = ?', (username, email))
        existing_user = cursor.fetchone()

        if existing_user:
            return redirect(url_for('signin'))
        else:
            save_user(username, email, password)  # Save user with hashed password
            return redirect(url_for('login'))
    return render_template('signin.html')


# Страница входа
@app.route('/AddSession/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = verify_login(email, password)

        if user:
            session['user'] = user['username']
            resp = make_response(redirect(url_for('profile')))
            resp.set_cookie('username', user['username'])
            return resp
        else:
            return redirect(url_for('login'))
    return render_template('login.html')


# Страница профиля
@app.route('/profile')
def profile():
    if 'user' in session:
        username = session['user']
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        mail_session = list(user)[2]
        cursor.execute('SELECT * FROM books WHERE usercode = ?', (user['usercode'],))
        publications = cursor.fetchall()
        conn.close()
        assets_resources = ["static/engine_assets/images/lobbysite_logo_btn.png",
                            "static/engine_assets/images/upload_btn.png",
                            "static/engine_assets/images/profile_pic.png", "static/engine_assets/images/MyLib_logo.png"]

        return render_template('profile.html', username=username, publications=reversed(publications),
                               mail_session=mail_session, asts_rsc = assets_resources)
    else:
        return redirect(url_for('login'))


# Выход из сессии
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))


# Скрипт сохранения профиля
@app.route('/save_profile', methods=['POST'])
def save_profile():
    if 'user' in session:
        username = session['user']
        new_username = request.form.get('username')
        user_email = request.form.get('user_email')
        userpass = request.form.get('userpass')

        if new_username and user_email and userpass:
            iv, ct = hash_password(userpass)

            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute('UPDATE users SET username = ?, mail = ?, password_iv = ?, password_ct = ? WHERE username = ?',
                           (new_username, user_email, iv, ct, username))
            conn.commit()
            conn.close()

            session.pop('user', None)
            return redirect(url_for('works'))
        else:
            return "Fields cannot be empty."
    else:
        return redirect(url_for('login'))


# API ADMIN PASS
ADMIN_PASS = SECRET_KEY
def get_publication(publicationcode):
    conn4api = get_db_connection()
    cursor = conn4api.cursor()
    cursor.execute('SELECT * FROM books WHERE publicationcode = ?', (publicationcode,))
    publication = cursor.fetchone()
    conn4api.close()
    return publication


def delete_publication(publicationcode):
    conn4api = get_db_connection()
    cursor = conn4api.cursor()
    cursor.execute('DELETE FROM books WHERE publicationcode = ?', (publicationcode,))
    conn4api.commit()
    conn4api.close()


class Publication(Resource):
    def get(self, publicationcode):
        publication = get_publication(publicationcode)
        if publication:
            publication_title = publication[1]
            publication_text = publication[2]
            return {'title': publication_title, 'text': publication_text}, 200
        else:
            return {'message': 'Публикация не найдена'}, 404

    def delete(self, publicationcode):
        auth_header = request.headers.get('Authorization')
        if auth_header != ADMIN_PASS:
            return {'message': 'Unauthorized'}, 401
        publication = get_publication(publicationcode)
        if publication:
            delete_publication(publicationcode)
            return {'message': 'Успешно'}, 200
        else:
            return {'message': 'Публикация не найдена'}, 404


api.add_resource(Publication, '/pubapi-<string:publicationcode>')


# Отладочное соединение с базой данных
def create_database():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Создаем таблицу users
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            mail TEXT NOT NULL,
            password TEXT NOT NULL,
            usercode TEXT NOT NULL
        )
    ''')

    # Создаем таблицу books
    cursor.execute('''
        CREATE TABLE books (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            text TEXT NOT NULL,
            author TEXT NOT NULL,
            usercode TEXT NOT NULL,
            likes INTEGER DEFAULT 0,
            publicationcode TEXT NOT NULL,
            path2pic TEXT
        )
    ''')

    # Создаем таблицу comments
    cursor.execute('''
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY,
            publicationcode TEXT NOT NULL,
            comment TEXT NOT NULL,
            usercode TEXT NOT NULL
        )
    ''')

    # Коммитим изменения и закрываем соединение
    conn.commit()
    conn.close()
    print(f"База данных '{DATABASE}' создана успешно.")


if __name__ == '__main__':
    # create_database()
    app.run(debug=False, host= '0.0.0.0', port=19502)
