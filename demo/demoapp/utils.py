import os
import secrets
import hashlib
import uuid
from PIL import Image

from demoapp import app, db

# define the functions used
def create_secure_password(password, pepper):
    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',  
        password.encode('utf-8') + pepper.encode('utf-8'), 
        salt, 
        100_000
    )
    
    return salt, password_hash

def generate_unique_id(model, id_field_name):
    # generates a unique id for the db model that ensures the id is not already taken
    while True:
        unique_id = str(uuid.uuid4())
        field = getattr(model, id_field_name)
        if db.session.execute(db.select(model).filter(field == unique_id)).scalar_one_or_none() is None:
            return unique_id
    

OUT_SIZE = {'pfp': (125, 125), 'media': (200, 200)}


def save_picture(picture, pic_type):

    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(picture.filename)
    pic_fname = random_hex + f_ext
    pic_path = os.path.join(app.root_path, 'static/profile_pics/', pic_fname)
    
    # resize and save
    i = Image.open(picture)
    i.thumbnail(OUT_SIZE[pic_type])
    i.save(pic_path)

    # return filename
    return pic_fname


def save_media(picture, pic_type):

    random_hex = secrets.token_hex(10)
    _, f_ext = os.path.splitext(picture.filename)
    pic_fname = random_hex + f_ext
    pic_path = os.path.join(app.root_path, 'static/media/', pic_fname)
    
    i = Image.open(picture)
    # resize and save
    bwidth = 600
    ratio = bwidth / float(i.size[0])
    height = int((float(i.size[1]) * ratio))
    i = i.resize((bwidth, height))
    i.save(pic_path)

    # save thumb now
    j = Image.open(picture)

    bwidth = 125
    ratio = bwidth / float(j.size[0])
    height = int((float(j.size[1]) * ratio))
    j = j.resize((bwidth, height))
    thumb_path = os.path.join(app.root_path, 'static/media/', 'thumb' + pic_fname)
    j.save(thumb_path)

    # save display image for explore and user page
    k = Image.open(picture)
    bwidth = 500
    ratio = bwidth / float(j.size[0])
    height = int((float(j.size[1]) * ratio))
    k = k.resize((bwidth, height))
    mid_path = os.path.join(app.root_path, 'static/media/', 'mid' + pic_fname)
    k.save(mid_path)

    # return filename
    return pic_fname


def get_file_url(f_path):
    url = os.path.join(app.root_path, 'static', f_path)

    return url


def delete_file(f_path):
    base_path = os.path.join(app.root_path, 'static', 'media/')
    for item in ['', 'mid', 'thumb']:
        file_path = os.path.join(base_path, item + f_path)
        if os.path.exists(file_path):
            os.remove(file_path)