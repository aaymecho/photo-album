#!flask/bin/python
import sys, os
sys.path.append(os.path.abspath(os.path.join('..', 'utils')))
from env import AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, AWS_REGION, PHOTOGALLERY_S3_BUCKET_NAME, RDS_DB_HOSTNAME, RDS_DB_USERNAME, RDS_DB_PASSWORD, RDS_DB_NAME, SES_EMAIL
from flask import Flask, jsonify, abort, request, make_response, url_for
from flask import render_template, redirect, session
import time
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_bcrypt import Bcrypt
from datetime import datetime
import exifread
import json
import uuid
import boto3  
import pymysql.cursors
from datetime import datetime
from pytz import timezone
import uuid
from datetime import timedelta
from botocore.exceptions import ClientError

# Append utils path to sys.path
sys.path.append(os.path.abspath(os.path.join('..', 'utils')))


serializer = URLSafeTimedSerializer(AWS_ACCESS_KEY)


app = Flask(__name__, static_url_path="")
app.secret_key = AWS_ACCESS_KEY
bcrypt = Bcrypt(app)
app.permanent_session_lifetime = timedelta(minutes=293213)


UPLOAD_FOLDER = os.path.join(app.root_path,'static','media')
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def getExifData(path_name):
    f = open(path_name, 'rb')
    tags = exifread.process_file(f)
    ExifData={}
    for tag in tags.keys():
        if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
            key="%s"%(tag)
            val="%s"%(tags[tag])
            ExifData[key]=val
    return ExifData



def s3uploading(filename, filenameWithPath, uploadType="photos"):
    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                            aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
                       
    bucket = PHOTOGALLERY_S3_BUCKET_NAME
    path_filename = uploadType + "/" + filename

    s3.upload_file(filenameWithPath, bucket, path_filename)  
    s3.put_object_acl(ACL='public-read', Bucket=bucket, Key=path_filename)
    return f'''http://{PHOTOGALLERY_S3_BUCKET_NAME}.s3.amazonaws.com/{path_filename}'''

def get_database_connection():
    conn = pymysql.connect(host=RDS_DB_HOSTNAME,
                             user=RDS_DB_USERNAME,
                             password=RDS_DB_PASSWORD,
                             db=RDS_DB_NAME,
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor)
    return conn

def send_email(email, body):
    try:
        print("Sent confirmation to " + email)
        ses = boto3.client('ses', aws_access_key_id=AWS_ACCESS_KEY,
                                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                                region_name=AWS_REGION)
        response = ses.send_email(
            Source=SES_EMAIL,
            Destination={'ToAddresses': [email]},
            Message={
                'Subject': {'Data': 'Photo Gallery: Confirm Your Account'},
                'Body': {
                    'Text': {'Data': body}
                }
            }
        )

    except ClientError as e:
        print(e.response['Error']['Message'])

        return False
    else:
        print("Email sent! Message ID:"),
        print(response['MessageId'])

        return True

@app.errorhandler(400)
def bad_request(error):
    """ 400 page route.

    get:
        description: Endpoint to return a bad request 400 page.
        responses: Returns 400 object.
    """
    return make_response(jsonify({'error': 'Bad request'}), 400)



@app.errorhandler(404)
def not_found(error):
    """ 404 page route.

    get:
        description: Endpoint to return a not found 404 page.
        responses: Returns 404 object.
    """
    return make_response(jsonify({'error': 'Not found'}), 404)


@app.route('/updateAlbum/<string:albumID>', methods=['PATCH'])
def update_album(albumID):
    data = request.json
    new_name = data.get('name')
    new_description = data.get('description')
    print("name: " + new_name + " Description: " + new_description)

    try:
        conn = get_database_connection()
        cursor = conn.cursor()
        update_query = """
        UPDATE Album
        SET name = %s, description = %s
        WHERE albumID = %s
        """
        cursor.execute(update_query, (new_name, new_description, albumID))
        affected_rows = cursor.rowcount
        conn.commit()
        cursor.close()

        if affected_rows > 0:
            return jsonify({
                'success': True,
                'message': 'Album updated successfully.'
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to update album or no change made.'
            }), 400
    except:
        print("An error occurred:", e)
        return jsonify({
            'success': False,
            'message': 'Failed to update album due to an error.'
        }), 500


@app.route('/album/<albumID>/delete', methods=['GET'])
def delete_album(albumID):

    try:
        conn = get_database_connection()
        cursor = conn.cursor()
        delete_query_two = "DELETE FROM Album WHERE albumID = %s"
        print("AlbumID: " + albumID)
        delete_query_one = "DELETE FROM Photo WHERE albumID = %s"
        cursor.execute(delete_query_one, (albumID))
        cursor.execute(delete_query_two, (albumID))
        conn.commit()
        cursor.close()
    except:
        print("Something went wrong deleting the album")
    return redirect(url_for('home_page'))


@app.route('/', methods=['GET', 'POST'])
def home_page():
    if 'userID' in session:
        conn=get_database_connection()
        cursor = conn.cursor ()
        cursor.execute("SELECT * FROM photogallerydb.Album;")
        results = cursor.fetchall()
        conn.close()
        
        items=[]
        for item in results:
            album={}
            album['albumID'] = item['albumID']
            album['name'] = item['name']
            album['description'] = item['description']
            album['thumbnailURL'] = item['thumbnailURL']

            createdAt = datetime.strptime(str(item['createdAt']), "%Y-%m-%d %H:%M:%S")
            createdAt_UTC = timezone("UTC").localize(createdAt)
            album['createdAt']=createdAt_UTC.astimezone(timezone("US/Eastern")).strftime("%B %d, %Y")

            items.append(album)
        return render_template('index.html', albums=items)
    else:
        session.clear()
        return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashedPassword = bcrypt.generate_password_hash(password).decode('utf-8')
        userID = uuid.uuid4()
        message = ""

        try:
            connection = get_database_connection()
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM User WHERE email = %s OR username = %s", (email, username))
                if cursor.fetchone() is not None:
                    message = "An account with this username or email already exists."
                    return render_template('signup.html', message=message)
                else:
                    cursor.execute("INSERT INTO User (userID, username, email, password, verified) VALUES (%s, %s, %s, %s, %s)",
                                   (str(userID), username, email, hashedPassword, False))
                    connection.commit()
                    connection.close()

                    token = serializer.dumps(email, salt='confirmemail')
                    link = url_for('confirm_email', token=token, _external=True)
                    send_email(email, body=f"Please click on the link to confirm your email: {link}")
                    print('Redirecting to confirmation page')
                    return render_template("confirmemail.html", message="You've been sent an email to confirm your account!")
        except Exception as e:
            app.logger.error("Signup error: %s", str(e))
            return render_template('signup.html', error="An error occurred during signup. Please try again.")
    else:
        return render_template('signup.html')


@app.route('/confirmemail/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='confirmemail', max_age=600)
        connection = get_database_connection()
        try:
            with connection.cursor() as cursor:
                sql = "UPDATE User SET verified = %s WHERE email = %s"
                cursor.execute(sql, (True, email))
                connection.commit()
        finally:
            connection.close()
        return redirect(url_for('login'))
    except BadSignature:
        return render_template('confirmemail.html', message="Confirmation link is invalid!")
    except SignatureExpired:
        return render_template('confirmemail.html', message="Confirmation link has expired!")

@app.route('/createAlbum', methods=['GET', 'POST'])
def add_album():
    """ Create new album route.

    get:
        description: Endpoint to return form to create a new album.
        responses: Returns all the fields needed to store new album.

    post:
        description: Endpoint to send new album.
        responses: Returns user to home page.
    """
    if request.method == 'POST':
        uploadedFileURL=''
        file = request.files['imagefile']
        name = request.form['name']
        description = request.form['description']

        if file and allowed_file(file.filename):
            albumID = uuid.uuid4()
            
            filename = file.filename
            filenameWithPath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filenameWithPath)
            
            uploadedFileURL = s3uploading(str(albumID), filenameWithPath, "thumbnails");

            conn=get_database_connection()
            cursor = conn.cursor ()
            statement = f'''INSERT INTO photogallerydb.Album (albumID, name, description, thumbnailURL) VALUES ("{albumID}", "{name}", "{description}", "{uploadedFileURL}");'''
            
            result = cursor.execute(statement)
            conn.commit()
            cursor.close()

        return redirect('/')
    else:
        return render_template('albumForm.html')



@app.route('/album/<string:albumID>', methods=['GET'])
def view_photos(albumID):
    """ Album page route.

    get:
        description: Endpoint to return an album.
        responses: Returns all the photos of a particular album.
    """
    conn=get_database_connection()
    cursor = conn.cursor ()
    # Get title
    statement = f'''SELECT * FROM photogallerydb.Album WHERE albumID="{albumID}";'''
    cursor.execute(statement)
    albumMeta = cursor.fetchall()
    
    # Photos
    statement = f'''SELECT photoID, albumID, title, description, photoURL FROM photogallerydb.Photo WHERE albumID="{albumID}";'''
    cursor.execute(statement)
    results = cursor.fetchall()
    conn.close() 
    
    items=[]
    for item in results:
        photos={}
        photos['photoID'] = item['photoID']
        photos['albumID'] = item['albumID']
        photos['title'] = item['title']
        photos['description'] = item['description']
        photos['photoURL'] = item['photoURL']
        items.append(photos)

    return render_template('viewphotos.html', photos=items, albumID=albumID, albumName=albumMeta[0]['name'])



@app.route('/album/<string:albumID>/addPhoto', methods=['GET', 'POST'])
def add_photo(albumID):
    if request.method == 'POST':    
        uploadedFileURL=''
        file = request.files['imagefile']
        title = request.form['title']
        description = request.form['description']
        tags = request.form['tags']

        if file and allowed_file(file.filename):
            photoID = uuid.uuid4()
            filename = file.filename
            filenameWithPath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filenameWithPath)            
            
            uploadedFileURL = s3uploading(filename, filenameWithPath);
            
            ExifData=getExifData(filenameWithPath)

            conn=get_database_connection()
            cursor = conn.cursor ()
            ExifDataStr = json.dumps(ExifData)
            statement = f'''INSERT INTO photogallerydb.Photo (PhotoID, albumID, title, description, tags, photoURL, EXIF) VALUES ("{photoID}", "{albumID}", "{title}", "{description}", "{tags}", "{uploadedFileURL}", %s);'''
            
            result = cursor.execute(statement, (ExifDataStr,))
            conn.commit()
            conn.close()

        return redirect(f'''/album/{albumID}''')
    else:
        conn=get_database_connection()
        cursor = conn.cursor ()
        # Get title
        statement = f'''SELECT * FROM photogallerydb.Album WHERE albumID="{albumID}";'''
        cursor.execute(statement)
        albumMeta = cursor.fetchall()
        conn.close()

        return render_template('photoForm.html', albumID=albumID, albumName=albumMeta[0]['name'])



@app.route('/deleteAccount', methods=['POST', 'GET'])
def delete_account():
    if 'userID' in session:
        try:
            connection = get_database_connection()
            cursor = connection.cursor()
            query_server = "DELETE FROM User WHERE email = %s"
            cursor.execute(query_server, (session['userEmail']))
            connection.commit()
            connection.close()
            session.clear()
            return redirect(url_for('home_page'))
        except Exception as e:
            return {
                "userEmail": session['userEmail'],
                "msg": "Deleting email failed!"
            }
    else:
        return redirect(url_for('home_page'))



@app.route('/album/<string:albumID>/photo/<string:photoID>', methods=['GET', 'PATCH', 'DELETE'])
def view_photo(albumID, photoID):
    if(request.method == 'GET'):
        print("GOT INSIDE THE GET HOMIE")
        conn=get_database_connection()
        cursor = conn.cursor ()

        statement = f'''SELECT * FROM photogallerydb.Album WHERE albumID="{albumID}";'''
        cursor.execute(statement)
        albumMeta = cursor.fetchall()

        statement = f'''SELECT * FROM photogallerydb.Photo WHERE albumID="{albumID}" and photoID="{photoID}";'''
        cursor.execute(statement)
        results = cursor.fetchall()
        conn.close()
        if len(results) > 0:
            photo={}
            photo['photoID'] = results[0]['photoID']
            photo['title'] = results[0]['title']
            photo['description'] = results[0]['description']
            photo['tags'] = results[0]['tags']
            photo['photoURL'] = results[0]['photoURL']
            photo['EXIF']=json.loads(results[0]['EXIF'])

            createdAt = datetime.strptime(str(results[0]['createdAt']), "%Y-%m-%d %H:%M:%S")
            updatedAt = datetime.strptime(str(results[0]['updatedAt']), "%Y-%m-%d %H:%M:%S")

            createdAt_UTC = timezone("UTC").localize(createdAt)
            updatedAt_UTC = timezone("UTC").localize(updatedAt)

            photo['createdAt']=createdAt_UTC.astimezone(timezone("US/Eastern")).strftime("%B %d, %Y")
            photo['updatedAt']=updatedAt_UTC.astimezone(timezone("US/Eastern")).strftime("%B %d, %Y")
            
            tags=photo['tags'].split(',')
            exifdata=photo['EXIF']
            
            return render_template('photodetail.html', photo=photo, tags=tags, exifdata=exifdata, albumID=albumID, albumName=albumMeta[0]['name'])
        else:
            return render_template('photodetail.html', photo={}, tags=[], exifdata={}, albumID=albumID, albumName="")

    elif request.method == 'PATCH':
        try:
            newTitle = request.form['title']
            newDescription = request.form['description']
            newTags = request.form['tags']
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print ("PhotoID: " + photoID + " AlbumID: " + albumID)
            conn=get_database_connection()
            cursor = conn.cursor ()


            update_query = f'''
            UPDATE Photo
            SET title = %s, description = %s, tags = %s, updatedAt = %s
            WHERE photoID = %s AND albumID = %s
            '''
            cursor.execute(update_query, (newTitle, newDescription, newTags, now, photoID,albumID))
            affected_rows = cursor.rowcount
            conn.commit()
            conn.close()

            if affected_rows > 0:
                return jsonify({
                    'success': True,
                    'message': "Photo has been updated"
                })
            else:
                return jsonify({
                    'success': False,
                    'message': "Failed to update photo"
                })
        except:
            print("Something went wrong in the photo patch")   
    elif request.method == "DELETE":
        try:
            delete_query = f'''
            DELETE FROM Photo
            WHERE photoID = %s AND albumID = %s
            '''
            conn = get_database_connection()
            cursor = conn.cursor()
            cursor.execute(delete_query, (photoID, albumID))
            affected_rows = cursor.rowcount
            conn.commit()
            conn.close()

            if affected_rows > 0:
                return jsonify({
                    'success': True,
                    'message': "Photo has been updated",
                    'redirect_url': "/"
                })
            else:
                return jsonify({
                    'success': False,
                    'message': "Failed to update photo"
                })
        except Exception as e:
            print("Something went wrong in the photo delete:", e)
            return jsonify({
                'success': False,
                'message': "An error occurred during the delete process"
            })
  
    else:
        return redirect(url_for('home_page'))


@app.route('/album/search', methods=['GET'])
def search_album_page():
    query = request.args.get('query', None)

    conn=get_database_connection()
    cursor = conn.cursor ()
    statement = f'''SELECT * FROM photogallerydb.Album WHERE name LIKE '%{query}%' UNION SELECT * FROM photogallerydb.Album WHERE description LIKE '%{query}%';'''
    cursor.execute(statement)

    results = cursor.fetchall()
    conn.close()

    items=[]
    for item in results:
        album={}
        album['albumID'] = item['albumID']
        album['name'] = item['name']
        album['description'] = item['description']
        album['thumbnailURL'] = item['thumbnailURL']
        items.append(album)

    return render_template('searchAlbum.html', albums=items, searchquery=query)



@app.route('/album/<string:albumID>/search', methods=['GET'])
def search_photo_page(albumID):
    """ search photo page route.

    get:
        description: Endpoint to return all the matching photos.
        responses: Returns all the photos from an album based on a particular query.
    """ 
    query = request.args.get('query', None)

    conn=get_database_connection()
    cursor = conn.cursor ()
    statement = f'''SELECT * FROM photogallerydb.Photo WHERE title LIKE '%{query}%' AND albumID="{albumID}" UNION SELECT * FROM photogallerydb.Photo WHERE description LIKE '%{query}%' AND albumID="{albumID}" UNION SELECT * FROM photogallerydb.Photo WHERE tags LIKE '%{query}%' AND albumID="{albumID}" UNION SELECT * FROM photogallerydb.Photo WHERE EXIF LIKE '%{query}%' AND albumID="{albumID}";'''
    cursor.execute(statement)

    results = cursor.fetchall()
    conn.close()

    items=[]
    for item in results:
        photo={}
        photo['photoID'] = item['photoID']
        photo['albumID'] = item['albumID']
        photo['title'] = item['title']
        photo['description'] = item['description']
        photo['photoURL'] = item['photoURL']
        items.append(photo)

    return render_template('searchPhoto.html', photos=items, searchquery=query, albumID=albumID)


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        submitted_email = request.form.get('email')
        submitted_password = request.form.get('password').encode('utf-8')

        try:
            connection = get_database_connection()
            with connection.cursor() as cursor:
                cursor.execute("SELECT userID, email, password, verified FROM User WHERE email = %s", (submitted_email,))
                user = cursor.fetchone()

                if user and user['verified'] and bcrypt.check_password_hash(user['password'].encode('utf-8'), submitted_password):
                    session['userEmail'] = user['email']
                    session['userID'] = user['userID']
                    return redirect(url_for('home_page'))
                else:
                    return render_template('login.html', message="Invalid email or password.")
        except Exception as e:
            print(e)
            return render_template('login.html', message="An error occurred during login.")
        finally:
            connection.close()
    else:
        return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)



if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
