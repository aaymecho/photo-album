#!flask/bin/python
import os
import sys
import boto3
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_bcrypt import Bcrypt
import pytz
from datetime import datetime
import pymysql.cursors
from boto3.dynamodb.conditions import Key, Attr
import uuid
import json
import exifread
import time
from flask import render_template, redirect
from flask import Flask, jsonify, abort, request, make_response, url_for
sys.path.append(os.path.abspath(os.path.join('..', 'utils')))
from env import AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, AWS_REGION, PHOTOGALLERY_S3_BUCKET_NAME, DYNAMODB_TABLE, DYNAMODB_USER_TABLE
from flask_mail import Mail, Message

serializer = URLSafeTimedSerializer(AWS_ACCESS_KEY)

app = Flask(__name__, static_url_path="")
bcrypt = Bcrypt(app)

dynamodb = boto3.resource('dynamodb', aws_access_key_id=AWS_ACCESS_KEY,
                          aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                          region_name=AWS_REGION)

table = dynamodb.Table(DYNAMODB_TABLE)
userTable = dynamodb.Table(DYNAMODB_USER_TABLE)

mail = Mail(app)


UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'media')
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def getExifData(path_name):
    f = open(path_name, 'rb')
    tags = exifread.process_file(f)
    ExifData = {}
    for tag in tags.keys():
        if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
            key = "%s" % (tag)
            val = "%s" % (tags[tag])
            ExifData[key] = val
    return ExifData


def s3uploading(filename, filenameWithPath, uploadType="photos"):
    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                      aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

    bucket = PHOTOGALLERY_S3_BUCKET_NAME
    path_filename = uploadType + "/" + filename

    s3.upload_file(filenameWithPath, bucket, path_filename)
    s3.put_object_acl(ACL='public-read', Bucket=bucket, Key=path_filename)
    return f'''http://{PHOTOGALLERY_S3_BUCKET_NAME}.s3.amazonaws.com/{path_filename}'''


"""
    INSERT YOUR NEW FUNCTION HERE (IF NEEDED)
"""


"""
"""

"""
    INSERT YOUR NEW ROUTE HERE (IF NEEDED)
"""


"""
"""


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


@app.route('/login', methods=['POST', 'GET'])
def login():
    return render_template('login.html')


@app.route('/confirmemail', methods=['GET'])
def confirm_page():
    return render_template('confirmemail.html')


@app.route('/confirmemail/<token>', methods=['GET', 'POST'])
def confirm_email(token):
    message = ''
    try:
        email = serializer.loads(token, salt='confirm-email', max_age=30)
    except SignatureExpired:
        message = 'faild'
        app.logger.info(message)
    except BadSignature:
        message = 'ewwwww'
        app.logger.info(message)
    return render_template('confirmemail.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Generate hashed password and hashed username
        hashedPassword = bcrypt.generate_password_hash(
            password).decode('utf-8')
        hashedUsername = bcrypt.generate_password_hash(
            username).decode('utf-8')

        try:
            # Attempt to retrieve user by hashed username
            response = userTable.get_item(
                Key={
                    "userID": hashedUsername,
                    "userEmail": email
                }
            )
            # Check if the user exists by looking for an item in the response
            if 'Item' in response:
                app.logger.info(
                    "Account with username %s already exists!", username)
                # Redirect or inform the user that the account exists
                return render_template('signup.html', error="Username already exists.")
            else:
                # If user does not exist, proceed to create a new one
                token = serializer.dumps(email, salt='confirm-email')
                userTable.put_item(
                    Item={
                        "userID": hashedUsername,
                        "userEmail": email,
                        "username": username,
                        "password": hashedPassword,
                        "verified": False
                    }
                )
                msg = Message('Confirm Email', sender='aaymecho3@gatech.edu', recipients=[email])
                msg.body = 'Your code is : ' + hashedUsername
                mail.send(msg)
                return redirect("confirmemail/")
        except Exception as e:
            app.logger.error("Signup error: %s", str(e))
            # Handle the exception and inform the user
            return render_template('signup.html', error="An error occurred during signup.")
    else:
        return render_template('signup.html')


@app.route('/', methods=['GET'])
def home_page():
    """ Home page route.

    get:
        description: Endpoint to return home page.
        responses: Returns all the albums.
    """
    response = table.scan(FilterExpression=Attr('photoID').eq("thumbnail"))
    results = response['Items']

    # if len(results) > 0:
    #     for index, value in enumerate(results):
    #         createdAt = datetime.strptime(str(results[index]['createdAt']), "%Y-%m-%d %H:%M:%S")
    #         createdAt_UTC = pytz.timezone("UTC").localize(createdAt)
    #         results[in.infodex]['createdAt'] = createdAt_UTC.astimezone(pytz.timezone("US/Eastern")).strftime("%B %d, %Y")

    return render_template('login.html', albums=results)


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
        uploadedFileURL = ''
        file = request.files['imagefile']
        name = request.form['name']
        description = request.form['description']

        if file and allowed_file(file.filename):
            albumID = uuid.uuid4()

            filename = file.filename
            filenameWithPath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filenameWithPath)

            uploadedFileURL = s3uploading(
                str(albumID), filenameWithPath, "thumbnails")

            createdAtlocalTime = datetime.now().astimezone()
            createdAtUTCTime = createdAtlocalTime.astimezone(pytz.utc)

            table.put_item(
                Item={
                    "albumID": str(albumID),
                    "photoID": "thumbnail",
                    "name": name,
                    "description": description,
                    "thumbnailURL": uploadedFileURL,
                    "createdAt": createdAtUTCTime.strftime("%Y-%m-%d %H:%M:%S")
                }
            )

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
    albumResponse = table.query(KeyConditionExpression=Key(
        'albumID').eq(albumID) & Key('photoID').eq('thumbnail'))
    albumMeta = albumResponse['Items']

    response = table.scan(FilterExpression=Attr('albumID').eq(
        albumID) & Attr('photoID').ne('thumbnail'))
    items = response['Items']

    return render_template('viewphotos.html', photos=items, albumID=albumID, albumName=albumMeta[0]['name'])


@app.route('/album/<string:albumID>/addPhoto', methods=['GET', 'POST'])
def add_photo(albumID):
    """ Create new photo under album route.

    get:
        description: Endpoint to return form to create a new photo.
        responses: Returns all the fields needed to store a new photo.

    post:
        description: Endpoint to send new photo.
        responses: Returns user to album page.
    """
    if request.method == 'POST':
        uploadedFileURL = ''
        file = request.files['imagefile']
        title = request.form['title']
        description = request.form['description']
        tags = request.form['tags']
        if file and allowed_file(file.filename):
            photoID = uuid.uuid4()
            filename = file.filename
            filenameWithPath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filenameWithPath)

            uploadedFdfghjuytyuileURL = s3uploading(filename, filenameWithPath)

            ExifData = getExifData(filenameWithPath)
            ExifDataStr = json.dumps(ExifData)

            createdAtlocalTime = datetime.now().astimezone()
            updatedAtlocalTime = datetime.now().astimezone()

            createdAtUTCTime = createdAtlocalTime.astimezone(pytz.utc)
            updatedAtUTCTime = updatedAtlocalTime.astimezone(pytz.utc)

            table.put_item(
                Item={
                    "albumID": str(albumID),
                    "photoID": str(photoID),
                    "title": title,
                    "description": description,
                    "tags": tags,
                    "photoURL": uploadedFileURL,
                    "EXIF": ExifDataStr,
                    "createdAt": createdAtUTCTime.strftime("%Y-%m-%d %H:%M:%S"),
                    "updatedAt": updatedAtUTCTime.strftime("%Y-%m-%d %H:%M:%S")
                }
            )

        return redirect(f'''/album/{albumID}''')

    else:

        albumResponse = table.query(KeyConditionExpression=Key(
            'albumID').eq(albumID) & Key('photoID').eq('thumbnail'))
        albumMeta = albumResponse['Items']

        return render_template('photoForm.html', albumID=albumID, albumName=albumMeta[0]['name'])


@app.route('/album/<string:albumID>/photo/<string:photoID>', methods=['GET'])
def view_photo(albumID, photoID):
    """ photo page route.

    get:
        description: Endpoint to return a photo.
        responses: Returns a photo from a particular album.
    """
    albumResponse = table.query(KeyConditionExpression=Key(
        'albumID').eq(albumID) & Key('photoID').eq('thumbnail'))
    albumMeta = albumResponse['Items']

    response = table.query(KeyConditionExpression=Key(
        'albumID').eq(albumID) & Key('photoID').eq(photoID))
    results = response['Items']

    if len(results) > 0:
        photo = {}
        photo['photoID'] = results[0]['photoID']
        photo['title'] = results[0]['title']
        photo['description'] = results[0]['description']
        photo['tags'] = results[0]['tags']
        photo['photoURL'] = results[0]['photoURL']
        photo['EXIF'] = json.loads(results[0]['EXIF'])

        createdAt = datetime.strptime(
            str(results[0]['createdAt']), "%Y-%m-%d %H:%M:%S")
        updatedAt = datetime.strptime(
            str(results[0]['updatedAt']), "%Y-%m-%d %H:%M:%S")

        createdAt_UTC = pytz.timezone("UTC").localize(createdAt)
        updatedAt_UTC = pytz.timezone("UTC").localize(updatedAt)

        photo['createdAt'] = createdAt_UTC.astimezone(
            pytz.timezone("US/Eastern")).strftime("%B %d, %Y")
        photo['updatedAt'] = updatedAt_UTC.astimezone(
            pytz.timezone("US/Eastern")).strftime("%B %d, %Y")

        tags = photo['tags'].split(',')
        exifdata = photo['EXIF']

        return render_template('photodetail.html', photo=photo, tags=tags, exifdata=exifdata, albumID=albumID, albumName=albumMeta[0]['name'])
    else:
        return render_template('photodetail.html', photo={}, tags=[], exifdata={}, albumID=albumID, albumName="")


@app.route('/album/search', methods=['GET'])
def search_album_page():
    """ search album page route.

    get:
        description: Endpoint to return all the matching albums.
        responses: Returns all the albums based on a particular query.
    """
    query = request.args.get('query', None)

    response = table.scan(FilterExpression=Attr('name').contains(
        query) | Attr('description').contains(query))
    results = response['Items']

    items = []
    for item in results:
        if item['photoID'] == 'thumbnail':
            album = {}
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

    response = table.scan(FilterExpression=Attr('title').contains(query) | Attr(
        'description').contains(query) | Attr('tags').contains(query) | Attr('EXIF').contains(query))
    results = response['Items']

    items = []
    for item in results:
        if item['photoID'] != 'thumbnail' and item['albumID'] == albumID:
            photo = {}
            photo['photoID'] = item['photoID']
            photo['albumID'] = item['albumID']
            photo['title'] = item['title']
            photo['description'] = item['description']
            photo['photoURL'] = item['photoURL']
            items.append(photo)

    return render_template('searchPhoto.html', photos=items, searchquery=query, albumID=albumID)


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
