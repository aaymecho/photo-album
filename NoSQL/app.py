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
from flask import render_template, redirect, session
from flask import Flask, jsonify, abort, request, make_response, url_for
sys.path.append(os.path.abspath(os.path.join('..', 'utils')))
from env import AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, AWS_REGION, PHOTOGALLERY_S3_BUCKET_NAME, DYNAMODB_TABLE, DYNAMODB_USER_TABLE, SES_EMAIL
from flask_mail import Mail, Message
from botocore.exceptions import ClientError
import uuid
from datetime import timedelta


serializer = URLSafeTimedSerializer(AWS_ACCESS_KEY)

app = Flask(__name__, static_url_path="")
app.secret_key = AWS_ACCESS_KEY
bcrypt = Bcrypt(app)
app.permanent_session_lifetime = timedelta(minutes=5)




dynamodb = boto3.resource('dynamodb', aws_access_key_id=AWS_ACCESS_KEY,
                          aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                          region_name=AWS_REGION)

table = dynamodb.Table(DYNAMODB_TABLE)
userTable = dynamodb.Table(DYNAMODB_USER_TABLE)


UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'media')
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])






def check_user_exist(value):
    response = userTable.scan(
        FilterExpression=Attr('username').eq(str(value))
    )
    userExist = response['Count'] > 0
    print(userExist)
    
    return userExist

def check_email_exist(value):
    response = userTable.query(
            KeyConditionExpression=Key('userEmail').eq(value),
            )
    emailExist = response['Count'] > 0
    print(emailExist)
    return emailExist


def send_email(email, body):
    try:
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

@app.route('/deleteAccount', methods=['POST', 'GET'])
def delete_account():
    if 'userID' in session:
        try:
            userTable.delete_item(
                Key={
                    "userEmail": session['userEmail']
                    }
                )
            session.clear()
            return redirect(url_for('home_page'))
        except:
            return {
                    "userEmail": session['userEmail'][0],
                    "msg": "Deleting email failed!"
                    }

    else:
        redirect(url_for('home_page'))
            

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        submitted_email = request.form.get('email')
        submitted_password = request.form.get('password')

        try:
            response = userTable.get_item(
                Key={'userEmail': submitted_email},
            )
            user = response.get('Item')
            if user and user.get('verified') and bcrypt.check_password_hash(user['password'], submitted_password):
                session['userEmail'] = submitted_email
                session['userID'] = user['userID']
                return redirect(url_for('home_page'))
            else:
                return render_template('login.html', message="Invalid email or password.")
        except Exception as e:
            print(e)
            return render_template('login.html', message="An error occurred during login.")
    else:
        return render_template('login.html')


@app.route('/confirmemail/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='confirmemail', max_age=600)
        userTable.update_item(
            Key={
                'userEmail': email
            },
            UpdateExpression="set verified = :v",
            ExpressionAttributeValues={
                ':v': True
            },
            ReturnValues="UPDATED_NEW"
        )
        return redirect(url_for('login'))
    except (BadSignature):
        return render_template('confirmemail.html', message="Confirmation link is invalid!")
    except SignatureExpired:
        return render_template('confirmemail.html', message="Confirmation link has expired!")





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
            emailExist = check_email_exist(email)
            userIDExist = check_user_exist(username)

            if emailExist or userIDExist:
                message = "An account with this username or email already exists."
                return render_template('signup.html', message=message)
            else:
                userTable.put_item(
                    Item={
                        "userEmail": email,
                        "userID": str(userID),
                        "username": username,
                        "password": hashedPassword,
                        "verified": False
                    }
                )

                token = serializer.dumps(email, salt='confirmemail')
                link = url_for('confirm_email', token=token, _external=True)
                send_email(email, body=f"Please click on the link to confirm your email: {link}")
                return render_template("confirmemail.html", message="You've been sent an email to confirm your account!")
        except Exception as e:
            app.logger.error("Signup error: %s", str(e))
            return render_template('signup.html', error="An error occurred during signup. Please try again.")
    else:
        return render_template('signup.html')

@app.route('/', methods=['GET'])
def home_page():
    if 'userID' in session:
        response = table.scan(FilterExpression=Attr('photoID').eq("thumbnail"))
        results = response['Items']
        for index, item in enumerate(results):
            createdAt = datetime.strptime(str(item['createdAt']), "%Y-%m-%d %H:%M:%S")
            createdAt_UTC = pytz.timezone("UTC").localize(createdAt)
            results[index]['createdAt'] = createdAt_UTC.astimezone(pytz.timezone("US/Eastern")).strftime("%B %d, %Y")
        return render_template('index.html', albums=results)
    else:
        session.clear()
        return redirect(url_for('login'))



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
    if 'userEmail' in session:
        if request.method == 'POST':
            uploadedFileURL = '' 
            file = request.files['imagefile']
            name = request.form['name']
            description = request.form['description']

            if file and allowed_file(file.filename):
                albumID = session['userID']
                print("Stored albumID: " + albumID)

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
    else:
        return redirect(url_for('login'))


@app.route('/updateAlbum/<string:albumID>', methods=['PATCH'])
def update_album(albumID):
    data = request.json
    new_name = data.get('name')
    new_description = data.get('description')
    print("name: " + new_name + " Description: " + new_description)

    response = table.update_item(
        Key={
            'albumID': albumID,
            'photoID': 'thumbnail'
        },
        UpdateExpression='SET #nm = :n, description = :d',
        ExpressionAttributeNames={
            '#nm': 'name'
        },
        ExpressionAttributeValues={
            ':n': new_name,
            ':d': new_description
        },
        ReturnValues="UPDATED_NEW"
    )

    updated_attributes = response.get('Attributes', {})
    if updated_attributes:
        return jsonify({
            'success': True,
            'message': 'Album updated successfully.',
            'updatedAlbum': updated_attributes
        }), 200
    else:
        return jsonify({
            'success': False,
            'message': 'Failed to update album.'
        }), 400





@app.route('/album/<string:albumID>/addPhoto', methods=['GET', 'POST'])
def add_photo(albumID):
    if 'userID' in session:
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

                uploadedFileURL = s3uploading(filename, filenameWithPath)

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
    else:
        return redirect(url_for('home_page'))


@app.route('/album/<string:albumID>/photo/<string:photoID>', methods=['GET', 'PATCH', 'DELETE'])
def view_photo(albumID, photoID):
    if 'userID' in session:
        if request.method == 'GET':
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
        elif request.method == 'PATCH':
            newTitle = request.form['title']
            newDescription = request.form['description']
            newTags = request.form['tags']
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            response = table.update_item(
                Key={
                    'albumID': albumID,
                    'photoID': photoID
                },
                UpdateExpression="SET title = :title, description = :description, tags = :tags, updatedAt = :updatedAt",
                ExpressionAttributeValues={
                    ':title': newTitle,
                    ':description': newDescription,
                    ':tags': newTags,
                    ':updatedAt': now
                },
                ReturnValues="UPDATED_NEW"
            )

            return jsonify({'message': 'Photo updated successfully', 'status': 'success'}), 200
        elif request.method == 'DELETE':
            try:
                response = table.delete_item(
                    Key={'albumID': albumID,
                        'photoID': photoID
                        }
                )
                return jsonify({'success': True, 'redirect_url': url_for('home_page')}), 200
            except Exception as e:
                print(e)
                return jsonify({'error': 'An error occurred'}), 500
        else:
            return redirect(url_for('home_page'))



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

@app.route('/album/<albumID>/delete', methods=['GET'])
def delete_album(albumID):
    # Query to find all photos with the given albumID
    response = table.query(
        KeyConditionExpression='albumID = :albumID',
        ExpressionAttributeValues={
            ':albumID': albumID
        }
    )

    # Iterate over the items and delete them one by one
    for item in response['Items']:
        table.delete_item(
            Key={
                'albumID': item['albumID'],
                'photoID': item['photoID'] 
            }
        )
    return redirect(url_for('home_page'))



@app.route('/album/<string:albumID>', methods=['GET'])
def view_photos(albumID):
    """ Album page route.

    get:
        description: Endpoint to return an album.
        responses: Returns all the photos of a particular album.
    """
    albumResponse = table.query(KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq('thumbnail'))
    albumMeta = albumResponse['Items']

    response = table.scan(FilterExpression=Attr('albumID').eq(albumID) & Attr('photoID').ne('thumbnail'))
    items = response['Items']

    return render_template('viewphotos.html', photos=items, albumID=albumID, albumName=albumMeta[0]['name'])

@app.route('/album/<string:albumID>/search', methods=['GET'])
def search_photo_page(albumID):
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