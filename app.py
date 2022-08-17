from flask import Flask, render_template, request, jsonify, url_for
from flask_cors import CORS
from flask_restful import abort
from werkzeug.utils import secure_filename
from flask_mysqldb import MySQL
from functools import wraps
import os
import jwt
import datetime
from subprocess import Popen, PIPE
import stripe
import random
import string

stripe_keys = {
  'secret_key': 'sk_test_51KL5fZSIeo8cbA9acaGiriXApreMJoliz1YnTX9SdweJMliwxVUeMDoU8zdb8nLFFVMmcUizp1S2BSlx1OVwhJ5j00i59tU6US',
  'publishable_key': 'pk_test_51KL5fZSIeo8cbA9aFNsoJYy35jp4ePQtnrJOSUwc34oMGcc0KL88oW1KB9jsdm0ZoShZwOh1zLba7yI6c6NxDIc200kIlLxI9q'
}

stripe.api_key = stripe_keys['secret_key']

app = Flask(__name__, static_url_path='/static')
SECRET_KEY = os.environ.get('SECRET_KEY') or '5j$@n324h@&$98redjrsdg43jh4*32$34&@5u4'

app.config['SECRET_KEY'] = SECRET_KEY
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'modelsDashboard2'

mysql = MySQL(app)
cors = CORS(app, resources={"*": {"origins": "*"}})

path = os.getcwd()
UPLOAD_FOLDER = os.path.join(path, 'models')
CSV_FOLDER = os.path.join(path, 'csv')

if not os.path.isdir(UPLOAD_FOLDER):
  os.mkdir(UPLOAD_FOLDER)

if not os.path.isdir(CSV_FOLDER):
  os.mkdir(CSV_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

class CursorByName():
  def __init__(self, cursor):
    self._cursor = cursor
  
  def __iter__(self):
    return self

  def __next__(self):
    row = self._cursor.__next__()
    return { description[0]: row[col] for col, description in enumerate(self._cursor.description) }


class dotdict(dict):
  """dot.notation access to dictionary attributes"""
  __getattr__ = dict.get
  __setattr__ = dict.__setitem__
  __delattr__ = dict.__delitem__


def token_required(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    token = None
    if "Authorization" in request.headers:
      token = request.headers["Authorization"].split(" ")[1]
    if not token:
      return {
        "message": "Authentication Token is missing!",
        "data": None,
        "error": "Unauthorized"
      }, 401
    try:
      data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])

      cursor = mysql.connection.cursor()
      cursor.execute("SELECT * FROM users WHERE id = %s", (data['public_id'],))
      current_user = cursor.fetchone()
      cursor.close()

      user = {
        "id": current_user[0],
        "username": current_user[1],
      }

      if current_user is None:
        return {
          "message": "Invalid Authentication token!",
          "data": None,
          "error": "Unauthorized"
        }, 401
    except Exception as e:
      return {
        "message": "Something went wrong",
        "data": None,
        "error": str(e)
      }, 500

    return f(user, *args, **kwargs)

  return decorated


@app.errorhandler(404)
def not_found(e):
  return render_template('admin.html')


@app.route('/admin')
def admin():
  return render_template('admin.html')


@app.route('/')
def index():
  cursor = mysql.connection.cursor()
  cursor.execute("SELECT * FROM models")
  columns = [column[0] for column in cursor.description]
  result = []

  for value in cursor.fetchall():
    tmp = {}
    for (index, column) in enumerate(value):
      tmp[columns[index]] = column
    result.append(tmp)

  cursor.close()

  return render_template('index.html', models=result)


@app.route('/results', methods=['GET'])
def results():
  modelID = request.args.get('model')
  data = request.args.get('data')
  userinfo = request.args.get('userinfo')
  cursor = mysql.connection.cursor()

  print(modelID)
  
  cursor.execute("SELECT * FROM models WHERE id = %s", (modelID,))
  model = cursor.fetchone()
  cursor.close()

  output = Popen(["python3", f'models/{model[4]}', str(data), str(userinfo)], stdout=PIPE)
  response, err = output.communicate()

  dataOutput = response.decode('utf-8')

  if modelID is None or data is None:
    return abort(400)

  return render_template('results.html', data=dataOutput, model_id=modelID, answers=data)


@app.route('/questions/<model_id>', methods=['GET'])
def questions(model_id):
  cursor = mysql.connection.cursor()
  cursor.execute("SELECT * FROM questions WHERE model_id = %s", (model_id,))
  columns = [column[0] for column in cursor.description]
  result = []

  for value in cursor.fetchall():
    tmp = {}
    for (index, column) in enumerate(value):
      tmp[columns[index]] = column
    result.append(tmp)

  cursor.close()
  
  return render_template('questions.html', questions=result)


@app.route('/reportform', methods=['GET'])
def reportform():
  return render_template('ReportForm.html')

@app.route('/api/login', methods=['POST'])
def loginAPI():
  username = request.json.get('username')
  password = request.json.get('password')
  cur = mysql.connection.cursor()
  cur.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
  data = cur.fetchone()
  cur.close()

  if data:
    token = jwt.encode({'public_id': data[0], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])  
    return jsonify({'token' : token})
  else:
    return jsonify({
      "message": "Invalid username or password"
    }), 401


@app.route('/api/token/check', methods=['POST'])
@token_required
def tokenCheckAPI(user):
  return jsonify({"message": "Token is valid"})


@app.route('/api/models', methods=['GET', 'POST'])
@token_required
def modelsAPI(user):
  if request.method == 'POST':
    name = request.form.get('name')
    description = request.form.get('description')
    price = request.form.get('price')
    model = request.files['model']

    model.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(model.filename)))

    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO models (name, description, price, model) VALUES (%s, %s, %s, %s)", (name, description, price, model.filename))
    mysql.connection.commit()
    cur.close()

    return jsonify({
      "message": "Model created successfully"
    }), 201

  if request.method == 'GET':
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM models')
    columns = [column[0] for column in cursor.description]
    result = []

    for value in cursor.fetchall():
      tmp = {}
      for (index, column) in enumerate(value):
          tmp[columns[index]] = column
      result.append(tmp)

    cursor.close()
    return jsonify(result)


@app.route('/api/models/<id>', methods=['DELETE'])
@token_required
def deleteModelAPI(user, id):
  cur = mysql.connection.cursor()
  cur.execute("DELETE FROM models WHERE id = %s", (id,))
  mysql.connection.commit()
  cur.close()

  return jsonify({
    "message": "Model deleted successfully"
  }), 200


@app.route('/api/models/<id>', methods=['POST'])
def useModelAPI(id):
  csv = request.files['csv']
  csv.save(os.path.join(CSV_FOLDER, secure_filename(csv.filename)))

  cur = mysql.connection.cursor()
  cur.execute("SELECT * FROM models WHERE id = %s", (id,))
  data = cur.fetchone()
  cur.close()

  if data:
    output = Popen(["python3", f'models/{data[3]}', os.path.join(CSV_FOLDER, secure_filename(csv.filename))], stdout=PIPE)
    response, err = output.communicate()

    tables = response.decode('utf-8')

    return render_template('OrderSubmitted.html', tables=tables)
  else:
    return jsonify({
      "message": "Model not found"
    }), 404


@app.route('/api/models/<id>', methods=['GET'])
def getModelAPI(id):
  cur = mysql.connection.cursor()
  cur.execute("SELECT * FROM models WHERE id = %s", (id,))
  data = cur.fetchone()

  return jsonify({
    "ID": data[0],
    "name": data[1],
    "description": data[2],
    "price": data[3],
    "model": data[4]
  })


@app.route('/api/questions', methods=['GET', 'POST', 'DELETE'])
@token_required
def questionsAPI(user):
  if request.method == 'POST':
    question = request.json.get('question')
    question_key = request.json.get('question_key')
    model_id = request.json.get('model_id')
    question_type = request.json.get('question_type')
    answers = request.json.get('answers')

    if answers == "":
      answers = None

    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO questions (question, question_key, model_id, question_type, answers) VALUES (%s, %s, %s, %s, %s)", (question, question_key, model_id, question_type, answers))
    mysql.connection.commit()
    cur.close()

    return jsonify({
      "message": "Question created successfully"
    }), 201

  if request.method == 'GET':
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM questions INNER JOIN models ON questions.model_id = models.id')
    columns = [column[0] for column in cursor.description]
    result = []

    for value in cursor.fetchall():
      tmp = {}
      for (index, column) in enumerate(value):
          tmp[columns[index]] = column
      result.append(tmp)

    cursor.close()
    return jsonify(result)


@app.route('/api/questions/<id>', methods=['DELETE'])
@token_required
def deleteQuestionAPI(user, id):
  cur = mysql.connection.cursor()
  cur.execute("DELETE FROM questions WHERE QuestionID = %s", (id,))
  mysql.connection.commit()
  cur.close()

  return jsonify({
    "message": "Question deleted successfully"
  }), 200


@app.route('/checkout/success/<session_id>', methods=['GET'])
def success(session_id):
  try:
    session = stripe.checkout.Session.retrieve(session_id)
    payment_intent = stripe.PaymentIntent.retrieve(session.payment_intent)
    checkout_id = payment_intent.metadata.get('checkout_id')
    model_id = payment_intent.metadata.get('model')

    if session.payment_status == 'paid':
      cur = mysql.connection.cursor()
      cur.execute("SELECT * FROM models WHERE id = %s", (model_id,))
      data = cur.fetchone()
      cur.close()

      if data:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM answers WHERE checkout_id = %s", (checkout_id,))
        answers = cur.fetchone()
        cur.close()

        if answers:
          output = Popen(["python3", f'models/{data[4]}', answers[1]], stdout=PIPE)
          response, err = output.communicate()

          tables = response.decode('utf-8')

          cur = mysql.connection.cursor()
          cur.execute("DELETE FROM answers WHERE checkout_id = %s", (checkout_id,))
          mysql.connection.commit()
          cur.close()

          return render_template('success.html', tables=tables)

    return render_template('error.html')
  except stripe.error.InvalidRequestError:
    return render_template('canceled.html')


@app.route('/checkout/canceled', methods=['GET'])
def cancel():
  return render_template('canceled.html')


@app.route("/config")
def get_publishable_key():
  stripe_config = {"publicKey": stripe_keys["publishable_key"]}
  return jsonify(stripe_config)


@app.route("/checkout", methods=["GET"])
def checkout():
  return render_template("checkout.html")


@app.route('/api/checkout/<model>/<answers>', methods=['GET'])
def checkoutApi(model, answers):
  cur = mysql.connection.cursor()
  cur.execute("SELECT * FROM models WHERE id = %s", (model,))
  data = cur.fetchone()
  cur.close()

  if data:
    checkout_id = ''.join(random.choice(string.ascii_letters) for i in range(32))
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO answers (answers, checkout_id) VALUES (%s, %s)", (answers, checkout_id))
    mysql.connection.commit()
    cur.close()

    product = stripe.Product.create(
      name=data[1],
    )

    # checkout using stripe
    price = stripe.Price.create(
      currency='inr',
      unit_amount=int(data[3]) * 100,
      product=product.id
    )

    session = stripe.checkout.Session.create(
      payment_method_types=['card'],
      mode='payment',
      line_items=[
        {
          'price': price.id,
          'quantity': 1,
        }
      ],
      payment_intent_data={
        'metadata': {
          'model': model,
          'checkout_id': checkout_id
        }
      },
      success_url='http://localhost:8000/checkout/success/{CHECKOUT_SESSION_ID}',
      cancel_url=url_for('cancel', _external=True)
    )

    return jsonify({"sessionId": session["id"]})

  return jsonify({
    "message": "Model not found"
  }), 404


# Edit model API
@app.route('/api/models/<id>', methods=['PUT'])
@token_required
def editModelAPI(user, id):
  cur = mysql.connection.cursor()
  cur.execute("SELECT * FROM models WHERE id = %s", (id,))
  data = cur.fetchone()

  if data:
    model_name = request.form.get('name') or data[1]
    model_description = request.form.get('description') or data[2]
    model_price = request.form.get('price') or data[3]
    model_path = dotdict({
      "filename": data[4]
    })

    if request.files.get('model', None):
      model_path = request.files['model']
      model_path.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(model_path.filename)))

    cur = mysql.connection.cursor()
    cur.execute("UPDATE models SET name = %s, description = %s, price = %s, model = %s WHERE ID = %s", (model_name, model_description, model_price, model_path.filename, id))
    mysql.connection.commit()
    cur.close()

    return jsonify({
      "message": "Model updated successfully"
    }), 200

  return jsonify({
    "message": "Model not found"
  }), 200


if __name__ == "__main__":
  app.run(debug=True, port=8000)