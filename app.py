from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///league.db'
db = SQLAlchemy(app)

API_KEY = '2f44c6674d2e4e50ae2af7035fa971f6'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    points = db.Column(db.Integer, default=0)


class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    home_team = db.Column(db.String(50))
    away_team = db.Column(db.String(50))
    home_crest = db.Column(db.String(200))
    away_crest = db.Column(db.String(200))
    home_score = db.Column(db.Integer, nullable=True)
    away_score = db.Column(db.Integer, nullable=True)
    is_finished = db.Column(db.Boolean, default=False)
    match_date = db.Column(db.String(20))


class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    match_id = db.Column(db.Integer, db.ForeignKey('match.id'))
    pred_home = db.Column(db.Integer)
    pred_away = db.Column(db.Integer)
    points_earned = db.Column(db.Integer, default=0)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



def update_user_points(match):
    for p in Prediction.query.filter_by(match_id=match.id).all():
        pts = 0
        h, a = match.home_score, match.away_score
        ph, pa = p.pred_home, p.pred_away
        if ph == h and pa == a:
            pts = 3
        elif (ph > pa and h > a) or (ph < pa and h < a) or (ph == pa and h == a):
            pts = 1
        p.points_earned = pts
        User.query.get(p.user_id).points += pts
    db.session.commit()


def fetch_from_api(league):
    headers = {'X-Auth-Token': API_KEY}
    try:
        url = f'https://api.football-data.org/v4/competitions/{league}/matches?status=SCHEDULED'
        data = requests.get(url, headers=headers).json()
        count = 0
        for i in data.get('matches', [])[:10]:
            if not Match.query.filter_by(home_team=i['homeTeam']['name'], away_team=i['awayTeam']['name']).first():
                db.session.add(Match(
                    home_team=i['homeTeam']['name'], away_team=i['awayTeam']['name'],
                    home_crest=i['homeTeam']['crest'], away_crest=i['awayTeam']['crest'],
                    match_date=i['utcDate'][:10]
                ))
                count += 1
        db.session.commit()
        return count
    except:
        return 0


def update_scores_api(league):
    headers = {'X-Auth-Token': API_KEY}
    try:
        url = f'https://api.football-data.org/v4/competitions/{league}/matches?status=FINISHED'
        data = requests.get(url, headers=headers).json()
        count = 0
        for i in data.get('matches', []):
            m = Match.query.filter_by(home_team=i['homeTeam']['name'], away_team=i['awayTeam']['name'],
                                      is_finished=False).first()
            if m:
                m.home_score = i['score']['fullTime']['home']
                m.away_score = i['score']['fullTime']['away']
                m.is_finished = True
                update_user_points(m)
                count += 1
        return count
    except:
        return 0

@app.route('/')
def index():
    matches = Match.query.order_by(Match.is_finished, Match.id).all()

    my_preds = {}
    if current_user.is_authenticated:
        my_preds = {p.match_id: p for p in Prediction.query.filter_by(user_id=current_user.id).all()}

    return render_template('index.html', matches=matches, my_preds=my_preds)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect('/')
            else:
                flash('Неверный пароль', 'danger')
        else:
            # Авто-регистрация
            new_user = User(username=username, password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            flash('Регистрация успешна!', 'success')
            return redirect('/')

    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect('/login')


@app.route('/leaderboard')
def leaderboard():
    users = User.query.order_by(User.points.desc()).all()
    return render_template('leaderboard.html', users=users)


@app.route('/predict/<int:mid>', methods=['POST'])
@login_required
def predict(mid):
    if Match.query.get(mid).is_finished: return redirect('/')
    p = Prediction.query.filter_by(user_id=current_user.id, match_id=mid).first()
    if not p: p = Prediction(user_id=current_user.id, match_id=mid)
    p.pred_home = int(request.form['home_goals'])
    p.pred_away = int(request.form['away_goals'])
    db.session.add(p);
    db.session.commit()
    flash('Ставка принята', 'success')
    return redirect('/')


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.id != 1: return redirect('/')

    if request.method == 'POST':
        if 'api_load' in request.form:
            c = fetch_from_api(request.form.get('league_select'))
            flash(f'Загружено {c} матчей', 'success')
        elif 'api_update_scores' in request.form:
            c = update_scores_api(request.form.get('league_select'))
            flash(f'Обновлено {c} матчей', 'success')
        elif 'manual_add' in request.form:
            stub = "https://crests.football-data.org/PL.png"
            db.session.add(
                Match(home_team=request.form['home_team'], away_team=request.form['away_team'], home_crest=stub,
                      away_crest=stub))
            db.session.commit()
            flash('Матч создан', 'success')

    matches = Match.query.order_by(Match.id.desc()).all()
    return render_template('admin.html', matches=matches)


@app.route('/delete/<int:mid>')
@login_required
def delete_match(mid):
    if current_user.id != 1: return redirect('/')
    match = Match.query.get(mid)
    if match:
        Prediction.query.filter_by(match_id=mid).delete()
        db.session.delete(match)
        db.session.commit()
        flash('Матч удален', 'warning')
    return redirect('/admin')


@app.route('/simulate/<int:mid>')
@login_required
def simulate(mid):
    if current_user.id != 1: return redirect('/')
    m = Match.query.get(mid)
    if not m.is_finished:
        m.home_score = random.randint(0, 3)
        m.away_score = random.randint(0, 3)
        m.is_finished = True
        update_user_points(m)
        flash(f'Симуляция: Счет {m.home_score}:{m.away_score}', 'info')
    return redirect('/')


@app.route('/profile')
@login_required
def profile():
    predictions = Prediction.query.filter_by(user_id=current_user.id).all()

    total_preds = len(predictions)
    exact_score = 0
    correct_outcome = 0

    for p in predictions:
        if p.points_earned == 3:
            exact_score += 1
        elif p.points_earned == 1:
            correct_outcome += 1

    accuracy = 0
    if total_preds > 0:
        accuracy = round(((exact_score + correct_outcome) / total_preds) * 100, 1)

    return render_template('profile.html',
                           user=current_user,
                           total=total_preds,
                           exact=exact_score,
                           outcome=correct_outcome,
                           accuracy=accuracy)

if __name__ == '__main__':
    with app.app_context(): db.create_all()

    app.run(debug=True)
