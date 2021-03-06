import os
import secrets
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort
from flaskblog.forms import LoginForm, RegistrationForm, UpdateAccount, CreatePostForm, ResetPassword, PasswordChange
from flaskblog import app, db, bcrypt, mail
from flaskblog.models import User, Post
from flask_mail import Message

from flask_login import login_user, current_user, logout_user, login_required


@app.route("/")
@app.route("/home")
def hello():
    page = request.args.get("page", 1, type=int)
    posts = Post.query.order_by(Post.date_posted.desc()).paginate(per_page=5, page=page)

    return render_template('index.html', posts=posts)


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('hello'))
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Your account has been created {form.username.data}', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title="Register", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('hello'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            if next_page is not None:
                return redirect(next_page)
            else:
                return redirect(url_for('hello'))
        else:
            flash("Login Unsuccessfull.Please check username and password", "danger")

    return render_template("login.html", title="Login", form=form)


@app.route("/about")
def about():
    return render_template('about.html')


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('hello'))


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    f_name, f_ext = os.path.splitext(form_picture.filename)
    picture_n = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_n)
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_n


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    form = UpdateAccount()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file

        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash(f"Your account has been updated", "success")
        return redirect(url_for("account"))
    elif request.method == "GET":
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template("account.html", title="Account", img_url=image_file, form=form)


@app.route("/post/new", methods=["GET", "POST"])
@login_required
def new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash("Your Post has been created", "success")
        return redirect(url_for("hello"))

    return render_template("create_post.html", title="New Post", form=form, legend="Create Post")


@app.route("/post/<int:post_id>", methods=["GET"])
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template("post.html", title="Post-title", post=post)


@app.route("/post/<int:post_id>/update", methods=["GET", "POST"])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)

    form = CreatePostForm()

    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash("Your Post has been updated! ", "success")
        return redirect(url_for("post", post_id=post.id))
    elif request.method == "GET":
        form.title.data = post.title
        form.content.data = post.content
    return render_template("create_post.html", title="Update Post", form=form, legend="Update Post")


@app.route("/post/<int:post_id>/delete", methods=["POST"])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash("Your post has been deleted!", "success")
    return redirect(url_for("hello"))


@app.route("/user/<username>")
def user_posts(username):
    page = request.args.get("page", 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(user_id=user.id).order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template("user_posts.html", posts=posts, user=user)


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', sender="mr.veliyev97@gmail.com", recipients=[user.email], )
    msg.body = f"{user.username} to reset your password,visit the following links: {url_for('change_password', token=token, _external=True)} If you did not make this request please ignore it"
    mail.send(msg)


@app.route('/reset', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for("hello"))

    form = ResetPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash("Email has been sent with instructions for resetting your password", "infor")
        return redirect(url_for("login"))

    return render_template("reset_request.html", title="Reset", form=form)


@app.route("/change_password/<token>", methods=["GET", "POST"])
def change_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("hello"))
    user = User.verify_reset_token(token)

    if user is None:
        flash("That is an invalid or expired token", "warning")
        return redirect(url_for(reset_request))

    form = PasswordChange()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash(f'Your password has been changed!', 'success')
        return redirect(url_for('login'))

    return render_template("change_password.html", title="Change Password", form=form)
