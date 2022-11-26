from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os.path

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)

# CONNECT TO DB
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(BASE_DIR, "instance/blog.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app,
                    size=200,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.relationship("User", back_populates="post")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    comments = db.relationship("Comments", back_populates="posts")


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    name = db.Column(db.String, nullable=False)
    post = db.relationship("BlogPost", back_populates="author")
    comments = db.relationship("Comments", back_populates="comment_author")


class Comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    comment_author = db.relationship("User", back_populates="comments")
    posts_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    posts = db.relationship("BlogPost", back_populates="comments")


# with app.app_context():
#     db.create_all()


# with app.app_context():
#     db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(f):
    wraps(f)

    def decorator(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.id != 1:
                return abort(403)
        return f(*args, **kwargs)

    decorator.__name__ = f.__name__
    return decorator


@app.route('/')
def get_all_posts():
    user_id = None
    posts = BlogPost.query.all()
    logged_in = current_user.is_authenticated
    if logged_in:
        user_id = current_user.id

    return render_template("index.html", all_posts=posts,
                           logged_in=current_user.is_authenticated,
                           user_id=user_id)


@app.route('/register', methods=["GET", "POST"])
def register():
    error = None
    register_form = RegisterForm()
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = generate_password_hash(request.form.get("password"), method="pbkdf2:sha256", salt_length=8)

        if User.query.filter_by(email=email).first() is None:
            user = User(email=email,
                        password=password,
                        name=name
                        )
            db.session.add(user)
            db.session.commit()

            login_user(user)
            return redirect(url_for("get_all_posts"))
        else:
            error = "This email already exist."
    return render_template("register.html", form=register_form, error=error)


@app.route('/login', methods=["GET", "POST"])
def login():
    error = None
    form = LoginForm()
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()

        if user is not None:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                error = "Wrong Password"
        else:
            error = "Email does not exists"

    return render_template("login.html", form=form, error=error)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    error = None
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if request.method == "POST":
        if current_user.is_authenticated:
            comment_text = request.form.get("text")

            new_comment = Comments(text=comment_text,
                                   posts=requested_post,
                                   comment_author=current_user)
            db.session.add(new_comment)
            db.session.commit()

            return redirect(url_for("show_post", post_id=post_id))
        else:
            flash("Only Logged In user Can Comment")
            return redirect(url_for("login"))

    get_comments = Comments.query.filter_by(posts_id=post_id).all()
    print(get_comments)
    return render_template(template_name_or_list="post.html",
                           post=requested_post,
                           logged_in=current_user.is_authenticated,
                           form=form,
                           error=error,
                           comments=get_comments,
                           gravatar=gravatar)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001, debug=True)
