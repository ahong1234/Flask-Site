"""
    Name: Alex Hong
    Course: SDEV300
    Instructor: L. Donoho
    Due: 7/12/22
    Description: A simple flask site with internal/external pages, registration, and login.
"""
import os
from datetime import datetime
from os import abort
from string import punctuation
from passlib.hash import sha256_crypt
from flask import Flask, render_template, flash, redirect, url_for, request, session

app = Flask(__name__)
app.secret_key = "helloworld"
debug = True


@app.route("/")
def home():
    """
    display the homepage
    """
    now = datetime.now()
    d_t = now.strftime("%a %b %d %Y (%I:%M:%S %p)")
    if "username" in session:
        return render_template("index.html", datetime=d_t)
    return redirect(url_for("login"))


@app.route("/about")
def about():
    """
    display the about us webpage
    """
    now = datetime.now()
    d_t = now.strftime("%a %b %d %Y (%I:%M:%S %p)")
    if "username" in session:
        return render_template("about.html", datetime=d_t)
    return "please log in first"


@app.route("/content")
def content():
    """
    display the services webpage
    """
    now = datetime.now()
    d_t = now.strftime("%a %b %d %Y (%I:%M:%S %p)")
    if "username" in session:
        return render_template("content.html", datetime=d_t)
    return "please log in first"


def is_registered(username):
    """
    Check if the user already exists in PASSFILE
    """
    with open("PASSFILE", "r", encoding='UTF-8') as passfile:
        for record in passfile:
            try:
                r_username, r_salt_hash = record.split()
                r_salt_hash += ""
                if username == r_username:
                    return True
            # this is to handle the initial blank file
            except ValueError:
                pass
    return False


def has_whitespace(username):
    """
    check if username has spaces
    """
    splitname = username.split()
    if len(splitname) > 1:
        return True
    return False


def is_complex(password):
    """
    Check if password is over 12 characters, has upper and lower letter, number, special character
    """
    if len(password) >= 12:
        if any(c.isupper() for c in password):
            if any(c.islower() for c in password):
                if any(c.isdigit() for c in password):
                    if any(c in punctuation for c in password):
                        return True
    return False


@app.route("/register", methods=['GET', 'POST'])
def register():
    """
    verify user submission of username and password
    """
    now = datetime.now()
    d_t = now.strftime("%a %b %d %Y (%I:%M:%S %p)")
    if request.method == "POST":
        username = None
        password = None
        username = request.form["username"]
        password = request.form["password"]
        error = None
        if not username:
            error = "Please enter a username"
        elif not password:
            error = "Please enter a password."
        elif is_registered(username):
            error = "username already exists"
        elif has_whitespace(username):
            error = "username contains space"
        elif not is_complex(password):
            error = "password too simple. must have upper and " \
                    "lower case, a number, a special character"
        if error:
            flash(error)
        else:
            password_hash = sha256_crypt.hash(password)
            with open("PASSFILE", "a", encoding='UTF-8') as passfile:
                passfile.write(username + " " + password_hash + "\n")
                flash("Registration successful. Please login.")
            return redirect(url_for("login"))
    return render_template("register.html", datetime=d_t)


def login_valid(username, password):
    """
    Lookup the user in PASSFILE and see if there are any matches. Verify password
    """
    with open("PASSFILE", "r", encoding='UTF-8') as passfile:
        for record in passfile:
            try:
                valid_user, valid_password = False, False
                r_username, r_salt_hash = record.split()
                if username == r_username:
                    valid_user = True
                if sha256_crypt.verify(password, r_salt_hash):
                    valid_password = True
                if valid_user and valid_password:
                    return True
            except ValueError:
                pass
    return False


@app.route("/login", methods=['GET', 'POST'])
def login():
    """
    take input of user credentials and verify if they are in passfile
    """
    now = datetime.now()
    d_t = now.strftime("%a %b %d %Y (%I:%M:%S %p)")
    if request.method == "POST":
        # assign user entry to variables
        username = request.form["username"]
        password = request.form["password"]
        user_ip = request.environ['REMOTE_ADDR']
        # check if the user and hash are in the file
        if not login_valid(username, password):
            with open("LOGFAIL", "a", encoding="UTF-8") as logfail:
                logfail.write(username + " " + password + " " + d_t + " " + user_ip + "\n")
                flash("Invalid username or password")
        else:
            session["username"] = username
            return redirect(url_for("home"))
    else:
        if "username" in session:
            return redirect(url_for("index"))
    return render_template("login.html", datetime=d_t)


@app.route("/table")
def table():
    """
    a page containing a 3 column 6 row table
    """
    now = datetime.now()
    d_t = now.strftime("%a %b %d %Y (%I:%M:%S %p)")
    if "username" in session:
        return render_template("table.html", datetime=d_t)
    return "Please log in first"


@app.route('/logout')
def logout():
    """
    pop username from session and return to login page
    """
    session.pop('username', None)
    return redirect(url_for('login'))


def isCommon(newpassword):
    """
    verify if an entered password is on the list of common passwords
    """
    with open("CommonPassword.txt", "r", encoding="UTF-8") as common_pass:
        for password in common_pass:
            r_password = password
            if newpassword.upper() + "\n" == r_password.upper():
                return True
        return False


@app.route("/updatePassword", methods=["GET", "POST"])
def updatePassword():
    """
    verify username and password. verify new password. update passfile with new password
    """
    now = datetime.now()
    d_t = now.strftime("%a %b %d %Y (%I:%M:%S %p)")
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        new_password = request.form["new password"]
        if not login_valid(username, password):
            flash("Invalid username or password. ")
        if isCommon(new_password):
            flash(f"\"{new_password}\" is a common password. Try another.")
        elif not is_complex(new_password):
            flash("Password not complex.")
        else:
            with open("PASSFILE", "r") as passfile, open("TEMPFILE", "a") as tempfile:
                for record in passfile:
                    try:
                        # split record from passfile into username and hash
                        r_username, r_salt_hash = record.split()
                        # create boolean for username match
                        same_username = username == r_username
                        # boolean for password match
                        same_password = sha256_crypt.verify(password, r_salt_hash)
                        if same_username and same_password:
                            t_salt_hash = sha256_crypt.hash(new_password)
                            tempfile.write(username + " " + t_salt_hash + "\n")
                        else:
                            tempfile.write(r_username + " " + r_salt_hash + "\n")
                    except ValueError:
                        pass
            # delete the password backup file
            try:
                os.remove("PASSFILE" + ".bak")
            except OSError:
                pass
            # this keeps a backup of the previous passfile
            os.rename("PASSFILE", "PASSFILE" + ".bak")
            os.rename("TEMPFILE", "PASSFILE")
            flash("Password changed")
    if "username" in session:
        return render_template("updatePassword.html", datetime=d_t)
    return "Please log in first"


if __name__ == "__main__":
    app.run()
