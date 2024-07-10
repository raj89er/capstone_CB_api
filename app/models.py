
from app import db
import secrets
from datetime import datetime, timedelta, timezone
from flask_bcrypt import Bcrypt
# from werkzeug.security import generate_password_hash, check_password_hash     ## replaced due to deprecation

bcrypt = Bcrypt()

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    date_joined = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    date_updated = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    token = db.Column(db.String(120), index=True, unique=True, nullable=True)
    token_expiration = db.Column(db.DateTime, nullable=True)
    recipes = db.relationship('Recipe', backref='author', lazy=True)
    favorites = db.relationship('Favorite', backref='user', lazy=True)
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if 'password' in kwargs:
            self.set_password(kwargs['password'])

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        if len(password) <= 7:
            raise ValueError("Safe, your recipes must be, 8 characters long your password should be.")
        if not any(char.isdigit() for char in password):
            raise ValueError("A number and letter. your password must contain,")
        try:
            # self.password = generate_password_hash(password)   ## replaced due to deprecation
            self.password = bcrypt.generate_password_hash(password).decode('utf-8')
            db.session.commit()
            return f"User {self.username}'s account has been secured."
        except Exception as e:
            db.session.rollback()
            return f"There was a disturbance in the force.. somewhere around: {e}"

    def check_password(self, password):
        # return check_password_hash(self.password, password)   ## replaced due to deprecation
        return bcrypt.check_password_hash(self.password, password)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def to_dict(self):
        data = {
            'user_id': self.user_id,
            'username': self.username,
            'email': self.email,
            'date_joined': self.date_joined,
            'date_updated': self.date_updated
        }
        return data

    def update(self, **kwargs):
        allowed_fields = ['username', 'email']
        for key, value in kwargs.items():
            if key in allowed_fields:
                setattr(self, key, value)
        try:
            self.save()
            return True
        except Exception as e:
            return False, f'Error updating user: {e}'
    
    def update_password(self, current_password, new_password):
        if not self.check_password(current_password):
            return f"You're memory has been tampered with. your old password is incorrect"
        try:
            self.set_password(new_password)
            return f"The account for {self.username} has been secured."
        except ValueError as e:
            return str(e)
        except Exception as e:
            return f"There was a disturbance in the force.. somewhere around: {e}"

    def get_token(self):
        now = datetime.now(timezone.utc)
        if self.token and self.token_expiration > now + timedelta(minutes=1):
            return {"token": self.token, "tokenExpiration": self.token_expiration}
        self.token = secrets.token_hex(16)
        self.token_expiration = now + timedelta(hours=1)
        self.save()
        return {"token": self.token, "tokenExpiration": self.token_expiration}

    @staticmethod
    def check_token(token):
        return User.query.filter_by(token=token).first() is not None


class Recipe(db.Model):
    recipe_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    date_created = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    date_updated = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    ingredients = db.Column(db.Text, nullable=False)
    instructions = db.Column(db.Text, nullable=False)
    favorites = db.relationship('Favorite', backref='recipe', lazy=True)
        
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def __repr__(self):
        return f'<Recipe "{self.title}">'

    def save(self):
        db.session.add(self)
        db.session.commit()

    def update(self, **kwargs):
        allowed_fields = ['title', 'tips', 'ingredients', 'instructions']
        for key, value in kwargs.items():
            if key in allowed_fields:
                setattr(self, key, value)
        try:
            self.save()
            return True, f"Recipe {self.title} has been updated."
        except Exception as e:
            db.session.rollback()
            return False, f'Error updating recipe: {e}'

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def to_dict(self):
        data = {
            'recipe_id': self.recipe_id,
            'user_id': self.user_id,
            'title': self.title,
            'date_created': self.date_created,
            'date_updated': self.date_updated,
            'ingredients': self.ingredients,
            'instructions': self.instructions
        }
        return data


class Favorite(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), primary_key=True)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipe.recipe_id'), primary_key=True)
    is_fav = db.Column(db.Boolean, default=False)
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
    def to_dict(self):
        data = {
            'user_id': self.user_id,
            'recipe_id': self.recipe_id,
            'is_fav': self.is_fav
        }
        return data
