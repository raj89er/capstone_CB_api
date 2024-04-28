
from flask import request, render_template
from . import app , db
from datetime import datetime, timezone
from .models import User, Recipe, Favorite
from .auth import basic_auth, token_auth

# Token route & endpoint
@app.route('/token', methods=['GET'])
@basic_auth.login_required
def get_token():
    user = basic_auth.current_user()
    return user.get_token()

# Home
@app.route("/")
def index():
    return render_template('index.html')

# [POST] /recipes
@app.route('/recipes', methods=['POST'])
def create_recipe():
    if not request.is_json:
        return {"error": "Please enter the JSON's suns"}, 400
    data = request.get_json()
    required_fields = ['title', 'ingredients', 'instructions']
    missing_fields = []
    for field in required_fields:
        if field not in data:
            missing_fields.append(field)
    if missing_fields:
        return {"error": f"Missing the following fields: {', '.join(missing_fields)}"}, 400
    new_recipe = Recipe(
        title=data['title'],
        ingredients=data['ingredients'],
        instructions=data['instructions'])
    try:
        db.session.add(new_recipe)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return {"error": str(e)}, 500
    # Return success message with created recipe information
    return new_recipe.to_dict(), 201
    

## [GET] /users/me
@app.route('/users/me', methods=['GET'])
@token_auth.login_required
def get_me():
    user = token_auth.current_user()
    return user.to_dict()


# [POST] /users
@app.route('/users', methods=['POST'])
def create_user():
    data = request.json
    # check request is json format
    if not request.is_json:
        return {"error": "Request must be in JSON format"}, 400
    # extract data from request
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    # check for required fields
    required_fields = ['username', 'password']
    missing_fields = []
    for field in required_fields:
        if field not in data:
            missing_fields.append(field)
    if missing_fields:
        return {"error": f"You are missing the following: {', '.join(missing_fields)}"}, 400
    # check for existing users with same username/email
    check_users = db.session.execute(db.select(User).where( (User.username == username) | (User.email == email) )).scalars().all()
    if check_users:
        return {"error": 'An account with that username or email already exists'}, 400
    # create instance of User and add to db
    new_user = User( username=username, email=email, password=password )
    db.session.add(new_user)
    db.session.commit()
    return {"message": f"User {new_user.username} created successfully", "user": new_user.to_dict()}, 201
    

## [GET] /user/<user_id>
@app.route('/users/<int:user_id>', methods=['GET'])
# @token_auth.login_required
def get_user(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        return {"error": "User not found"}, 404
    return user.to_dict() , 200

@app.route('/users/me', methods=['PUT'])
@token_auth.login_required
def update_user():
    user = token_auth.current_user()
    if user is None:
        return {"error": "User not found"}, 404
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    if username and username.strip():
        existing_username = User.query.filter(User.username == username, User.user_id != user.user_id).first()
        if existing_username:
            return {"error": "An account with that username already exists"}, 400
        user.username = username.strip()
    if email and email.strip():
        if not "@" in email:
            return {"error": "Invalid email format"}, 400
        existing_email = User.query.filter(User.email == email, User.user_id != user.user_id).first()
        if existing_email:
            return {"error": "An account with that email already exists"}, 400
        user.email = email.strip()
    if password and password.strip():
        if len(password) < 8:
            return {"error": "Password must be at least 8 characters long"}, 400
        user.set_password(password)
    try:
        db.session.commit()
        return {"YAY!!!": "User updated successfully"}, 200
    except Exception as e:
        db.session.rollback()
        return {"error": str(e)}, 500


## [DELETE] /users/me
@app.route('/users/me', methods=['DELETE'])
@token_auth.login_required
def delete_user():
    user = token_auth.current_user()
    if user is None:
        return {"error": "Disturbance in the force detected... You do not exist"}, 404
    db.session.delete(user)
    db.session.commit()
    return {"success": "User deleted successfully"}, 200


# Recipe routes & endpoints
## [GET] /recipes
@app.route('/recipes', methods=['GET'])
def get_recipes():
    recipes = db.session.query(Recipe).all()
    recipe_list = [recipe.to_dict() for recipe in recipes]
    return {"recipes": recipe_list}, 200


## [GET] /recipes/<recipe_id>
@app.route('/recipes/<int:recipe_id>', methods=['GET'])
def get_recipe(recipe_id):
    recipe = db.session.get(Recipe, recipe_id)
    if recipe:
        return recipe.to_dict(), 200
    else:
        return {'error': 'Recipe not found'}, 404


## [PUT] /recipes/<recipe_id>
@app.route('/recipes/<int:recipe_id>', methods=['PUT'])
def update_recipe(recipe_id):
    recipe = db.session.get(Recipe, recipe_id)
    if recipe is None:
        return {"error": f'Recipe with ID {recipe_id} not found'}, 404
    if recipe.user_id != token_auth.current_user().user_id:
        return {"error": "Stop trying to edit a recipe you didn't post!"}, 403
    data = request.json
    # Update recipe details
    recipe.update(**data)
    return {"success": "Recipe updated successfully"}, 200


# [DELETE] /recipes/<int:recipe_id>
@app.route('/recipes/<int:recipe_id>', methods=['DELETE'])
def delete_recipe(recipe_id):
    recipe = Recipe.query.get(recipe_id)
    if recipe is None:
        return {"error": "Recipe not found"}, 404
    for ingredient in recipe.ingredients:
        db.session.delete(ingredient)
    for direction in recipe.directions:
        db.session.delete(direction)
    db.session.delete(recipe)
    db.session.commit()
    return {"success": "Recipe has been deleted successfully"}, 200

# [GET] /favorites
@app.route('/favorites', methods=['GET'])
@token_auth.login_required
def get_favorites():
    current_user = token_auth.current_user()
    favorite_recipes = db.session.query(Recipe).join(Favorite).filter(Favorite.user_id == current_user.user_id, Favorite.is_favorite == True).all()
    favorite_list = []
    for recipe in favorite_recipes:
        favorite_list.append(recipe.to_dict())
    return {"favorites": favorite_list}, 200


# [POST] /favorites/<int:recipe_id>
@app.route('/favorites/<int:recipe_id>', methods=['POST'])
@token_auth.login_required
def toggle_favorite(recipe_id):
    current_user = token_auth.current_user()
    recipe = db.session.get(Recipe, recipe_id)
    if recipe is None:
        return {"error": f"Recipe with ID {recipe_id} not found"}, 404
    favorite = db.session.query(Favorite).filter_by(user_id=current_user.user_id, recipe_id=recipe_id).first()
    if favorite:
        favorite.is_favorite = not favorite.is_favorite
    else:
        favorite = Favorite(user_id=current_user.user_id, recipe_id=recipe_id)
        db.session.add(favorite)
    db.session.commit()
    return {"success": "Favorite status updated successfully"}, 200


# [DELETE] /favorites/<recipe_id>
@app.route('/favorites/<int:recipe_id>', methods=['DELETE'])
@token_auth.login_required
def remove_favorite(recipe_id):
    current_user = token_auth.current_user()
    favorite = db.session.query(Favorite).filter_by(user_id=current_user.user_id, recipe_id=recipe_id).first()
    if favorite:
        db.session.delete(favorite)
        db.session.commit()
        return {"success": "Recipe removed from favorites successfully"}, 200
    else:
        return {"error": "Recipe is not in your favorites"}, 404



