## Cookbook CRUD App Design and Functionality

### Database Design (ERD)

#### Users Table
    
    | Field             | Data Type        | Key            |
    |-------------------|------------------|----------------|
    | user_id           | INT              | Primary        |
    | username          | TEXT(50)         | Unique, not null |
    | email             | TEXT(50)         | Unique         |
    | password          | TEXT             | Not null       |
    | token             | TEXT             |                |
    | token_expiration  | DATETIME         |                |

#### Recipes Table
    
    | Field         | Data Type    | Key       |
    |---------------|--------------|-----------|
    | recipe_id     | INT          | Primary   |
    | title         | TEXT         | Not null  |
    | cook_time     | INT          |           |
    | prep_time     | INT          |           |
    | ingredients   | Relationship |           |
    | directions    | Relationship |           |
    | tips          | TEXT         |           |
    | created_at    | DATETIME     | Default   |
    | user_id       | INT          | Foreign   |

#### Ingredients Table
    
    | Field         | Data Type    | Key       |
    |---------------|--------------|-----------|
    | ingredient_id | INT          | Primary   |
    | name          | TEXT(100)    | Not null  |
    | quantity      | FLOAT        |           |
    | units         | TEXT(20)     |           |
    | recipe_id     | INT          | Foreign   |

#### Directions Table
    Stores sequential instructions for recipes.
    
    | Field         | Data Type    | Key       |
    |---------------|--------------|-----------|
    | direction_id  | INT          | Primary   |
    | step_number   | INT          | Not null  |
    | instruction   | TEXT         | Not null  |
    | recipe_id     | INT          | Foreign   |

#### Favorites Table
    
    | Field         | Data Type    | Key       |
    |---------------|--------------|-----------|
    | user_id       | INT          | Primary   |
    | recipe_id     | INT          | Primary   |
    | is_favorite   | BOOLEAN      | Not null  |



### API Routes and Endpoints

### [POST] [/token]
- **Description**: Authenticate and receive an access token.
- **Auth Required**: Basic Auth (Username & Password)

### [GET] [/users/me]
- **Description**: Retrieve the current user's details.
- **Auth Required**: Token Auth

## [PUT] [/users/me]
- **Description**: Update the current user's details.
- **Auth Required**: Token Auth
- **Sample Payload**:
```
{
    "username": "yikes",
    "email": "pandorasb@temple.jed",
    "password": "qwer1234"
}
```

[PUT] [/users/me]
- **Authorization**: Bearer <access-token>
- **Content-Type** application/json
```
{
    "username": "okenobi",
    "email": "okenobi@temple.jed",
    "password": "qwer1234"
}
{
    "username": "yikes",
    "email": "pandorasb@temple.jed",
    "password": "qwer1234"
}
{
    "username": "bombadil",
    "email": "pandor@temple.jed",
    "password": "qwer1234"
}
```
[POST] [/recipes]
- **Authorization**: No
- sample paylod
```

```
[GET] [/recipes]
Description: Retrieve all recipes.
Auth Required: No

[GET] [/recipes/<recipe_id>]

[PUT] [/recipes/<recipe_id>]
Description: Update an existing recipe.
Auth Required: Token Auth
```
{
  "title": "Updated Chocolate Cake",
  "cook_time": 50
}
```
[DELETE] [/recipes/<recipe_id>]
Description: Delete a specific recipe.
Auth Required: Token Auth

[GET] [/favorites]
Description: Retrieve all favorite recipes of the current user.
Auth Required: Token Auth

[POST] [/favorites/<recipe_id>]

[DELETE] [/favorites/<recipe_id>]



### Navbar and Pages
- **Navbar:**
  - Include links to the home page, recipes page, login page, and about us page for easy navigation.
  - Implement a search bar for users to search for specific recipes.
- **Home Page:**
  - Display a welcome message and brief introduction to the app.
  - Provide quick access to popular or featured recipes.
- **Recipes Page:**
  - Show a list or grid view of all available recipes.
  - Include sorting and filtering options (e.g., by category, cuisine, cooking time).
- **Recipe Details Page:**
  - When a recipe is clicked, navigate to a dedicated recipe details page.
  - Display recipe name, description, ingredients with quantities, directions, cook time, prep time, and other relevant details.
  - Include buttons to toggle ingredient visibility and mark ingredients as crossed out when used.

### Ingredient View and Quantity Multiplier
- **Ingredient View:**
  - Add buttons next to each ingredient to toggle visibility (show/hide) for easy tracking while cooking.
  - Use checkboxes or strike-through styling to visually indicate ingredients that have been used.
- **Quantity Multiplier:**
  - Include a dropdown or buttons for the user to select a multiplier (1x, 2x, 4x, 6x) to adjust ingredient quantities accordingly.
  - Update the displayed ingredient quantities dynamically based on the selected multiplier.

### Authentication and User Management
- **Login Page:**
  - Create a login page with forms for users to enter their credentials.
  - Implement authentication using JSON Web Tokens (JWT) for secure user sessions.
- **User Management:**
  - Allow registered users to create, edit, and delete their own recipes.
  - Implement role-based access control for admin privileges (e.g., managing all recipes, users).


start on flask
make the tables
use supabase
