# Login System with User Details & File Access

A small Flask + SQLite web app.

## Features
- Register and log in (username or email)
- Passwords stored as salted hashes (never plain text)
- View and edit your own details (full name, email, phone)
- Upload, download and delete your own files
- Each user can only access their own files

## Run it
1. Open a terminal in the `login_system` folder.
2. Create a virtual environment:
   - Windows: `python -m venv venv` then `venv\Scripts\activate`
   - Mac/Linux: `python3 -m venv venv` then `source venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Start the app: `python app.py`
5. Open http://127.0.0.1:5000 in your browser.

The database (`app.db`) and the `uploads/` folder are created automatically on first run.

## Project structure
```
login_system/
  app.py              routes, database, auth logic
  requirements.txt
  templates/
    base.html         layout, navigation, styling
    register.html
    login.html
    profile.html      user details
    files.html        file upload / list / download / delete
```

## Routes
| Route | Method | Purpose |
|---|---|---|
| `/register` | GET, POST | Create an account |
| `/login` | GET, POST | Log in |
| `/logout` | POST | Log out |
| `/profile` | GET, POST | View / edit user details |
| `/files` | GET | List your files |
| `/upload` | POST | Upload a file |
| `/download/<id>` | GET | Download your file |
| `/delete/<id>` | POST | Delete your file |

## Security notes
- Password hashing with Werkzeug
- CSRF token checked on every POST
- Uploads: allowed extensions only, 5 MB limit, names sanitised, stored under random names in a per-user folder
- Download/delete check that the file belongs to the logged-in user (others get 404)
- For real deployment, set the `SECRET_KEY` environment variable and turn off `debug=True`
