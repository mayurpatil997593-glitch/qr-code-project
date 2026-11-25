# QR Shield - QR Code Security Analyzer

A Flask + PostgreSQL web application that decodes uploaded QR images, performs basic offline URL checks, stores scan history, and generates PDF reports.

## Important security notes
- The application **does not open or fetch** decoded URLs.
- The risk score is heuristic and cannot prove that a URL is safe or malicious.
- HTTPS does not guarantee a website is trustworthy.
- For deeper reputation checks, integrate a reputable threat-intelligence provider and keep its API key in environment variables.
- Do not upload sensitive QR codes to public scanning services.

## Requirements
- Windows 10/11
- Python 3.10 or newer (Python 3.12 is recommended)
- PostgreSQL 14+ installed locally, or a hosted PostgreSQL database
- VS Code (optional)

## Windows local setup

1. Install Python and PostgreSQL.
2. Create a database in PostgreSQL named `qr_shield`.
3. Open this project folder in PowerShell.
4. Create and activate a virtual environment:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use Command Prompt:
```cmd
.venv\Scripts\activate.bat
```

5. Install dependencies:
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

6. Copy `.env.example` to `.env` and set your PostgreSQL connection string:
```env
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/qr_shield
SECRET_KEY=use-a-long-random-value
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=ChangeThisAdminPassword123!
FLASK_DEBUG=1
```

7. Start the app:
```powershell
python app.py
```

8. Open `http://127.0.0.1:5000`.

The tables are created automatically when the app starts. The admin account is created automatically only if ADMIN_EMAIL and ADMIN_PASSWORD are set and the email is not already registered.

## Render deployment

### Option A: Render Blueprint
1. Push the project to a GitHub repository. Do not commit `.env`.
2. In Render choose **New + -> Blueprint** and connect the repository.
3. Render reads `render.yaml` and offers to create the web service and PostgreSQL database.
4. If the free database plan is not available or your account has reached its free database limit, use an existing PostgreSQL database or select a plan available to your account.
5. During setup, enter `ADMIN_EMAIL` and a strong `ADMIN_PASSWORD`.
6. Deploy. The app's `/health` endpoint checks the database connection.

### Option B: Existing Render PostgreSQL
1. Create a Render Web Service from the GitHub repository.
2. Build command: `pip install -r requirements.txt`
3. Start command: `gunicorn app:app --workers 2 --threads 4 --timeout 120`
4. In the Web Service -> Environment, add:
   - `DATABASE_URL`: the **Internal Database URL** from the Render PostgreSQL service when both services are in the same Render region; otherwise use the appropriate external connection string.
   - `SECRET_KEY`: a long random secret.
   - `ADMIN_EMAIL`: admin email address.
   - `ADMIN_PASSWORD`: strong admin password.
5. Deploy. Tables are initialized on app startup.

## Notes
- Render free web services can spin down after inactivity.
- Temporary uploaded image files are deleted after decoding; scan history stores decoded text, not the original image.
- The PDF report contains decoded content; protect reports as they may include private information.
- The initial URL checks are educational/basic checks, not a commercial-grade phishing detection engine.
