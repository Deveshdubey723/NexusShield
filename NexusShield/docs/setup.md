# Local setup

Use Windows PowerShell from the project root.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload --app-dir backend
```

In a second PowerShell terminal:

```powershell
Set-Location .\frontend
npm install
Copy-Item .env.example .env.local
npm run dev
```

Run backend tests from the project root:

```powershell
.\.venv\Scripts\python.exe -m pytest backend\tests -q
```

The optional ML dataset evaluator can be run with:

```powershell
.\.venv\Scripts\python.exe backend\app\ml.py C:\path\to\your-labeled-data.csv
```

Build the frontend:

```powershell
Set-Location .\frontend
npm run build
```

Configuration is documented in `.env.example` and `frontend\.env.example`. Do not commit local `.env` files or user documents.
