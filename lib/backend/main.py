import os
import jwt
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

# Get your JWT Secret from Supabase Dashboard -> Project Settings -> API
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "")

app = FastAPI(title="Lightweight Flutter Backend")

# Allow Flutter (web/mobile) to talk to FastAPI without CORS issues
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_current_user(authorization: str = Header(...)):
    """Decodes and validates the Supabase JWT sent from Flutter."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token format")

    token = authorization.split(" ")[1]

    try:
        # Decodes token locally using your Supabase JWT secret
        payload = jwt.decode(
            token, SUPABASE_JWT_SECRET, algorithms=["HS256"], audience="authenticated"
        )
        return payload  # Contains sub (user_id), email, role, etc.
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/api/protected-data")
def get_protected_data(user: dict = Depends(get_current_user)):
    """Route only accessible with a valid Supabase login token."""
    user_id = user.get("sub")
    email = user.get("email")

    return {
        "message": f"Hello, user {user_id}!",
        "email": email,
        "data": "Here is secure data from your lightweight Python backend.",
    }
