from fastapi import FastAPI
from dotenv import load_dotenv

# Load .env
load_dotenv()

from app.api import router

app = FastAPI(title="CircuitWisp CTI Engine")

# Include all routes
app.include_router(router)
