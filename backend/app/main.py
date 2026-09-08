from fastapi import FastAPI

from backend.app.core.config import settings
from backend.app.api.routes import router
from backend.app.database.connection import engine
from backend.app.database.models import Base


Base.metadata.create_all(bind=engine)


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.DESCRIPTION,
    version=settings.VERSION,
)


app.include_router(router)