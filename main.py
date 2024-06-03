from contextlib import asynccontextmanager

from fastapi import FastAPI

import uvicorn

from core.config import settings
from api_v1 import router as router_v1
from users.views import router as users_router
from items_views import router as items_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(lifespan=lifespan)
app.include_router(router=router_v1, prefix=settings.api_v1_prefix)
app.include_router(users_router)
app.include_router(items_router)


@app.get("/")
def hello_index():
    return {"message": "Hello World!"}


@app.get("/hello")
def hello(name: str = "World"):
    name = name.strip().title()
    return {"message": f"Hello, {name}!"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="localhost", port=8000, reload=True)
