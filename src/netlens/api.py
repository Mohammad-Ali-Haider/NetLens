from fastapi import FastAPI

app = FastAPI(title="NetLens", version="0.1.0")


@app.get("/health/live")
def liveness():
    return {"status": "ok"}
