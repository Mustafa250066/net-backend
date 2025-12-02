from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt
from passlib.context import CryptContext
from datetime import datetime


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()
JWT_SECRET = os.environ.get('JWT_SECRET', 'default-secret-key')
ALGORITHM = "HS256"

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# ============ Models ============

class AdminLogin(BaseModel):
    username: str
    password: str

class AdminChangePassword(BaseModel):
    current_password: str
    new_password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class Show(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    poster_url: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ShowCreate(BaseModel):
    name: str
    description: Optional[str] = None
    poster_url: Optional[str] = None

class Season(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    show_id: str
    season_number: int
    name: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SeasonCreate(BaseModel):
    show_id: str
    season_number: int
    name: Optional[str] = None

class Episode(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    season_id: str
    show_id: str
    episode_number: int
    title: str
    description: Optional[str] = None
    video_url: str
    duration: Optional[int] = None  # in seconds
    thumbnail_url: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class EpisodeCreate(BaseModel):
    season_id: str
    show_id: str
    episode_number: int
    title: str
    description: Optional[str] = None
    video_url: str
    duration: Optional[int] = None
    thumbnail_url: Optional[str] = None

class Movie(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    show_id: str
    title: str
    description: Optional[str] = None
    video_url: str
    duration: Optional[int] = None  # in seconds
    thumbnail_url: Optional[str] = None
    poster_url: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

#now movie create model
class MovieCreate(BaseModel):
    show_id: Optional[str] = None  # now optional
    title: str                     # still required
    description: Optional[str] = None
    video_url: str
    duration: Optional[int] = None
    thumbnail_url: Optional[str] = None
    poster_url: Optional[str] = None


class WatchProgress(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_session: str  # For non-logged users, use browser fingerprint or random ID
    episode_id: str
    progress: float  # seconds
    last_watched: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class WatchProgressUpdate(BaseModel):
    user_session: str
    episode_id: str
    progress: float

# ============ Auth Helper Functions ============

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = timedelta(days=7)):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# ============ Auth Routes ============

@api_router.post("/auth/login", response_model=TokenResponse)
async def admin_login(login_data: AdminLogin):
    admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
    admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
    
    # Check if password is already hashed in DB
    admin_doc = await db.admin.find_one({"username": admin_username})
    
    if login_data.username != admin_username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    # If admin exists in DB, verify against hashed password
    if admin_doc and "password_hash" in admin_doc:
        if not verify_password(login_data.password, admin_doc["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    else:
        # First time login with env password
        if login_data.password != admin_password:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        # Store hashed password in DB
        await db.admin.update_one(
            {"username": admin_username},
            {"$set": {"password_hash": hash_password(admin_password)}},
            upsert=True
        )
    
    access_token = create_access_token(data={"sub": login_data.username})
    return TokenResponse(access_token=access_token)

@api_router.post("/auth/change-password")
async def change_password(change_data: AdminChangePassword, current_admin: str = Depends(get_current_admin)):
    admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
    admin_doc = await db.admin.find_one({"username": admin_username})
    
    if not admin_doc or "password_hash" not in admin_doc:
        # Compare with env password
        if change_data.current_password != os.environ.get('ADMIN_PASSWORD', 'admin123'):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    else:
        # Verify current password
        if not verify_password(change_data.current_password, admin_doc["password_hash"]):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    
    # Update password
    new_password_hash = hash_password(change_data.new_password)
    await db.admin.update_one(
        {"username": admin_username},
        {"$set": {"password_hash": new_password_hash}},
        upsert=True
    )
    
    return {"message": "Password changed successfully"}

@api_router.get("/auth/verify")
async def verify_token(current_admin: str = Depends(get_current_admin)):
    return {"username": current_admin}

# ============ Show Routes ============

@api_router.post("/shows", response_model=Show)
async def create_show(show: ShowCreate, current_admin: str = Depends(get_current_admin)):
    show_obj = Show(**show.model_dump())
    doc = show_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.shows.insert_one(doc)
    return show_obj

@api_router.get("/shows", response_model=List[Show])
async def get_shows():
    shows = await db.shows.find({}, {"_id": 0}).to_list(1000)
    for show in shows:
        if isinstance(show['created_at'], str):
            show['created_at'] = datetime.fromisoformat(show['created_at'])
    return shows

@api_router.get("/shows/{show_id}", response_model=Show)
async def get_show(show_id: str):
    show = await db.shows.find_one({"id": show_id}, {"_id": 0})
    if not show:
        raise HTTPException(status_code=404, detail="Show not found")
    if isinstance(show['created_at'], str):
        show['created_at'] = datetime.fromisoformat(show['created_at'])
    return show

@api_router.put("/shows/{show_id}", response_model=Show)
async def update_show(show_id: str, show_update: ShowCreate, current_admin: str = Depends(get_current_admin)):
    result = await db.shows.find_one({"id": show_id}, {"_id": 0})
    if not result:
        raise HTTPException(status_code=404, detail="Show not found")
    
    await db.shows.update_one({"id": show_id}, {"$set": show_update.model_dump()})
    updated_show = await db.shows.find_one({"id": show_id}, {"_id": 0})
    if isinstance(updated_show['created_at'], str):
        updated_show['created_at'] = datetime.fromisoformat(updated_show['created_at'])
    return updated_show

@api_router.delete("/shows/{show_id}")
async def delete_show(show_id: str, current_admin: str = Depends(get_current_admin)):
    result = await db.shows.delete_one({"id": show_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Show not found")
    # Delete associated seasons, episodes, and movies
    await db.seasons.delete_many({"show_id": show_id})
    await db.episodes.delete_many({"show_id": show_id})
    await db.movies.delete_many({"show_id": show_id})
    return {"message": "Show deleted successfully"}

# ============ Season Routes ============

@api_router.post("/seasons", response_model=Season)
async def create_season(season: SeasonCreate, current_admin: str = Depends(get_current_admin)):
    season_obj = Season(**season.model_dump())
    doc = season_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.seasons.insert_one(doc)
    return season_obj

@api_router.get("/seasons", response_model=List[Season])
async def get_seasons(show_id: Optional[str] = None):
    query = {"show_id": show_id} if show_id else {}
    seasons = await db.seasons.find(query, {"_id": 0}).to_list(1000)
    for season in seasons:
        if isinstance(season['created_at'], str):
            season['created_at'] = datetime.fromisoformat(season['created_at'])
    return seasons

@api_router.put("/seasons/{season_id}", response_model=Season)
async def update_season(season_id: str, season_update: SeasonCreate, current_admin: str = Depends(get_current_admin)):
    result = await db.seasons.find_one({"id": season_id}, {"_id": 0})
    if not result:
        raise HTTPException(status_code=404, detail="Season not found")
    
    await db.seasons.update_one({"id": season_id}, {"$set": season_update.model_dump()})
    updated_season = await db.seasons.find_one({"id": season_id}, {"_id": 0})
    if isinstance(updated_season['created_at'], str):
        updated_season['created_at'] = datetime.fromisoformat(updated_season['created_at'])
    return updated_season

@api_router.delete("/seasons/{season_id}")
async def delete_season(season_id: str, current_admin: str = Depends(get_current_admin)):
    result = await db.seasons.delete_one({"id": season_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Season not found")
    # Delete associated episodes
    await db.episodes.delete_many({"season_id": season_id})
    return {"message": "Season deleted successfully"}

# ============ Episode Routes ============

@api_router.post("/episodes", response_model=Episode)
async def create_episode(episode: EpisodeCreate, current_admin: str = Depends(get_current_admin)):
    episode_obj = Episode(**episode.model_dump())
    doc = episode_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.episodes.insert_one(doc)
    return episode_obj

@api_router.get("/episodes", response_model=List[Episode])
async def get_episodes(season_id: Optional[str] = None, show_id: Optional[str] = None):
    query = {}
    if season_id:
        query["season_id"] = season_id
    if show_id:
        query["show_id"] = show_id
    episodes = await db.episodes.find(query, {"_id": 0}).to_list(1000)
    for episode in episodes:
        if isinstance(episode['created_at'], str):
            episode['created_at'] = datetime.fromisoformat(episode['created_at'])
    return episodes

@api_router.get("/episodes/{episode_id}", response_model=Episode)
async def get_episode(episode_id: str):
    episode = await db.episodes.find_one({"id": episode_id}, {"_id": 0})
    if not episode:
        raise HTTPException(status_code=404, detail="Episode not found")
    if isinstance(episode['created_at'], str):
        episode['created_at'] = datetime.fromisoformat(episode['created_at'])
    return episode

@api_router.put("/episodes/{episode_id}", response_model=Episode)
async def update_episode(episode_id: str, episode_update: EpisodeCreate, current_admin: str = Depends(get_current_admin)):
    result = await db.episodes.find_one({"id": episode_id}, {"_id": 0})
    if not result:
        raise HTTPException(status_code=404, detail="Episode not found")
    
    await db.episodes.update_one({"id": episode_id}, {"$set": episode_update.model_dump()})
    updated_episode = await db.episodes.find_one({"id": episode_id}, {"_id": 0})
    if isinstance(updated_episode['created_at'], str):
        updated_episode['created_at'] = datetime.fromisoformat(updated_episode['created_at'])
    return updated_episode

@api_router.delete("/episodes/{episode_id}")
async def delete_episode(episode_id: str, current_admin: str = Depends(get_current_admin)):
    result = await db.episodes.delete_one({"id": episode_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Episode not found")
    return {"message": "Episode deleted successfully"}

# ============ Movie Routes ============

@api_router.post("/movies", response_model=Movie)
async def create_movie(movie: MovieCreate, current_admin: str = Depends(get_current_admin)):
    movie_obj = Movie(**movie.model_dump())
    doc = movie_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.movies.insert_one(doc)
    return movie_obj




# @api_router.get("/movies", response_model=List[Movie])
# async def get_movies(show_id: Optional[str] = None):
#     query = {"show_id": show_id} if show_id else {}
#     movies = await db.movies.find(query, {"_id": 0}).to_list(1000)
#     for movie in movies:
#         if isinstance(movie['created_at'], str):
#             movie['created_at'] = datetime.fromisoformat(movie['created_at'])
#     return movies
@api_router.get("/movies", response_model=List[Movie])
async def get_movies(show_id: Optional[str] = None):
    query = {"show_id": show_id} if show_id else {}
    raw_movies = await db.movies.find(query, {"_id": 0}).to_list(1000)

    movies = []
    for movie in raw_movies:
        # Safely parse created_at
        if isinstance(movie.get("created_at"), str):
            try:
                movie["created_at"] = datetime.fromisoformat(movie["created_at"])
            except ValueError:
                movie["created_at"] = datetime.utcnow()  # fallback

        try:
            movies.append(Movie(**movie))  # validate against Pydantic model
        except Exception as e:
            print("Movie parse error:", movie, e)
            continue  # skip malformed entries

    return movies


@api_router.get("/movies/{movie_id}", response_model=Movie)
async def get_movie(movie_id: str):
    movie = await db.movies.find_one({"id": movie_id}, {"_id": 0})
    if not movie:
        raise HTTPException(status_code=404, detail="Movie not found")
    if isinstance(movie['created_at'], str):
        movie['created_at'] = datetime.fromisoformat(movie['created_at'])
    return movie

@api_router.put("/movies/{movie_id}", response_model=Movie)
async def update_movie(movie_id: str, movie_update: MovieCreate, current_admin: str = Depends(get_current_admin)):
    result = await db.movies.find_one({"id": movie_id}, {"_id": 0})
    if not result:
        raise HTTPException(status_code=404, detail="Movie not found")
    
    await db.movies.update_one({"id": movie_id}, {"$set": movie_update.model_dump()})
    updated_movie = await db.movies.find_one({"id": movie_id}, {"_id": 0})
    if isinstance(updated_movie['created_at'], str):
        updated_movie['created_at'] = datetime.fromisoformat(updated_movie['created_at'])
    return updated_movie

@api_router.delete("/movies/{movie_id}")
async def delete_movie(movie_id: str, current_admin: str = Depends(get_current_admin)):
    result = await db.movies.delete_one({"id": movie_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Movie not found")
    return {"message": "Movie deleted successfully"}

# ============ Watch Progress Routes ============

@api_router.post("/watch-progress")
async def update_watch_progress(progress_data: WatchProgressUpdate):
    existing = await db.watch_progress.find_one({
        "user_session": progress_data.user_session,
        "episode_id": progress_data.episode_id
    })
    
    if existing:
        await db.watch_progress.update_one(
            {"user_session": progress_data.user_session, "episode_id": progress_data.episode_id},
            {"$set": {
                "progress": progress_data.progress,
                "last_watched": datetime.now(timezone.utc).isoformat()
            }}
        )
    else:
        progress_obj = WatchProgress(**progress_data.model_dump())
        doc = progress_obj.model_dump()
        doc['last_watched'] = doc['last_watched'].isoformat()
        await db.watch_progress.insert_one(doc)
    
    return {"message": "Progress updated"}

@api_router.get("/watch-progress/{user_session}/{episode_id}")
async def get_watch_progress(user_session: str, episode_id: str):
    progress = await db.watch_progress.find_one(
        {"user_session": user_session, "episode_id": episode_id},
        {"_id": 0}
    )
    if not progress:
        return {"progress": 0}
    return {"progress": progress.get("progress", 0)}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

# All your routes above....

# --- LAST LINES ---
# from mangum import Mangum
# handler = Mangum(app)
