from datetime import datetime
from pydantic import BaseModel

class User(BaseModel):
    id: int
    signup_ts: datetime

user = User(id=1, signup_ts=datetime.fromisoformat('2023-10-27T10:00:00'))