from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class SuricataEvent(BaseModel):
    timestamp: datetime
    src_ip: str
    dest_ip: str
    alert: Optional[dict]
