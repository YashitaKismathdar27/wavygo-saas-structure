
import logging
from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from pymongo.collection import Collection
from pymongo.errors import PyMongoError

from app.modules.auth.security import get_current_vendor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/staff", tags=["staff"])

StaffStatus = Literal["Active", "Inactive"]
StaffRole = Literal[
    "Fleet manager",
    "Operations associate",
    "Customer support",
    "Delivery associate",
    "Administrator",
]


class StaffCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    role: StaffRole
    phone: str = Field(min_length=7, max_length=25)
    salary: float = Field(ge=0)
    attendance: str = Field(default="Not recorded", max_length=100)
    nextSalary: str = Field(default="", max_length=50)
    status: StaffStatus = "Active"


class StaffUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=120)
    role: StaffRole | None = None
    phone: str | None = Field(default=None, min_length=7, max_length=25)
    salary: float | None = Field(default=None, ge=0)
    attendance: str | None = Field(default=None, max_length=100)
    nextSalary: str | None = Field(default=None, max_length=50)
    status: StaffStatus | None = None


class StaffStatusUpdate(BaseModel):
    status: StaffStatus


def get_staff_collection(request: Request) -> Collection:
    database = getattr(request.app.state, "database", None)

    if database is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MongoDB is not configured.",
        )

    return database["staff_members"]


def serialize_staff(document: dict[str, Any]) -> dict[str, Any]:
    result = dict(document)
    result["id"] = str(result.pop("_id"))
    result.pop("tenant_id", None)
    return result


def parse_staff_id(staff_id: str) -> ObjectId:
    if not ObjectId.is_valid(staff_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid staff ID.",
        )
    return ObjectId(staff_id)


def storage_error() -> None:
    logger.exception("Staff database operation failed.")
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Staff storage is unavailable.",
    )


@router.get("/")
def list_staff(
    vendor: Annotated[dict[str, Any], Depends(get_current_vendor)],
    collection: Annotated[Collection, Depends(get_staff_collection)],
) -> dict[str, Any]:
    try:
        query = {"tenant_id": vendor["_id"]}
        documents = list(
            collection.find(query).sort("created_at", -1)
        )
        items = [serialize_staff(doc) for doc in documents]
        return {"items": items, "total": len(items)}
    except PyMongoError:
        storage_error()


@router.post("/", status_code=status.HTTP_201_CREATED)
def create_staff(
    staff: StaffCreate,
    vendor: Annotated[dict[str, Any], Depends(get_current_vendor)],
    collection: Annotated[Collection, Depends(get_staff_collection)],
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    document = {
        **staff.model_dump(),
        "tenant_id": vendor["_id"],
        "created_at": now,
        "updated_at": now,
    }

    try:
        result = collection.insert_one(document)
        document["_id"] = result.inserted_id
        return serialize_staff(document)
    except PyMongoError:
        storage_error()


@router.patch("/{staff_id}/status")
def update_staff_status(
    staff_id: str,
    changes: StaffStatusUpdate,
    vendor: Annotated[dict[str, Any], Depends(get_current_vendor)],
    collection: Annotated[Collection, Depends(get_staff_collection)],
) -> dict[str, Any]:
    object_id = parse_staff_id(staff_id)
    query = {"_id": object_id, "tenant_id": vendor["_id"]}

    try:
        result = collection.update_one(
            query,
            {
                "$set": {
                    "status": changes.status,
                    "updated_at": datetime.now(timezone.utc),
                }
            },
        )
        if not result.matched_count:
            raise HTTPException(status_code=404, detail="Staff member not found.")

        document = collection.find_one(query)
        return serialize_staff(document)
    except PyMongoError:
        storage_error()


@router.put("/{staff_id}")
def update_staff(
    staff_id: str,
    changes: StaffUpdate,
    vendor: Annotated[dict[str, Any], Depends(get_current_vendor)],
    collection: Annotated[Collection, Depends(get_staff_collection)],
) -> dict[str, Any]:
    update = changes.model_dump(exclude_unset=True)
    if not update:
        raise HTTPException(status_code=400, detail="No changes provided.")

    object_id = parse_staff_id(staff_id)
    query = {"_id": object_id, "tenant_id": vendor["_id"]}
    update["updated_at"] = datetime.now(timezone.utc)

    try:
        result = collection.update_one(query, {"$set": update})
        if not result.matched_count:
            raise HTTPException(status_code=404, detail="Staff member not found.")

        document = collection.find_one(query)
        return serialize_staff(document)
    except PyMongoError:
        storage_error()
