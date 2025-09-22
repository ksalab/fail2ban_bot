# app/middlewares/admin.py
import logging
from typing import Any, Awaitable, Callable, Dict, List

from aiogram import BaseMiddleware
from aiogram.types import TelegramObject, User

logger = logging.getLogger(__name__)


class AdminMiddleware(BaseMiddleware):
    """
    Middleware to check if the user is in the admin list.
    """

    def __init__(self, admin_ids: List[int]):
        super().__init__()
        self.admin_ids = admin_ids

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        user: User | None = data.get("event_from_user")

        if not user or user.id not in self.admin_ids:
            logger.warning(
                "Access denied for user %s (ID: %d).", user.full_name, user.id
            )
            # Stop processing the event
            return

        # User is an admin, proceed with the handler
        return await handler(event, data)
