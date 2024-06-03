from users.schemas import CreateUser


def create_user(user_in: CreateUser):
    user = user_in.model_dump_json()
    return {
        "success": True,
        "user": user,
    }