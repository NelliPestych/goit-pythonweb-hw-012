from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Request
from fastapi.security import OAuth2PasswordRequestForm
from app.auth import create_email_verification_token, decode_email_verification_token
from sqlalchemy.orm import Session
from datetime import timedelta

from app import schemas, crud, deps, models
from app.auth import verify_password, create_access_token, get_current_user
from app.email import send_email

router = APIRouter(prefix="/auth", tags=["Auth"])

@router.get("/confirm_email/{token}")
async def confirm_email(token: str, db: Session = Depends(deps.get_db)):
    email = decode_email_verification_token(token)
    if email is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification token")

    user = crud.get_user_by_email(db, email=email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.confirmed:
        return {"message": "Your email is already confirmed"}

    crud.update_user_confirmation(db, user, True)
    return {"message": "Email successfully confirmed"}


@router.post("/register", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
async def register(
        body: schemas.UserCreate,
        background_tasks: BackgroundTasks,
        request: Request,
        db: Session = Depends(deps.get_db)
):
    exist_user = crud.get_user_by_email(db, body.email)
    if exist_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account already exists")
    new_user = crud.create_user(db, body)

    token_verification = create_email_verification_token({"sub": new_user.email})
    host = request.base_url.hostname

    print(f"Verification URL for {new_user.email}: http://{host}:8000/api/auth/confirm_email/{token_verification}")

    background_tasks.add_task(send_email, new_user.email, new_user.email, host, token_verification)

    return new_user

@router.post("/login", response_model=schemas.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(deps.get_db)
):
    user = crud.get_user_by_email(db, email=form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.confirmed:
         raise HTTPException(
             status_code=status.HTTP_401_UNAUTHORIZED,
             detail="Email not confirmed",
             headers={"WWW-Authenticate": "Bearer"},
         )

    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/current_user", response_model=schemas.UserOut)
async def read_users_me(current_user: models.User = Depends(get_current_user), db: Session = Depends(deps.get_db)):
    user_from_db = crud.get_user_by_email(db, email=current_user["email"])
    if not user_from_db:
        raise HTTPException(status_code=404, detail="User not found")
    return user_from_db