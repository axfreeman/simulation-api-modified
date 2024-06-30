"""Endpoints for the administrator.

"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Security
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Security, status
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from ..schemas import UserMessage, ServerMessage
from typing import Annotated
from ..reporting.caplog import logger
import logging

from ..schemas import UserBase
from ..database import get_session
from ..authorization.auth import get_api_key
from ..models import User

router = APIRouter(prefix="/admin", tags=["Admin"])

@router.get("/users",response_model=List[UserBase])
def get_users_for_admin(
    u: User = Security(get_api_key),
    session:Session =Depends(get_session)
)->List[User]:
    """Provide an admin with a list of users.  
    Backdoor access to global data via an API key.
    
        Only the admin user has access to this.  
        Exception: if the key is not valid  
        Exception: if the user is not admin  

    """
    if u.username!='admin':
        raise HTTPException(status_code=400, detail='Only admin can do this')
    user = session.query(User).all()
    return user

@router.get("/user/{username}",response_model=UserBase)
def get_user_for_admin(
    username:str,
    u: User = Security(get_api_key),
    session:Session =Depends(get_session)
)->User:
    """Provide an admin with the details of the user called username.
    Backdoor access to global data via an API key.
    The API key must be the admin's key    
        
        username: the name of the user.
        Returns: authentication error if the key is not valid.
        Returns: not allowed error if requester is not the admin
        Returns: None if the user does not exist.
    """
    if u.username!="admin" and u.username!=username:
        raise HTTPException(status_code=400, detail='Only an admin user or the requesting user is allowed to make this request')
    user = session.query(User).where(User.username==username).first()
    if user==None:
        raise HTTPException(status_code=404, detail=f'User {username} does not exist')
    return user

@router.post("/register", status_code=201,response_model=UserMessage)
def register(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: Session = Depends(get_session),
    u:User=Security(get_api_key)
)->str:
    """Register a new user and API key. 
    Only admin user can do this.

        form_data: user and api key.
        Return status: 405 if not the admin user.
        Return status: 409 if user already exists.
        Return status: 201 if the registration succeeds.
    """
    print("Entered Register")
    return
    print(f"The user {u.username} with credentials {u.api_key} wants to register a new user")
    print(f"The new user is called {form_data.username}")

    if u.username!='admin':
        logger.error('Only admin can do this')
        raise HTTPException(status_code=400, detail='Only admin can do this')
    if session.query(User).where(User.username == form_data.username).first() is not None:
        logger.error(f'{form_data.username} already exists')
        raise HTTPException(status_code=409, detail=f'{form_data.username} already exists')
    user:User=User(
        username=form_data.username,
        api_key=form_data.password,
        current_simulation_id=0,
        is_locked=False,
    )
    session.add(user)
    session.commit()
    logger.info(f'{form_data.username} created')

    return {'message': f'User {form_data.username} registered'}

@router.get("/lock/{username}",response_model=ServerMessage)
def lock_user(
    username: str,
    u: User = Security(get_api_key),
    session:Session =Depends(get_session)
)->ServerMessage:
    """
    Lock a username to restrict access to it to one player.

        username (string):the name of the user to lock

        If there is no such user, respond with status code 400.   

        If user is not locked, generate and send an apikey with status code 200  [NB IS THIS NEEDED?].  

        If user is locked, respond with status code 409).  
    """
    logger.info(f"request to lock user  {username}")
    # Find out if the user exists.  
    user:User = session.query(User).where(User.username==username).first()
    print(f"User details follow:\n")
    print(vars(user))
    if user is None:
        raise HTTPException(status_code=400, detail='Request to lock non-existent user')
    if user.is_locked:
        raise HTTPException(status_code=409, detail='Request to lock user who is already locked')
    session.add(user)
    user.is_locked=True
    session.commit()
    return {'message': f'User {username} has now been locked',"statusCode":status.HTTP_200_OK}
        

@router.get("/unlock/{username}",response_model=ServerMessage)
def unlock_user(
    username: str,
    u: User = Security(get_api_key),
    session:Session =Depends(get_session)
)->ServerMessage:
    """
    Unlock a username so other players can use it.

        username(string):
            the name of the user to unlock

        If there is no such user, send a failure (status code 400?).   

        If user is not locked, send a message and status code 204.    

        If user is locked, unlock it and return status code 200.  
    """
    logger.info(f"request to unlock user {username}")
    # Find out if the user exists.  
    user = session.query(User).where(User.username==username).first()
    if user is None:
        raise HTTPException(status_code=400, detail='Request to ulock non-existent user')
    if not user.is_locked:
        raise HTTPException(status_code=400, detail='Request to unlock user who is not locked')
    session.add(user)
    user.is_locked=False
    session.commit()
    return {'message': f'User {username} was unlocked',"statusCode":status.HTTP_200_OK}
