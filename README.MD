# simulation-api
In this version, authorization is by an api-key, to keep things as simple 
as possible.
## This is an api provider for the simulation of a capitalist economy 
* You can see the results in a browser.  
* Or you can view more meaningful representations using a front end.  
* This version contains a primitive Excel frontend, in the 'Excel-frontend' folder.  
* Or you can use the front end at www.github.com/axfreeman/simulation-client. 
  
* That said, the whole point of having an API is that you can make your own frontend.  
* So you can use this API without accepting mine.  

## The general idea
* Everything that explains this project is in the DOCS folder.

## Installation and use, brief suggestions  
To install, create virtual environment (assuming you want one) and pip install from ``requirements.txt``  
To run, enter ``uvicorn app.main:app `` or any other local development server  
Default port is 8000 - choose a different port if you don't want that  
To see the endpoints enter http://localhost:8000/docs (or use whichever port you created).  
This invokes the Swagger interface which tells you most of what you need to know.  



