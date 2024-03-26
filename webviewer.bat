@echo off

if exist ./venv_webviewer (
	echo Virtual environment already exists.
    call venv_webviewer\Scripts\activate.bat
) else (
    python -m venv venv_webviewer
	call venv_webviewer\Scripts\activate.bat
	python -m pip install pip --upgrade
	python -m pip install --upgrade flask flask-session flask-sqlalchemy flask-bcrypt --ignore-installed
)

python webviewer.py
pause