# KLS - Server

Implementation of KLS server.

# Installation

Note: We recommend using [PyCharm Community Edition](https://www.jetbrains.com/pycharm/download/?section=windows) as development environment, since it was the environment used to create the software. The instructions here use Pycharm CE:

 1. Setup and test **[kls-mcmarr](https://github.com/AlbertoCasasOrtiz/kls-mcmarr/)** to check that it works on your computer (Optional - recommended).
 2. Open PyCharm Community Edition and click on **Get from VCS**.
 3. Insert the URL of the repository [https://github.com/AlbertoCasasOrtiz/kls-server](https://github.com/AlbertoCasasOrtiz/kls-server) and click **Clone** ().
     - _Note_: If there is a message indicating that **Git is not installed**, click on **download and install**.
     - _Note_: You may need to **login to GitHub**.
 4. Once the repository has been cloned, click on **Trust Project**.
 5. At bottom right, you will see a message **No Interpreter**. Click on it and then in **Add New Interpreter->Add Local Interpreter...**
 6. Configure your interpreter selecting **Python 3.10+** as the base interpreter and click **OK**.
 7. Open the pycharm console (one of the tabs at bottom left) and execute the command `pip install -r requirements.txt` to install requirements.
 8. Execute the command `python -m pip install git+https://github.com/AlbertoCasasOrtiz/kls-mcmarr/` to install **kls-mcmarr**.
    - _Note_: If git complains about the repository quota, try the backup repository: `pip install git+https://bitbucket.org/doctorado-sistemas-inteligentes/kls-mcmarr/`
 9. Download the affective model from [Google Drive](https://drive.google.com/file/d/18ouyTh0VdmheKkO-T27DOy_W8b7EkrQ8/view?usp=drive_link) and locate it into `assets/models/affective/`.
 10. Execute the commands `python manage.py makemigrations` and `python manage.py migrate` to create the databases.
 11. Execute the command `python manage.py createsuperuser` to create your admin user and follow the instructions in the console.
 12. To start the server, execute the command `python manage.py runserver 0.0.0.0:8000`.
 13. In your browser, go to [localhost at port 8000](http://127.0.0.1:8000).
 14. At the top right, click on **Log In** and login with the user you created before.
 15. In Home, click on **Upload Template** and upload your template. There is a template for Blocking Set I in spanish and english in the assets.
 16. In Home, click on **Start Set** to load the template and start kls web. Consider this is a guided view for testing.

### Instructions to update kls-server
 1. Execute the following commands in the terminal:
     - `git fetch`
     - `git pull`
 2. Restart the server.

### Instructions to update kls-mcmarr
 1. Execute the following command:
     - `python -m pip install git+https://github.com/AlbertoCasasOrtiz/kls-mcmarr/ --upgrade`
     - _Note_: If git complains about the repository quota, try the backup repository: `pip install git+https://bitbucket.org/doctorado-sistemas-inteligentes/kls-mcmarr/ --upgrade`
