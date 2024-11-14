### Setup instructions for developers
 1. Setup and test **kls-mcmarr** to check that it works on your computer.
 2. Close the **kls-mcmarr** project on PyCharm Community Edition and click on **Get from VCS**.
 3. Insert the URL of the repository [https://github.com/AlbertoCasasOrtiz/kls_server](https://github.com/AlbertoCasasOrtiz/kls_server) and click **Clone** ().
     - _Note_: If there is a message indicating that **Git is not installed**, click on **download and install**.
     - _Note_: You may need to **login to GitHub**.
 4. Once the repository has been cloned, click on **Trust Project**.
 5. At bottom right, you will see a message **No Interpreter**. Click on it and then in **Add New Interpreter->Add Local Interpreter...**
 6. Configure your interpreter selecting **Python 3.10+** as the base interpreter and click **OK**.
 7. Open the pycharm console (one of the tabs at bottom left) and execute the command `pip install -r requirements.txt` to install requirements.
 8. Execute the command ` python -m pip install git+https://bitbucket.org/doctorado-sistemas-inteligentes/kls_mcmarr_private/` to install **kls_mcmarr**.
 9. Download the affective model from [this link](https://bitbucket.org/doctorado-sistemas-inteligentes/kls_mcmarr_private/raw/72c1ba421e5319fc47a09883a6d2187d77007708/kls_mcmarr/models/affective/model.tflite) file and locate it into `assets/models/affective/`.
 10. Execute the commands `pyhon manage.py makemigrations` and `python manage.py migrate` to create the databases.
 11. Execute the command `pyhon manage.py createsuperuser` to create your admin user and follow the instructions in the console.
 12. To start the server, execute the command `python manage.py runserver`.
 13. In your browser, go to [localhost at port 8000](http://127.0.0.1:8000).
 14. At the top left, click on **Log In** and login with the user you created before.
 15. In Home, click on **Upload Template** and upload your template. There is a template for Blocking Set I in spanish and english in the assets.
 16. In Home, click on **Start Set** to load the template and start kls web. Consider this is a guided view for testing.
