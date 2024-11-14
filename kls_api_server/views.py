import os
import ast
import http
import json
import traceback
from datetime import datetime

from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from kls_mcmarr.mcmarr.movement.Movement import Movement
from kls_mcmarr.mcmarr.movement.MovementError import MovementError
from kls_mcmarr.mcmarr.movement.SetOfMovements import SetOfMovements
from rest_framework import views, permissions
from .models import User, SetModel, MovementModel, KeyPointsMovementModel, MovementErrorModel, \
    KeyPointsMovementErrorModel, KeyPointsIntegerChoices
from kls_mcmarr.mcmarr.movement.XmlSetLoader import XmlSetLoader
from .serializers import SetSerializer

from common.utils.utils import get_kls_from_session

import pandas as pd
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt

from kls_mcmarr.kls.kls import KLS

import cv2

from django.http import StreamingHttpResponse

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

class TestServerView(views.APIView):
    """
    get:
        Test if the server is running and working.

        This API allows the client to check if the server is running by returning an HTTP 200 OK status.

        Responses:
            200: The server is running and working.
    """

    @csrf_exempt
    def get(self, request):
        return JsonResponse({"status": http.HTTPStatus.OK}, status=http.HTTPStatus.OK)


class GetCSRFToken(views.APIView):
    """
    get:
        Retrieve CSRF token.

        This API allows the client to manually retrieve the CSRF token, which can be used for subsequent requests requiring CSRF protection.

        Responses:
            200: The CSRF token was successfully retrieved.
            500: There was an error while obtaining the CSRF token.
    """

    @csrf_exempt
    def get(self, request):
        error_message = ""
        response_status = http.HTTPStatus.OK

        try:
            csrf_token = get_token(request)
        except Exception as e:
            # Handle exception (you can log it if necessary)
            error_message = "There was an error while obtaining the CSRF token."
            csrf_token = ""
            response_status = http.HTTPStatus.INTERNAL_SERVER_ERROR

        return JsonResponse({
            'csrf_token': csrf_token,
            "status": response_status,
            'error_message': error_message
        }, status=response_status)


class GetListSets(views.APIView):
    """
    get:
        List all available sets.

        This API returns a list of set names from the database. Each set is ordered by its ID.

        Responses:
            200: A list of set names.
    """

    @csrf_exempt
    def get(self, request):
        set_names = SetModel.objects.values_list('set_name', flat=True)
        return JsonResponse({'set_names': list(set_names), "status": http.HTTPStatus.OK}, status=http.HTTPStatus.OK)


class WebcamStream(views.APIView):
    """
    get:
        Stream webcam video.

        This API streams live video from the webcam. The video is served as an MP4 stream, and the client can view it using standard video players.

        Responses:
            200: A continuous stream of webcam video.
    """

    def get(self, request):
        cap = cv2.VideoCapture(0)
        response = StreamingHttpResponse(self.generate_frames(cap), content_type="multipart/x-mixed-replace; boundary=frame")
        return response

    @staticmethod
    def generate_frames(cap):
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            _, buffer = cv2.imencode('.jpg', frame)
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')


class LogoutApp(views.APIView):
    """
    get:
        Logout the current user.

        This API logs out the currently authenticated user by ending their session.

        Responses:
            200: A JSON response indicating the logout was successful.
    """

    def get(self, request):
        logout(request)
        return JsonResponse({"status": http.HTTPStatus.OK}, status=http.HTTPStatus.OK)


class Logout(views.APIView):
    """
    get:
        Render a logout confirmation page.

        This view logs out the user and renders a confirmation page using the 'logout.html' template.

        Responses:
            200: A rendered HTML page confirming the user has been logged out.
    """

    def get(self, request):
        logout(request)
        context = {}
        return render(request, 'logout.html', context=context)


class Home(views.APIView):
    """
    get:
        Render the home page.

        This API renders the 'home.html' template, displaying the homepage of the application.

        Responses:
            200: A rendered HTML page for the homepage.
    """

    def get(self, request):
        context = {}
        # Render the HTML template 'home.html' with the data in the context variable
        return render(request, 'home.html', context=context)


class TermsOfUse(views.APIView):
    """
    get:
        Render the terms of use page.

        This API renders the 'terms_of_use.html' template, displaying the terms and conditions of the application.

        Responses:
            200: A rendered HTML page for the terms of use.
    """

    def get(self, request):
        context = {}
        # Render the HTML template 'terms_of_use.html' with the data in the context variable
        return render(request, 'terms_of_use.html', context=context)


class PrivacyPolicy(views.APIView):
    """
    get:
        Render the privacy policy page.

        This API renders the 'privacy_policy.html' template, displaying the privacy policy of the application.

        Responses:
            200: A rendered HTML page for the privacy policy.
    """

    def get(self, request):
        context = {}
        # Render the HTML template 'privacy_policy.html' with the data in the context variable
        return render(request, 'privacy_policy.html', context=context)


class LoginView(views.APIView):
    """
    post:
        Authenticate a user and log them in.

        This API authenticates a user based on the provided username and password. It supports both JSON and browser form submissions.

        If the format requested is 'json', the response includes a session ID upon successful authentication. If the format requested is for a browser, the user is redirected to the home page on success, or an error message is displayed in case of failure.

        Responses:
            200: JSON response with session ID or a redirect to the homepage upon successful authentication.
            400: JSON response with an error message for missing username or password.
            403: JSON response with an error message for incorrect login credentials.

    get:
        Render the login page.

        This API renders the 'login.html' template, allowing the user to access the login form.

        Responses:
            200: A rendered HTML page with the login form.
    """

    def post(self, request):
        # Get format requested. If browser, this does not exist and default is "". If app, this should be "json".
        format_requested = request.POST.get("format_requested", "")

        # Get username and password.
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")

        # Check presence of username and password.
        if username == "":
            error_message = "Please, insert your username."
            return JsonResponse({"error_message": error_message}, status=http.HTTPStatus.BAD_REQUEST)
        if password == "":
            error_message = "Please, insert your password."
            return JsonResponse({"error_message": error_message}, status=http.HTTPStatus.BAD_REQUEST)

        # Authenticate with provided username and password.
        user = authenticate(request, username=username, password=password)

        # Case format requested "json".
        if format_requested == "json":
            # If authentication was successful, return sessionid.
            if user is not None:
                # Login.
                login(request, user)
                # Return response with generated sessionid for this user.
                return JsonResponse({"sessionid": request.session.session_key}, status=http.HTTPStatus.OK)
            # If authentication was not successful, return error message.
            else:
                error_message = "Username or password incorrect. Please, try again."
                return JsonResponse({"error_message": error_message}, status=http.HTTPStatus.FORBIDDEN)

        # Case browser.
        else:
            # If authentication was successful, login and redirect to home.
            if user is not None:
                login(request, user)
                return redirect('home')
            # If authentication was not successful, return error message.
            else:
                error_message = "Username or password incorrect. Please, try again."
                return render(request, 'login.html', {'error_message': error_message, "status": "error"})

    def get(self, request):
        context = {"status": "success"}
        return render(request, 'login.html', context=context)


class SignupView(views.APIView):
    """
    post:
        Register a new user.

        This API allows for the registration of a new user based on the provided username, email, and password. It supports both JSON and browser form submissions.

        If the format requested is 'json', a JSON response is returned indicating success or failure. If the format requested is for a browser, the user is redirected to the homepage upon successful signup, or an error message is displayed in case of failure.

        Responses:
            200: JSON response with an empty body upon successful registration, or a redirect to the homepage.
            400: JSON response with an error message for missing username, email, or password.
            403: JSON response with an error message if user creation fails.
            409: JSON response if the username is already taken.

    get:
        Render the signup page.

        This API renders the 'signup.html' template, allowing the user to access the signup form.

        Responses:
            200: A rendered HTML page with the signup form.
    """

    def post(self, request):
        format_requested = request.POST.get("format_requested", "")

        # Get username, email, and password.
        username = request.POST.get("username", "")
        email = request.POST.get("email", "")
        password = request.POST.get("password", "")

        # Check presence of username, email, and password.
        if username == "":
            error_message = "Please, insert your username."
            return JsonResponse({"error_message": error_message}, status=http.HTTPStatus.BAD_REQUEST)
        if email == "":
            error_message = "Please, insert your email."
            return JsonResponse({"error_message": error_message}, status=http.HTTPStatus.BAD_REQUEST)
        if password == "":
            error_message = "Please, insert your password."
            return JsonResponse({"error_message": error_message}, status=http.HTTPStatus.BAD_REQUEST)

        # Case format requested "json".
        if format_requested == "json":
            # Check if username is already taken
            if User.objects.filter(username=username).exists():
                error_message = "Username already exists."
                return JsonResponse({"error_message": error_message}, status=http.HTTPStatus.CONFLICT)
            else:
                # Create a new user with the provided information.
                user = User.objects.create_user(username=username, email=email, password=password)

                # If user created, return empty json with no errors. Otherwise, return error.
                if user is not None:
                    return JsonResponse({}, status=http.HTTPStatus.OK)
                else:
                    error_message = "There was an error while creating the user."
                    return JsonResponse({"error_message": error_message}, status=http.HTTPStatus.FORBIDDEN)
        else:
            if User.objects.filter(username=username).exists():
                error_message = "Username already exists."
                return render(request, 'signup.html', {'error_message': error_message, "status": "error"})
            else:
                # Create a new user with the provided information.
                user = User.objects.create_user(username=username, email=email, password=password)

                # Log the user in.
                login(request, user)

                # Redirect to home, since we already signed in.
                return redirect('home')

    def get(self, request):
        return render(request, 'signup.html', {"status": "success"})


class UploadTemplateView(views.APIView):
    """
    get:
        Render the upload template page.

        This API renders the 'upload_template.html' template, allowing users to access the file upload form.

        Responses:
            200: A rendered HTML page for the file upload template.
    """

    def get(self, request):
        context = {}
        # Render the HTML template index.html with the data in the context variable
        return render(request, 'upload_template.html', context=context)


class UploadTemplate(views.APIView):
    """
    post:
        Upload and process a set template file.

        This API allows authenticated users to upload a template file, which contains information about a set of movements. The file is processed, and the data is stored in the database, including the set, movements, keypoints, and errors. If the set already exists, an error message is returned.

        Responses:
            200: The template was successfully uploaded and processed, or an error message if the set already exists.
            403: The user is not authenticated and cannot upload the template.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        status = 'success'
        error_message = ''

        # Get uploaded file, read it and decode it.
        file_content = request.FILES["file"].read().decode('utf-8')

        # Load set information.
        loader = XmlSetLoader(string=file_content)
        set_of_movements = loader.load_xml_set()

        # Check if the set is already in the database.
        set_count = SetModel.objects.filter(set_name=set_of_movements.get_name()).count()

        if set_count > 0:
            status = 'error'
            error_message = "This set is already in the database. " \
                            "Remove it or change its name if you want to upload it again."
        else:
            # Upload set information to database.
            # Create a row for the set.
            db_set_of_movements = SetModel(set_name=set_of_movements.get_name(),
                                           set_description=set_of_movements.get_description(),
                                           set_template=set_of_movements.get_template(),
                                           set_template_file=request.FILES["file"])
            # Save set row.
            db_set_of_movements.save()

            # Upload movements.
            # Get Set from database.
            set_object = SetModel.objects.get(set_name=set_of_movements.get_name())

            # For each movement...
            for movement in set_of_movements.get_movements():

                # Create a row for the movement.
                db_movement = MovementModel(movement_name=movement.get_name(),
                                            movement_description=movement.get_description(),
                                            movement_feedback_message=movement.get_feedback_message(),
                                            movement_start_frame=movement.get_start_frame(),
                                            movement_end_frame=movement.get_end_frame(),
                                            movement_order=movement.get_order(),
                                            set=set_object)
                # Save movement row.
                db_movement.save()

                # Get movement from database.
                movement_object = MovementModel.objects.filter(set=set_object).get(movement_name=movement.get_name())

                # For each keypoint...
                for keypoint in movement.get_keypoint_names():
                    db_keypoints = KeyPointsMovementModel(keypoint_name=KeyPointsIntegerChoices.get_choice_from_name(keypoint),
                                                          movement=movement_object)
                    # Save keypoints row.
                    db_keypoints.save()

                # For each error...
                for movement_error in movement.get_movement_errors():
                    # Create a row for the movement error.
                    db_movement_error = MovementErrorModel(movement_name=movement_error.get_name(),
                                                           movement_description=movement_error.get_description(),
                                                           movement_feedback_message=movement_error.get_feedback_message(),
                                                           movement_start_frame=movement_error.get_start_frame(),
                                                           movement_end_frame=movement_error.get_end_frame(),
                                                           movement=movement_object)
                    # Save movement error row.
                    db_movement_error.save()

                    # Get movement error from database.
                    movement_error_object = MovementErrorModel.objects.filter(movement=movement_object).get(movement_name=movement_error.get_name())

                    # For each error keypoint...
                    for keypoint_error in movement.get_keypoint_names():
                        db_keypoints_error = KeyPointsMovementErrorModel(keypoint_name=KeyPointsIntegerChoices.get_choice_from_name(keypoint_error),
                                                                         movement_error=movement_error_object)
                        # Save keypoints row.
                        db_keypoints_error.save()

        context = {
            'status': status,
            'error_message': error_message
        }

        return render(request, 'uploaded_template.html', context=context)


class StartSetView(views.APIView):
    """
    get:
        Retrieve the list of available set names.

        This API retrieves the names of all the sets available in the database and returns them in the context.

        Responses:
            200: The set names were successfully retrieved and rendered.

    post:
        Start a new set and initialize KLS with its movements, keypoints, and errors.

        This API takes the selected set name from the request, retrieves the corresponding set and its movements from the database, and initializes the Kenpo Learning System (KLS) instance with the set data. It also stores the set information, templates, and the KLS instance in the session.

        Responses:
            200: The set was successfully loaded, or an error occurred during the process.
            403: The user is not authenticated and cannot start the set.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        set_names = SetModel.objects.values_list('set_name', flat=True)

        context = {
            'set_names': list(set_names)
        }

        return render(request, 'start_set.html', context=context)

    def post(self, request):
        status = 'success'
        error_message = ''

        #  Create new kls instance.
        kls = KLS()

        # kls set where everything is stored.
        kls_set = SetOfMovements(kls.model)

        try:
            # Serialize data.
            serializer = SetSerializer(data=request.data, context={'request': request})
            serializer.is_valid(raise_exception=True)

            # Get set name.
            set_name_search = serializer.validated_data['set_name']

            # Get set database object.
            set_database = SetModel.objects.filter(set_name=set_name_search)[0]

            # Extract information from set object.
            kls_set.set_name(set_database.set_name)
            set_name = set_database.set_name
            set_description = set_database.set_description
            kls_set.set_description(set_description)

            # Extract template and convert into json object.
            if set_database.set_template:
                json_template = json.loads(set_database.set_template)
                kls_set.set_template(json_template)

            # Extract movement objects.
            list_movements = MovementModel.objects.filter(set__set_name=set_name).order_by("movement_order")

            # For each movement, extract information.
            for movement in list_movements:
                kls_movement = Movement()
                kls_movement.set_name(movement.movement_name)
                kls_movement.set_description(movement.movement_description)
                kls_movement.set_feedback_message(movement.movement_feedback_message)
                kls_movement.set_start_frame(movement.movement_start_frame)
                kls_movement.set_end_frame(movement.movement_end_frame)
                kls_movement.set_order(movement.movement_order)

                # Extract keypoints.
                list_keypoints = KeyPointsMovementModel.objects.filter(movement__exact=movement)

                # For each keypoint, extract information.
                for keypoint in list_keypoints:
                    kls_movement.add_keypoint(KeyPointsIntegerChoices.choices[keypoint.keypoint_name][1])

                # Extract movement error objects.
                list_movements_error = MovementErrorModel.objects.filter(movement__exact=movement)

                # For each movement error, extract information.
                for movement_error in list_movements_error:
                    kls_movement_error = MovementError()
                    kls_movement_error.set_name(movement_error.movement_name)
                    kls_movement_error.set_description(movement_error.movement_description)
                    kls_movement_error.set_feedback_message(movement_error.movement_feedback_message)
                    kls_movement_error.set_start_frame(movement_error.movement_start_frame)
                    kls_movement_error.set_end_frame(movement_error.movement_end_frame)

                    # Extract keypoints.
                    list_keypoints_error = KeyPointsMovementErrorModel.objects.filter(
                        movement_error__exact=movement_error)

                    # For each keypoint, extract information.
                    for keypoint_error in list_keypoints_error:
                        kls_movement_error.add_keypoint(
                            KeyPointsIntegerChoices.choices[keypoint_error.keypoint_name][1])

                    # Add movement error to movement.
                    kls_movement.add_movement_error(kls_movement_error)

                # Add movement to set.
                kls_set.add_movement(kls_movement)
        except:
            # printing stack trace
            error_message = "The Set does not exist."
            status = 'error'

        # Set this set as current set in kls. We do this here since we want an empty set if there is an error or the
        # set has not been found.
        kls.set_set_of_movements(kls_set)
        kls.initialize_set()

        # Extract templates.
        templates = {}
        movements_from_template = kls.set_of_movements.get_movements()
        for movement in movements_from_template:
            movement_name = movement.get_name()
            # Modeled because we need it modeled in the same way as the captured movement.
            if kls.set_of_movements.template:
                movement_template = kls.model.model_movement(
                    kls.set_of_movements.get_template_of_movement(movement.get_name()), "template_" + movement_name)
                templates[movement_name] = movement_template.to_json(orient='records')

        # Store the instance to the cache again.
        request.session['kls'] = kls.to_dict()
        request.session['templates'] = templates
        request.session['last_successful'] = True

        context = {
            'status': status,
            'error_message': error_message
        }

        format_requested = request.POST.get("format_requested", "")

        if format_requested == "json":
            return JsonResponse(context, status=http.HTTPStatus.OK)
        else:
            return render(request, 'start_set.html', context=context)


class RestartSet(views.APIView):
    """
    get:
        Restart the current set and reinitialize the KLS instance.

        This API fetches a new Kenpo Learning System (KLS) instance, resets the set to its initial state,
        and stores the reinitialized instance in the session. If an error occurs during the process,
        it logs the error message and returns it in the response.

        Responses:
            200: The set was successfully restarted.
            403: The user is not authenticated and cannot restart the set.
            500: An error occurred during the restart process.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get kls instance.
            kls = KLS()

            # Store the instance to the cache again.
            request.session['kls'] = kls.to_dict()
        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'

        context = {
            'status': status,
            'error_message': error_message
        }

        return render(request, 'restart_set.html', context=context)


class GetSetInfoApp(views.APIView):
    """
    get:
        Fetch the current Kenpo Learning System (KLS) set details.

        This API fetches the current Kenpo Learning System (KLS) instance from the session and retrieves
        details about the set of movements, such as the set name, description, number of movements,
        current movement index, and movement names. If an error occurs, it logs the error and returns
        an error message in the response.

        Responses:
            200: Successfully retrieved set information.
            500: An internal server error occurred.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = http.HTTPStatus.OK
        set_name = ''
        set_description = ''
        movement_num = 0
        current_movement = -1
        movement_name = []
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get current set of movements in mcmarr
            kls_set = kls.get_set_of_movements()

            # Check if the name is empty, if not, continue.
            if kls_set.get_name() != '':
                set_name = kls_set.get_name()
                set_description = kls_set.get_description()
                movement_name = kls_set.get_movement_names()
                movement_num = len(movement_name)
                current_movement = kls.current_movement

                # Create a session uuid name.
                # Generate uuid_name to identify this session.
                current_datetime = datetime.now()
                ordered_string = current_datetime.strftime("%Y-%m-%d-%H-%M-%S")
                session_folder_name = "session - " + str(ordered_string) + "/"

                # Initialize phase implementations.
                output_path = "assets/output/" + request.user.username + "/" + session_folder_name + "/"
                request.session['output_path'] = output_path

                # Create results folder
                os.makedirs("assets/output/" + request.user.username + "/" + session_folder_name + "/")

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = http.HTTPStatus.INTERNAL_SERVER_ERROR

        context = {
            'status': status,
            'set_name': set_name,
            'set_description': set_description,
            'movement_num': movement_num,
            'current_movement': current_movement,
            'movement_name': movement_name,
            'error_message': error_message
        }

        return JsonResponse(context, status=http.HTTPStatus.OK)


class GetSetInfo(views.APIView):
    """
    get:
        Fetch the current Kenpo Learning System (KLS) set details.

        Retrieves the set information, including set name, description, number of movements,
        current movement index, and movement names, from the KLS instance in the user's session.
        The method also manages the output path for saving session-related data and creates
        a folder to store the results of the current session.

        Responses:
            200: Successfully retrieved set information and created output folder.
            500: An error occurred while processing the request.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        set_name = ''
        set_description = ''
        movement_num = 0
        current_movement = -1
        movement_name = []
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get current set of movements in mcmarr
            kls_set = kls.get_set_of_movements()

            # Check if the name is empty, if not, continue.
            if kls_set.get_name() != '':
                set_name = kls_set.get_name()
                set_description = kls_set.get_description()
                movement_name = kls_set.get_movement_names()
                movement_num = len(movement_name)
                current_movement = kls.current_movement

                # Create a session uuid name.
                # Generate uuid_name to identify this session.
                current_datetime = datetime.now()
                ordered_string = current_datetime.strftime("%Y-%m-%d-%H-%M-%S")
                session_folder_name = "session - " + str(ordered_string) + "/"

                # Initialize phase implementations.
                output_path = "assets/output/" + request.user.username + "/" + session_folder_name + "/"
                request.session['output_path'] = output_path

                # Create results folder
                os.makedirs("assets/output/" + request.user.username + "/" + session_folder_name + "/")

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'

        context = {
            'status': status,
            'set_name': set_name,
            'set_description': set_description,
            'movement_num': movement_num,
            'current_movement': current_movement,
            'movement_name': movement_name,
            'error_message': error_message
        }

        return render(request, 'get_set_info.html', context=context)


class GetNextMovementApp(views.APIView):
    """
    get:
        Retrieve the next movement in the current KLS session.

        If the last movement retrieval was successful, the next movement is fetched; otherwise,
        the current movement is returned. It updates the session with a UUID for the movement and stores
        the KLS instance for caching.

        Responses:
            200: Successfully retrieved the next or current movement.
            500: An error occurred while processing the request.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        movement_name = ""
        movement_description = ""
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            if request.session.get('last_successful', True):
                movement = kls.get_next_movement()
            else:
                movement = kls.get_current_movement()

            if movement is not None:
                movement_name = movement.get_name()
                movement_description = movement.get_description()
            else:
                if kls.condition_finish_session():
                    status = "error"
                    error_message = "There was a problem retrieving the next movement."

            # Initialize and save an uuid for this movement.
            expected_movement = kls.set_of_movements.get_movements()[kls.current_movement]
            request.session['uuid_name'] = str(kls.num_iter) + "-" + expected_movement.get_name()

            # Store the instance to the cache again.
            request.session['kls'] = kls.to_dict()
        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'

        context = {
            'status': status,
            'movement_name': movement_name,
            'movement_description': movement_description,
            'error_message': error_message
        }

        return JsonResponse(context, status=http.HTTPStatus.OK)


class GetNextMovement(views.APIView):
    """
    get:
        Retrieve the next or current movement in the KLS session.

        Depending on the last retrieval's success, either the next movement or the current one is fetched.
        The session is updated with a UUID for the movement, and the KLS instance is stored in the cache.

        Responses:
            200: Successfully retrieved the movement.
            500: An error occurred during the request.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        movement_name = ""
        movement_description = ""
        error_message = ''
        movement = None

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            if request.session.get('last_successful', True):
                movement = kls.get_next_movement()
            else:
                movement = kls.get_current_movement()

            if movement is not None:
                movement_name = movement.get_name()
                movement_description = movement.get_description()

            # Initialize and save an uuid for this movement.
            if kls.current_movement < len(kls.set_of_movements.get_movements()):
                expected_movement = kls.set_of_movements.get_movements()[kls.current_movement]
                request.session['uuid_name'] = str(kls.num_iter) + "-" + expected_movement.get_name()
            else:
                request.session['uuid_name'] = str(kls.num_iter) + "-" + "None"


            # Store the instance to the cache again.
            request.session['kls'] = kls.to_dict()
        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'

        context = {
            'status': status,
            'movement_name': movement_name,
            'movement_description': movement_description,
            'error_message': error_message
        }

        if movement is not None:
            return render(request, 'get_next_movement.html', context=context)
        else:
            context = {
                'status': status,
                'generated_response': "",
                'is_last': True,
                'is_correct': True,
                'error_message': error_message
            }

            return render(request, 'get_response.html', context=context)


class PrepareCaptureMovementView(views.APIView):
    """
    get:
        This view prepares the interface for capturing movement data.

        Responses:
            200: Successfully renders the capture preparation page.
    """

    def get(self, request):
        context = {}
        # Render the HTML template index.html with the data in the context variable
        return render(request, 'prepare_capture_movement.html', context=context)


class CaptureMovementApp(views.APIView):
    """
    get:
        Captures a movement using the KLS instance and stores the result in the session.

        Responses:
            200: Successfully captures and stores movement data.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get uuid for this iteration.
            uuid_name = request.session.get('uuid_name', None)

            # Start capturing movement
            captured_movement = kls.capture.capture_movement(uuid_name=uuid_name, autofocus=0)

            # Store captured movement.
            request.session['captured_movement'] = captured_movement.to_json(orient='records')

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            print(error_message)

        context = {
            'status': status,
            'error_message': error_message
        }

        return JsonResponse(context, status=http.HTTPStatus.OK)


class CaptureMovement(views.APIView):
    """
    get:
        Captures a movement using the KLS instance and stores the result in the session.

        Responses:
            200: Successfully captures and stores movement data, then renders the result page.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get uuid for this iteration.
            uuid_name = request.session.get('uuid_name', None)

            # Start capturing movement
            captured_movement = kls.capture.capture_movement(uuid_name=uuid_name)

            # Store captured movement.
            request.session['captured_movement'] = captured_movement.to_json(orient='records')

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            print(error_message)

        context = {
            'status': status,
            'error_message': error_message
        }

        return render(request, 'finished_capture_movement.html', context=context)


class ModelMovementApp(views.APIView):
    """
    get:
        Models the captured movement using the KLS instance and stores the result in the session.

        Responses:
            200: Successfully models the movement and stores the result.
            500: If there is an error during the process.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get uuid for this iteration.
            uuid_name = request.session.get('uuid_name', None)

            # Get captured movement from session.
            captured_movement = pd.read_json(request.session.get('captured_movement', None))

            # Start model movement
            modeled_movement = kls.model.model_movement(captured_movement, uuid_name)

            # Store modeled movement.
            request.session['modeled_movement'] = modeled_movement.to_json(orient='records')

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            print(error_message)

        context = {
            'status': status,
            'error_message': error_message
        }

        return JsonResponse(context, status=http.HTTPStatus.OK)


class ModelMovement(views.APIView):
    """
    get:
        Models the captured movement using the KLS instance and stores the result in the session.

        Responses:
            200: Successfully models the movement and renders the page.
            500: If there is an error during the process.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get uuid for this iteration.
            uuid_name = request.session.get('uuid_name', None)

            # Get captured movement from session.
            captured_movement = pd.read_json(request.session.get('captured_movement', None))

            # Start model movement
            modeled_movement = kls.model.model_movement(captured_movement, uuid_name)

            # Store modeled movement.
            request.session['modeled_movement'] = modeled_movement.to_json(orient='records')

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            print(error_message)

        context = {
            'status': status,
            'error_message': error_message
        }

        return render(request, 'model_movement.html', context=context)


class AnalyzeMovementApp(views.APIView):
    """
    get:
        Analyzes the modeled movement against the expected movement and stores the results in the session.

        Responses:
            200: Successfully analyzes the movement and returns the results in JSON format.
            500: If there is an error during the analysis process.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get expected movement.
            expected_movement = kls.set_of_movements.get_movements()[kls.current_movement]

            # Get uuid for this iteration.
            uuid_name = request.session.get('uuid_name', None)

            # Extract templates from session in json format.
            templates_json = request.session.get('templates', None)

            # Reconvert templates to pandas dataframes.
            templates = {}
            for key, value in templates_json.items():
                templates[key] = pd.read_json(value)

            # Get modeled movement from session.
            modeled_movement = pd.read_json(request.session.get('modeled_movement', None))

            # Analyze modeled movement.
            movement_finished, analyzed_movement_errors = kls.analyze.analyze_movement(modeled_movement,
                                                                                       expected_movement,
                                                                                       kls.num_iter,
                                                                                       uuid_name)

            # Store analyzed movement name.
            request.session['movement_finished'] = movement_finished
            request.session['analyzed_movement_errors'] = str(analyzed_movement_errors)

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            movement_finished = False
            analyzed_movement_errors = []
            print(error_message)

        context = {
            'status': status,
            'movement_finished': movement_finished,
            'analyzed_movement_errors': analyzed_movement_errors,
            'error_message': error_message
        }

        return JsonResponse(context, status=http.HTTPStatus.OK)


class AnalyzeMovement(views.APIView):
    """
    get:
        Analyzes the modeled movement against the expected movement and stores the results in the session.

        Responses:
            200: Successfully analyzes the movement and renders the results in the template.
            500: If there is an error during the analysis process.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get expected movement.
            expected_movement = kls.set_of_movements.get_movements()[kls.current_movement]

            # Get uuid for this iteration.
            uuid_name = request.session.get('uuid_name', None)

            # Extract templates from session in json format.
            templates_json = request.session.get('templates', None)

            # Reconvert templates to pandas dataframes.
            templates = {}
            for key, value in templates_json.items():
                templates[key] = pd.read_json(value)

            # Get modeled movement from session.
            modeled_movement = pd.read_json(request.session.get('modeled_movement', None))

            # Analyze modeled movement.
            movement_finished, analyzed_movement_errors = kls.analyze.analyze_movement(modeled_movement,
                                                                                       expected_movement,
                                                                                       kls.num_iter,
                                                                                       uuid_name)

            # Store analyzed movement name.
            request.session['movement_finished'] = movement_finished
            request.session['analyzed_movement_errors'] = str(analyzed_movement_errors)

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            movement_finished = False
            analyzed_movement_errors = []
            print(error_message)

        context = {
            'status': status,
            'movement_finished': movement_finished,
            'analyzed_movement_errors': analyzed_movement_errors,
            'error_message': error_message
        }

        return render(request, 'analyze_movement.html', context=context)


class GetResponseApp(views.APIView):
    """
    get:
        Generates a response based on the analyzed movement and updates the KLS instance.

        Responses:
            200: Successfully generates the response and updates the KLS instance.
            500: If there is an error during the response generation process.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        is_last = False
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Check if empty set.
            if len(kls.set_of_movements.get_movements()) == 0:
                context = {
                    'status': status,
                    'generated_response': '',
                    'is_last': True,
                    'is_correct': True,
                    'error_code': '',
                    'error_message': ''
                }
                return JsonResponse(context, status=http.HTTPStatus.OK)
            else:
                # Get expected movement.
                expected_movement = kls.set_of_movements.get_movements()[kls.current_movement]

                # Get next movement.
                if kls.current_movement + 1 < len(kls.set_of_movements.get_movements()):
                    next_movement = kls.set_of_movements.get_movements()[kls.current_movement + 1]
                    next_movement_name = next_movement.get_name()
                    is_last = False
                else:
                    next_movement_name = None
                    is_last = True

                # Get analyzed movement name from request.
                movement_finished = request.session.get('movement_finished', None)
                analyzed_movement_errors = ast.literal_eval(request.session.get('analyzed_movement_errors', None))

                # Obtain generated response and if the movement is correct.
                text_to_deliver, generated_feedback, is_correct, code_to_return = kls.response.generate_response(movement_finished,
                                                                                                                 analyzed_movement_errors,
                                                                                                                 expected_movement,
                                                                                                                 next_movement_name,
                                                                                                                 kls.should_repeat_movement())

                # Update next movement.
                if is_correct:
                    kls.num_reps = 1
                else:
                    kls.num_reps += 1

                # Deliver response.
                # kls.response.deliver_response(generated_response)

                # Store errors.
                kls.compiled_errors.append([kls.num_iter, expected_movement.get_name(), analyzed_movement_errors])

                # Update next movement.
                if is_correct:
                    request.session['last_successful'] = True
                else:
                    request.session['last_successful'] = False

                # Update num. iter.
                kls.num_iter = kls.num_iter + 1

                # Store the instance to the cache again.
                request.session['kls'] = kls.to_dict()

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            text_to_deliver = ''
            is_last = False
            is_correct = False
            code_to_return = ''
            print(error_message)

        context = {
            'status': status,
            'generated_response': text_to_deliver,
            'is_last': is_last,
            'is_correct': is_correct,
            'error_code': code_to_return,
            'error_message': error_message
        }

        return JsonResponse(context, status=http.HTTPStatus.OK)


class GetResponse(views.APIView):
    """
    get:
        Generates a response based on the analyzed movement and updates the KLS instance.

        Responses:
            200: Successfully generates and delivers the response, updates the KLS instance.
            500: If there is an error during the response generation process.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        is_last = False
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get expected movement.
            expected_movement = kls.set_of_movements.get_movements()[kls.current_movement]

            # Get next movement.
            if kls.current_movement + 1 < len(kls.set_of_movements.get_movements()):
                next_movement = kls.set_of_movements.get_movements()[kls.current_movement + 1]
                next_movement_name = next_movement.get_name()
            else:
                next_movement_name = None
                is_last = True

            # Get analyzed movement name from request.
            movement_finished = request.session.get('movement_finished', None)
            analyzed_movement_errors = ast.literal_eval(request.session.get('analyzed_movement_errors', None))

            # Obtain generated response and if the movement is correct.
            text_to_deliver, generated_feedback, is_correct, code_to_return = kls.response.generate_response(movement_finished,
                                                                                                          analyzed_movement_errors,
                                                                                                          expected_movement,
                                                                                                          next_movement_name,
                                                                                                          kls.should_repeat_movement())

            # Deliver response.
            kls.response.deliver_response(text_to_deliver)

            # Update next movement.
            if is_correct:
                kls.num_reps = 1
            else:
                kls.num_reps += 1

            # Store errors.
            kls.compiled_errors.append([kls.num_iter, expected_movement.get_name(), analyzed_movement_errors])

            # Update next movement.
            if is_correct:
                request.session['last_successful'] = True
            else:
                request.session['last_successful'] = False

            # Update num. iter.
            kls.num_iter = kls.num_iter + 1

            # Store the instance to the cache again.
            request.session['kls'] = kls.to_dict()
        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            text_to_deliver = ''
            is_last = False
            is_correct = False
            code_to_return = ''
            print(error_message)

        context = {
            'status': status,
            'generated_response': text_to_deliver,
            'is_last': is_last,
            'is_correct': is_correct,
            'error_code': code_to_return,
            'error_message': error_message
        }

        return render(request, 'get_response.html', context=context)


class RegenerateReport(views.APIView):
    """
    post:
        From the information stored in a session, regenerates a report.

        Responses:
            200: Successfully generates and displays the report.
            500: If there is an error during the report generation process.
    """

    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Post method for authentication",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['path_to_session'],
            properties={
                'path_to_session': openapi.Schema(type=openapi.TYPE_STRING, description='Path to the session that requires a report.'),
            },
        )
    )
    def post(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get a new kls instance to restart it.
            kls = KLS()

            # Store the instance to the cache again.
            request.session['kls'] = kls.to_dict()

            # Get path with files to regenerate the report.
            output_path = request.data.get("path_to_session", "")

            if not output_path.endswith("/"):
                output_path = output_path + "/"

            #  Get kls instance.
            kls = get_kls_from_session(request, output_path)

            # Load compiled errors.
            for filename in os.listdir(output_path):
                if filename.endswith("-errors.txt"):
                    parts = filename.split("-")
                    iteration_number = parts[0]
                    movement_name = parts [1]

                    errors_list = []
                    with open(output_path + filename, 'r') as file:
                        for line in file:
                            # Convert each line (which is a string representation of a list) into an actual list
                            individual_error = ast.literal_eval(line.strip())  # Use strip() to remove any extra spaces/newlines
                            errors_list.append(individual_error)
                    kls.compiled_errors.append([iteration_number, movement_name, errors_list])

            # Load wrong questions.
            for filename in os.listdir(output_path):
                if filename.endswith("-cognitive.txt"):
                    with open(output_path + filename, 'r') as file:
                        for line in file:
                            individual_error = ast.literal_eval(line.strip())
                            correct = individual_error[0]
                            question = individual_error[1]
                            answer = individual_error[2]
                            question_id = individual_error[3]
                            kls.answers.append({"correct": correct, "question": question, "answer": answer, "id": question_id})


            generated_reports = kls.reports.generate_reports(output_path, "",
                                                             kls.compiled_errors, kls.answers, True)
            generated_reports = kls.reports.generate_summary_report(output_path, "",
                                                             kls.compiled_errors, kls.answers, True)

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            generated_reports = ""
            print(error_message)

        context = {
            'status': status,
            'generated_report': generated_reports,
            'error_message': error_message
        }

        return JsonResponse(context, status=http.HTTPStatus.OK)


class GetReport(views.APIView):
    """
    get:
        Generates and displays a report based on compiled errors and wrong questions.

        Responses:
            200: Successfully generates and displays the report.
            500: If there is an error during the report generation process.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get session uuid_name.
            output_path = request.session.get('output_path', None)

            generated_reports = kls.reports.generate_reports(output_path, "",
                                                             kls.compiled_errors, kls.answers, True)
            generated_reports = kls.reports.generate_summary_report(output_path, "",
                                                             kls.compiled_errors, kls.answers, True)

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            generated_reports = ""
            print(error_message)

        context = {
            'status': status,
            'generated_report': generated_reports,
            'error_message': error_message
        }

        return render(request, 'get_report.html', context=context)


class GetReportApp(views.APIView):
    """
    get:
        Generates and displays a report based on compiled errors and wrong questions.

        Responses:
            200: Successfully generates and returns the report in JSON format.
            500: If there is an error during the report generation process.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get session uuid_name.
            output_path = request.session.get('output_path', None)

            generated_reports = kls.reports.generate_reports(output_path, "",
                                                             kls.compiled_errors, kls.answers, True)
            generated_reports = kls.reports.generate_summary_report(output_path, "",
                                                             kls.compiled_errors, kls.answers, True)

        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'
            generated_reports = ""
            print(error_message)

        context = {
            'status': status,
            'generated_report': generated_reports,
            'error_message': error_message
        }

        return JsonResponse(context, status=http.HTTPStatus.OK)


class GetNextQuestion(views.APIView):
    """
    get:
        Retrieves the next cognitive question and its answers in JSON format.

        If there are no more questions, indicates that this is the last question.

        Responses:
            200: Successfully retrieves and returns the question, answers, and status.
            500: If there is an error during the retrieval process.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''
        question_str = ''
        answers = []
        question = None
        correct_answer = ""

        kls = None

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get session uuid_name.
            output_path = request.session.get('output_path', None)

            # Get question.
            if kls and kls.current_question < len(kls.cognitive.get_set().get_questions()):
                question = kls.cognitive.get_set().get_question(kls.current_question)

                question_str = question.get_question()
                answers = question.get_answers()
                correct_answer = question.get_correct_answer()

                # Store the instance to the cache again.
                request.session['kls'] = kls.to_dict()
        except:
            # printing stack trace
            error_message = traceback.format_exc()
            question_str = ""
            answers = []
            correct_answer = ""
            status = 'error'

        context = {
            'status': status,
            'question_str': question_str,
            'correct_answer': correct_answer,
            'answers': answers,
            'error_message': error_message
        }

        if kls and question:
            return render(request, 'cognitive.html', context=context)
        else:
            get_report = GetReport()
            response = get_report.get(request)
            return response


class GetNextQuestionApp(views.APIView):
    """
    get:
        Retrieves the next cognitive question and its answers in JSON format.

        If there are no more questions, indicates that this is the last question.

        Responses:
            200: Successfully retrieves and returns the question, answers, and status.
            500: If there is an error during the retrieval process.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''
        question_str = ''
        answers = []
        correct_answer = ""

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get question.
            if kls and kls.current_question < len(kls.cognitive.get_set().get_questions()):
                question = kls.cognitive.get_set().get_question(kls.current_question)

                question_str = question.get_question()
                answers = question.get_answers()
                correct_answer = question.get_correct_answer_pos()

                # Store the instance to the cache again.
                request.session['kls'] = kls.to_dict()

            # Get if last question.
            last_question = kls.current_question == (len(kls.cognitive.get_set().get_questions()) - 1)
        except:
            # printing stack trace
            error_message = traceback.format_exc()
            question_str = ""
            answers = []
            correct_answer = ""
            status = 'error'
            last_question = False

        context = {
            'status': status,
            'question_str': question_str,
            'correct_answer': correct_answer,
            'answers': answers,
            'error_message': error_message,
            'last_question': last_question
        }

        return JsonResponse(context, status=http.HTTPStatus.OK)


class RegisterWrongQuestion(views.APIView):
    """
    post:
        Registers a wrong answer for the current cognitive question.

        Responses:
            200: Successfully registers the wrong answer.
            500: If there is an error during the registration process.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        status = 'success'
        error_message = ''
        question_str = ''
        answers = []
        question = None
        correct_answer = ""
        wrong_answer = request.data.get("wrong_answer", "")  # Capture the wrong answer from the POST request data

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get question.
            if kls and kls.current_question < len(kls.cognitive.get_set().get_questions()):
                question = kls.cognitive.get_set().get_question(kls.current_question)

                question_str = question.get_question()
                question_id = question.get_id()
                answers = question.get_answers()
                correct_answer = question.get_correct_answer()

                kls.cognitive.save_answer(False, question_str, wrong_answer, question_id, output_path)
                kls.answers.append({"correct": False, "question": question.get_question(), "answer": wrong_answer, "id": question_id})

                # Store the instance to the cache again.
                request.session['kls'] = kls.to_dict()

            print(kls.answers)

            # Store the instance to the cache again.
            request.session['kls'] = kls.to_dict()
        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'

        context = {
            'status': status,
            'question_str': question_str,
            'correct_answer': correct_answer,
            'answers': answers,
            'error_message': error_message
        }

        return render(request, 'cognitive.html', context=context)


class RegisterWrongQuestionApp(views.APIView):
    """
    post:
        Registers a wrong answer for the current cognitive question.

        Responses:
            200: Successfully registers the wrong answer.
            500: If there is an error during the registration process.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        status = 'success'
        error_message = ''
        wrong_answer = request.data.get("wrong_answer", "")  # Capture the wrong answer from the POST request data

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get question.
            if kls and kls.current_question < len(kls.cognitive.get_set().get_questions()):
                question = kls.cognitive.get_set().get_question(kls.current_question)

                question_str = question.get_question()
                question_id = question.get_id()

                kls.cognitive.save_answer(False, question_str, wrong_answer, question_id, output_path)
                kls.answers.append({"correct": False, "question": question.get_question(), "answer": wrong_answer, "id": question_id})

                # Store the instance to the cache again.
                request.session['kls'] = kls.to_dict()

            print(kls.answers)

            # Store the instance to the cache again.
            request.session['kls'] = kls.to_dict()
        except:
            # printing stack trace
            status = 'error'
            error_message = traceback.format_exc()

        context = {
            'status': status,
            'error_message': error_message
        }

        return JsonResponse(context, status=http.HTTPStatus.OK)


class RegisterCorrectQuestion(views.APIView):
    """
    get:
        Registers the correct answer for the current cognitive question and advances to the next question.

        Responses:
            200: Successfully advances to the next question.
            500: If there is an error during the process.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''
        question_str = ''
        answers = []
        question = None
        correct_answer = ""

        kls = None

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get question.
            if kls and kls.current_question < len(kls.cognitive.get_set().get_questions()):
                question = kls.cognitive.get_set().get_question(kls.current_question)

                question_str = question.get_question()
                answers = question.get_answers()
                correct_answer = question.get_correct_answer()

                question_id = question.get_id()

                kls.cognitive.save_answer(True, question_str, correct_answer, question_id, output_path)
                kls.answers.append({"correct": True, "question": question.get_question(), "answer": correct_answer, "id":question_id})

                kls.current_question = kls.current_question + 1

            # Store the instance to the cache again.
            request.session['kls'] = kls.to_dict()
        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'

        context = {
            'status': status,
            'question_str': question_str,
            'correct_answer': correct_answer,
            'answers': answers,
            'error_message': error_message
        }

        if kls and question:
            get_next_question_view = GetNextQuestion()
            response = get_next_question_view.get(request)
            return response
        else:
            get_report = GetReport()
            response = get_report.get(request)
            return response


class RegisterCorrectQuestionApp(views.APIView):
    """
    get:
        Registers the correct answer for the current cognitive question and advances to the next question.

        Responses:
            200: Successfully advances to the next question.
            500: If there is an error during the process.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        status = 'success'
        error_message = ''

        try:
            #  Get kls instance.
            output_path = request.session.get('output_path', "assets/output/capture/")
            kls = get_kls_from_session(request, output_path)

            # Get question.
            if kls and kls.current_question < len(kls.cognitive.get_set().get_questions()):
                question = kls.cognitive.get_set().get_question(kls.current_question)

                correct_answer = question.get_correct_answer()

                question_str = question.get_question()
                question_id = question.get_id()

                kls.cognitive.save_answer(True, question_str, correct_answer, question_id, output_path)
                kls.answers.append({"correct": True, "question": question.get_question(), "answer": correct_answer, "id":question_id})

                kls.current_question = kls.current_question + 1

            # Store the instance to the cache again.
            request.session['kls'] = kls.to_dict()
        except:
            # printing stack trace
            error_message = traceback.format_exc()
            status = 'error'

        context = {
            'status': status,
            'error_message': error_message
        }

        return JsonResponse(context, status=http.HTTPStatus.OK)