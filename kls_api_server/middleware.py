from django.utils.deprecation import MiddlewareMixin

from kls_mcmarr.kls.kls import KLS


class InitializeSessionKLS(MiddlewareMixin):

    def process_request(self, request):
        # Check if the session variable is not already set
        if 'kls' not in request.session:
            # Create a KLS object.
            kls = KLS()

            # Store in session.
            request.session['kls'] = kls.to_dict()
