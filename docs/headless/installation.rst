Installation
============

In your ``settings.py``, include::

  INSTALLED_APPS = [
      ...

      # Required
      'allauth.account',
      'allauth.headless',

      # Optional
      'allauth.socialaccount',
      'allauth.mfa',
      'allauth.usersessions',

      ...
  ]

  # Implement HEADLESS_FRONTEND_URLS for your single-page application. 
  # Which urls you have to implement depends on your application, you can
  # find them in the configuration docs.
   


Your project ``urls.py`` should include::

    urlpatterns = [
        # Even when using headless, the third-party provider endpoints are stil
        # needed for handling e.g. the OAuth handshake. The account views
        # can be disabled using `HEADLESS_ONLY = True`.
        path("accounts/", include("allauth.urls")),

        # Include the API endpoints:
        path("_allauth/", include("allauth.headless.urls")),
    ]
