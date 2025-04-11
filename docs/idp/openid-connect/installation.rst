Installation
============

In order to use this functionality you need to install the
``idp-openid-connect`` extra as follows::

  pip install "django-allauth[idp-openid-connect]"

As the provider functionality is dependent on the regular allauth account
handling, you will need to follow the installation instructions related to
``allauth.account`` first. On top of that, you will need to add the following to
your project setup.

In your ``settings.py``, include::

    INSTALLED_APPS = [
        ...
        "allauth.idp.protocols.openid_connect",
        ...
    ]

Your project ``urls.py`` should include::

    urlpatterns = [
        ...
        path("", include("allauth.idp.urls")),
        ...
    ]
