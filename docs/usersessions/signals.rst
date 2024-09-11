Signals
=======

There is a signal emitted during usersession store. You can
hook to them for your own needs.


- ``allauth.usersessions.signals.session_client_changed(from_session, to_session)``
    Sent when IP or useragent changed for a user session.

