Signals
=======

There are several signals emitted during usersession store. You can
hook to them for your own needs.


- ``allauth.usersessions.signals.user_agent_changed(session, from_user_agent, to_user_agent)``
    Sent when useragent changed for a user session.

- ``allauth.usersessions.signals.ip_changed(session, from_ip, to_ip)``
    Sent when ip changed for a user session.
