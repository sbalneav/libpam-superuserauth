libpam-superuserauth
====================

What is it?
-----------

It's a pam module that allows you, as the superuser, to authenticate as any
user on the system by entering an alternative password as opposed to the user's
password.

How do I use it?
----------------

It is recommended that you create a secondary, non-privileged user with a good
password to act as the alternative password holder.  For example:

    adduser --system --home /nonexistant --shell /bin/false --no-create-home altauth
    passwd altauth

In your pam configuration files (for example, common-auth), you'll have
something like the following:

    auth   [success=3 default=ignore]  pam_unix.so nullok_secure
    auth   [success=2 default=ignore]  pam_superuserauth.so superuser=altauth use_first_pass
    auth   [success=1 default=ignore]  pam_ldap.so minimum_uid=1000 use_first_pass

This allows you to log in as one of your regular LDAP users without knowing, or
changing their password, by using the altauth password.

WHY would I use it?!
--------------------

Good for debugging user problems with their programs.

SHOULD I use it?!?!
-------------------

As with all programs that operate on the PAM stack, you should understand what
the security implications are for your site.
